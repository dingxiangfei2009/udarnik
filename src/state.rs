use core::{
    convert::TryInto,
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
    num::Wrapping,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    error::Error as StdError,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use aead::{Aead, NewAead, Payload};
use async_std::sync::{Arc, Condvar, Mutex, RwLock};
use backtrace::Backtrace as Bt;
use blake2::Blake2b;
use chacha20poly1305::ChaCha20Poly1305;
use crypto_mac::NewMac;
use futures::{
    channel::{
        mpsc::{channel, Receiver, Sender},
        oneshot::Sender as OneshotSender,
    },
    future::{AbortHandle, Abortable, BoxFuture, Fuse},
    join, pin_mut,
    prelude::*,
    select, select_biased,
    stream::{iter, FuturesUnordered},
};
use generic_array::GenericArray;
use hmac::{Hmac, Mac};
use log::{debug, error, info, trace, warn};
use lru::LruCache;
use prost::Message as ProstMessage;
use rand::{rngs::StdRng, seq::IteratorRandom, CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha3::Digest;
use sss::{
    artin::GF65536NPreparedMultipointEvalVZG,
    lattice::{
        Anke, AnkeIdentity, AnkePublic, AnkeSessionKeyPart, AnkeSessionKeyPartR, Boris,
        BorisIdentity, BorisPublic, BorisSessionKeyPart, BorisSessionKeyPartR, Init, PrivateKey,
        PublicKey, Reconciliator, SessionKeyPart, SessionKeyPartMix,
        SessionKeyPartMixParallelSampler, SessionKeyPartParallelSampler,
    },
    mceliece::{McElieceCiphertext, McElieceKEM65536PrivateKey, McElieceKEM65536PublicKey},
};
use thiserror::Error;
use typenum::Unsigned;

use crate::{
    bridge::{grpc, BridgeHalf, ConstructibleBridge},
    err_msg,
    protocol::{
        CodecError, QuorumError, RSCodec, RawShard, RawShardId, ReceiveError, ReceiveQueue,
        RemoteRecvError, SendError, SendQueue, ShardState, TaskProgressNotifier,
    },
    utils::{ClonableSendableFuture, ClonableSink, Spawn},
    GenericError,
};

pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/protocol.rs"));
}

mod apply_proposal;
mod bridge_state;
mod bridges_in;
mod convert;
mod error_reports;
mod input;
mod key_exchange;
mod master_messages;
mod new_stream;
mod session;
mod stream_state;
pub use convert::WireError;
pub use key_exchange::{key_exchange_anke, key_exchange_boris};

#[derive(From, Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Debug, Deref)]
pub struct InitIdentity(String);

impl From<&'_ Init> for InitIdentity {
    fn from(Init(init): &'_ Init) -> Self {
        let mut digest = sha3::Sha3_512::new();
        for bytes in init.into_coeff_bytes() {
            digest.update(bytes);
        }
        Self(format!("{:x}", digest.finalize()))
    }
}

#[derive(From, Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Debug, Deref, Display)]
pub struct Identity(String);

impl From<&'_ PublicKey> for Identity {
    fn from(PublicKey(key): &'_ PublicKey) -> Self {
        let mut digest = sha3::Sha3_512::new();
        digest.update("rlwe:");
        for bytes in key.into_coeff_bytes() {
            digest.update(bytes);
        }
        Self(format!("{:x}", digest.finalize()))
    }
}

impl From<&'_ McElieceKEM65536PublicKey> for Identity {
    fn from(key: &'_ McElieceKEM65536PublicKey) -> Self {
        let mut digest = sha3::Sha3_512::new();
        digest.update("mceliece_kem_65536:");
        digest.update(serde_json::to_string(key).unwrap());
        Self(format!("{:x}", digest.finalize()))
    }
}

pub trait Guard<P, T> {
    type Error;
    fn encode(&self, payload: P) -> Vec<u8>;
    fn encode_with_tag(&self, payload: P, tag: &T) -> Vec<u8>;
    fn decode(&self, data: &[u8]) -> Result<P, Self::Error>;
    fn decode_with_tag(&self, data: &[u8], tag: &T) -> Result<P, Self::Error>;
}

#[derive(Debug)]
pub struct Pomerium<Guard, Payload, Tag> {
    pub data: Vec<u8>,
    _p: PhantomData<fn() -> (Guard, Payload, Tag)>,
}

impl<G, P, T> Pomerium<G, P, T> {
    pub fn from_raw(data: Vec<u8>) -> Self {
        Self {
            data,
            _p: PhantomData,
        }
    }
}

impl<G, P, T> Pomerium<G, P, T>
where
    G: Guard<P, T>,
{
    pub fn encode(guard: &G, payload: P) -> Self {
        Pomerium {
            data: guard.encode(payload),
            _p: PhantomData,
        }
    }

    pub fn decode(self, guard: &G) -> Result<P, G::Error> {
        guard.decode(&self.data)
    }

    pub fn encode_with_tag(guard: &G, payload: P, tag: &T) -> Self {
        Pomerium {
            data: guard.encode_with_tag(payload, tag),
            _p: PhantomData,
        }
    }

    pub fn decode_with_tag(self, guard: &G, tag: &T) -> Result<P, G::Error> {
        guard.decode_with_tag(&self.data, tag)
    }
}

#[derive(Debug)]
pub enum BridgeNegotiationMessage {
    Ask(Vec<BridgeAsk>),
    Retract(Vec<BridgeRetract>),
    ProposeAsk,
    AskProposal(Vec<BridgeAsk>),
    QueryHealth,
    Health(HashMap<BridgeId, u64>),
}

#[derive(Clone, Debug)]
pub struct BridgeAsk {
    r#type: BridgeType,
    id: BridgeId,
}

#[derive(Clone, Debug)]
pub enum BridgeType {
    Grpc(GrpcBridge),
    Unix(UnixBridge),
}

#[derive(Clone, Debug, From)]
pub struct GrpcBridge {
    pub addr: Vec<SocketAddr>,
    pub id: BridgeId,
    pub up: [u8; 32],
    pub down: [u8; 32],
}

#[derive(Clone, Debug, From)]
pub struct UnixBridge {
    pub addr: PathBuf,
    pub id: BridgeId,
    pub up: [u8; 32],
    pub down: [u8; 32],
}

#[derive(Clone, Debug, From)]
pub struct BridgeRetract(BridgeId);

#[derive(Clone, Debug)]
pub struct BridgeConstructorParams {
    pub ip_listener_address: IpAddr,
    pub ip_listener_mask: usize,
}

pub enum Message<G> {
    KeyExchange(KeyExchangeMessage),
    Params(Pomerium<G, Params, ()>),
    Client(ClientMessage<G>),
    Session(SessionId),
    SessionLogOnChallenge(Vec<u8>),
    SessionLogOn(SessionLogOn),
}

impl<G> Debug for Message<G> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Message::KeyExchange(m) => f.debug_tuple("Message::KeyExchange").field(m).finish(),
            Message::Params(_) => f.debug_tuple("Message::Params").finish(),
            Message::Client(m) => f.debug_tuple("Message::Client").field(m).finish(),
            Message::Session(sid) => f.debug_tuple("Message::Session").field(sid).finish(),
            Message::SessionLogOnChallenge(challenge) => {
                f.debug_tuple("Message::Session").field(challenge).finish()
            }
            Message::SessionLogOn(logon) => f.debug_tuple("Message::Session").field(logon).finish(),
        }
    }
}

#[derive(Debug)]
pub struct SessionLogOn {
    pub session: SessionId,
    pub challenge: Vec<u8>,
}

impl SessionLogOn {
    pub fn generate_body(session: &SessionId, challenge: &[u8]) -> Vec<u8> {
        let mut body = challenge.to_vec();
        body.extend(session.as_bytes());
        body
    }
    pub fn recover_body(&self) -> Vec<u8> {
        Self::generate_body(&self.session, &self.challenge)
    }
}

pub struct ClientMessage<G> {
    variant: Pomerium<G, ClientMessageVariant, (SessionId, u64)>,
    serial: u64,
    session: SessionId,
}

impl<G> Debug for ClientMessage<G> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("ClientMessage")
            .field("serial", &self.serial)
            .field("session", &self.session)
            .finish()
    }
}

#[derive(Debug)]
pub enum ClientMessageVariant {
    BridgeNegotiate(BridgeNegotiationMessage),
    Stream(StreamRequest),
    Ok,
    Err,
}

#[derive(Debug, Clone)]
pub struct Params {
    pub correction: u8,
    pub entropy: u8,
    pub window: usize,
}

#[derive(Debug)]
pub enum KeyExchangeMessage {
    RLWE(RLWEKeyExchange),
    McEliece(McElieceKeyExchange),
}

pub enum RLWEKeyExchange {
    AnkePart {
        part: SessionKeyPart,
        anke_identity: String,
        boris_identity: String,
        init_identity: String,
    },
    BorisPart {
        part: SessionKeyPart,
        reconciliator: Reconciliator,
    },
}

impl Debug for RLWEKeyExchange {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            RLWEKeyExchange::AnkePart {
                anke_identity,
                boris_identity,
                init_identity,
                ..
            } => f
                .debug_struct("RLWEKeyExchange::AnkePart")
                .field("anke_identity", anke_identity)
                .field("boris_identity", boris_identity)
                .field("init_identity", init_identity)
                .finish(),
            RLWEKeyExchange::BorisPart { .. } => {
                f.debug_struct("RLWEKeyExchange::BorisPart").finish()
            }
        }
    }
}

#[derive(Debug)]
pub enum KeyExchangeAnkeIdentity<R, H> {
    RLWE(RLWEAnkeIdentity<R>),
    McEliece(McElieceAnkeIdentity<H>),
}

#[derive(Debug)]
pub struct KeyExchangeBorisIdentity<R, H> {
    pub rlwe: RLWEBorisIdentity<R>,
    pub mc: McElieceBorisIdentity<H>,
}

pub struct RLWEAnkeIdentity<R> {
    init_identity: InitIdentity,
    init: Init,
    anke_identity: Identity,
    boris_identity: Identity,
    anke_pri: PrivateKey,
    anke_pub: PublicKey,
    boris_pub: PublicKey,
    anke_data: Vec<u8>,
    boris_data: Vec<u8>,
    session_key_part_sampler: SessionKeyPartParallelSampler<R>,
    anke_session_key_part_mix_sampler: SessionKeyPartMixParallelSampler<R, Anke>,
}

impl<R> RLWEAnkeIdentity<R>
where
    R: 'static + RngCore + CryptoRng + SeedableRng + Send,
{
    pub fn new(
        init_identity: InitIdentity,
        init: Init,
        anke_identity: Identity,
        boris_identity: Identity,
        anke_pri: PrivateKey,
        anke_pub: PublicKey,
        boris_pub: PublicKey,
        anke_data: Vec<u8>,
        boris_data: Vec<u8>,
    ) -> Self {
        Self {
            init_identity,
            init,
            anke_identity,
            boris_identity,
            anke_pri,
            boris_pub,
            anke_pub,
            anke_data,
            boris_data,
            session_key_part_sampler: SessionKeyPart::parallel_sampler::<R>(2, 4096),
            anke_session_key_part_mix_sampler: SessionKeyPartMix::parallel_sampler::<R>(2, 4096),
        }
    }
}

impl<R> Debug for RLWEAnkeIdentity<R> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("RLWEAnkeIdentity")
            .field("anke_identity", &self.anke_identity)
            .field("boris_identity", &self.boris_identity)
            .field("init_identity", &self.init_identity)
            .finish()
    }
}

pub struct RLWEBorisIdentity<R> {
    init_db: BTreeMap<InitIdentity, Init>,
    identity_db: BTreeMap<InitIdentity, BTreeMap<Identity, PrivateKey>>,
    allowed_identities: HashMap<InitIdentity, HashMap<Identity, PublicKey>>,
    anke_data: Vec<u8>,
    boris_data: Vec<u8>,
    session_key_part_sampler: SessionKeyPartParallelSampler<R>,
    boris_session_key_part_mix_sampler: SessionKeyPartMixParallelSampler<R, Boris>,
}

impl<R> RLWEBorisIdentity<R>
where
    R: 'static + RngCore + CryptoRng + SeedableRng + Send,
{
    pub fn new(
        init_db: BTreeMap<InitIdentity, Init>,
        identity_db: BTreeMap<InitIdentity, BTreeMap<Identity, PrivateKey>>,
        allowed_identities: HashMap<InitIdentity, HashMap<Identity, PublicKey>>,
        anke_data: Vec<u8>,
        boris_data: Vec<u8>,
    ) -> Self {
        Self {
            init_db,
            identity_db,
            allowed_identities,
            anke_data,
            boris_data,
            session_key_part_sampler: SessionKeyPart::parallel_sampler::<R>(2, 4096),
            boris_session_key_part_mix_sampler: SessionKeyPartMix::parallel_sampler::<R>(2, 4096),
        }
    }
}

impl<R> Debug for RLWEBorisIdentity<R> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("RLWEBorisIdentity")
            .field("anke_data", &self.anke_data)
            .field("boris_data", &self.boris_data)
            .finish()
    }
}

#[derive(Debug)]
pub enum McElieceKeyExchange {
    Anke {
        anke_identity: Identity,
        boris_identity: Identity,
        c0: Vec<u8>,
        c1: Vec<u8>,
    },
    Boris {
        c0: Vec<u8>,
        c1: Vec<u8>,
    },
}

pub struct McElieceAnkeIdentity<H> {
    anke_identity: Identity,
    boris_identity: Identity,
    anke_pub: McElieceKEM65536PublicKey,
    anke_pri: McElieceKEM65536PrivateKey<GF65536NPreparedMultipointEvalVZG>,
    boris_pub: McElieceKEM65536PublicKey,
    _p: PhantomData<fn() -> H>,
}

impl<H> McElieceAnkeIdentity<H> {
    pub fn new(
        anke_pri: McElieceKEM65536PrivateKey<GF65536NPreparedMultipointEvalVZG>,
        anke_pub: McElieceKEM65536PublicKey,
        boris_pub: McElieceKEM65536PublicKey,
    ) -> Self {
        Self {
            anke_identity: Identity::from(&anke_pub),
            boris_identity: Identity::from(&boris_pub),
            anke_pri,
            boris_pub,
            anke_pub,
            _p: PhantomData,
        }
    }
}

impl<H> Debug for McElieceAnkeIdentity<H> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("McElieceAnkeIdentity").finish()
    }
}

pub struct McElieceBorisIdentity<H> {
    allowed_identities: BTreeMap<Identity, McElieceKEM65536PublicKey>,
    identities: BTreeMap<Identity, McElieceKEM65536PrivateKey<GF65536NPreparedMultipointEvalVZG>>,
    _p: PhantomData<fn() -> H>,
}

impl<H> McElieceBorisIdentity<H> {
    pub fn new(
        allowed_identities: BTreeMap<Identity, McElieceKEM65536PublicKey>,
        identities: BTreeMap<
            Identity,
            McElieceKEM65536PrivateKey<GF65536NPreparedMultipointEvalVZG>,
        >,
    ) -> Self {
        Self {
            allowed_identities,
            identities,
            _p: PhantomData,
        }
    }
}

impl<H> Debug for McElieceBorisIdentity<H> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("McElieceAnkeIdentity").finish()
    }
}

#[derive(Error, Debug)]
pub enum KeyExchangeError {
    #[error("unknown message received, {0:?}")]
    UnknownMessage(Bt),
    #[error("message decoding: {0}, backtrace: {1:?}")]
    Message(GenericError, Bt),
    #[error("sending message: {0}, backtrace: {1:?}")]
    MessageSink(GenericError, Bt),
    #[error("message receiving terminated: {0:?}")]
    Terminated(Bt),
    #[error("all authentication attempts failed")]
    Authentication,
    #[error("unknown init parameter")]
    UnknownInit(Bt),
    #[error("client key exchange need to supply channel parameters")]
    NoParams,
    #[error("session: {0}")]
    Session(GenericError),
}

#[derive(Clone, Copy, Debug)]
pub enum KeyExchangeRole {
    Anke,
    Boris,
}

#[derive(Hash, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BridgeId {
    pub up: String,
    pub down: String,
}

#[derive(From, Hash, Clone, Display, Debug, PartialEq, Eq, PartialOrd, Ord, Deref)]
pub struct SessionId(String);

type HallOfFame = Arc<RwLock<LruCache<u8, Mutex<LruCache<u64, HashMap<u8, Option<BridgeId>>>>>>>;

pub struct Session<G> {
    local_serial: AtomicU64,
    remote_serial: AtomicU64,
    inbound_guard: Arc<G>,
    outbound_guard: Arc<G>,
    session_key: Vec<u8>,

    // internal states
    master_sink: Box<dyn Send + Sync + ClonableSink<Message<G>, GenericError>>,
    // bridge_kill_switches: Mutex<HashMap<BridgeId, OneshotSender<()>>>,
    bridge_builder: BridgeBuilder<G>,
    bridge_drivers: Pin<
        Arc<RwLock<FuturesUnordered<Fuse<Box<dyn Future<Output = ()> + Send + Sync + Unpin>>>>>,
    >,

    new_tasks: Sender<Box<dyn 'static + Send + Sync + Unpin + Future<Output = ()>>>,
    hall_of_fame: HallOfFame,
    role: KeyExchangeRole,

    bridge_state: Pin<Arc<BridgeState>>,
    stream_state: Pin<Arc<StreamState>>,
    bridge_constructor_params: BridgeConstructorParams,
    pub session_id: SessionId,
    pub params: Params,
}

pub struct SessionStream {
    // REASON: when session stream is dropped, stream is automatically terminated
    #[allow(unused)]
    terminate: OneshotSender<()>,
    inbound: Sender<BridgeMessage>,
    send_enqueue: Sender<Vec<u8>>,
}

type StreamPoll = Box<dyn Sync + ClonableSendableFuture<()> + Unpin>;

struct StreamState {
    streams: RwLock<HashMap<u8, Arc<SessionStream>>>,
    new_stream_poll: Sender<StreamPoll>,
    stream_avail_mutex: Mutex<()>,
    stream_avail_cv: Condvar,

    session_progress: Sender<()>,
    bridge_outward: Sender<BridgeMessage>,
    codec: Arc<RSCodec>,
    error_reports: Sender<(u8, u64, HashSet<u8>)>,
    output: Sender<Vec<u8>>,

    stream_timeout: Duration,
    send_cooldown: Duration,
    recv_timeout: Duration,
}

struct StreamTimeouts {
    stream_timeout: Duration,
    send_cooldown: Duration,
    stream_reset_timeout: Duration,
    recv_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Hash, Serialize, Deserialize)]
pub struct TimeoutParams {
    /// Timeout for streams with no progress
    pub stream_timeout: Duration,
    /// Cool down time for every extra shard sent after the threshold pack
    pub send_cooldown: Duration,
    /// Timeout for reseting stream if there is not one
    pub stream_reset_timeout: Duration,
    /// Timeout for head-of-line packet in the receive queue
    pub recv_timeout: Duration,
    /// Cool down time for inviting new bridge proposals if there is no bridge
    pub invite_cooldown: Duration,
}

#[derive(Debug)]
pub enum StreamRequest {
    Reset { stream: u8, window: usize },
}

pub struct SessionBootstrap {
    role: KeyExchangeRole,
    params: Params,
    session_key: Vec<u8>,
    session_id: SessionId,
}

pub struct SessionHandle<G> {
    pub session: Pin<Arc<Session<G>>>,
    pub poll: BoxFuture<'static, Result<(), SessionError>>,
    pub input: Sender<Vec<u8>>,
    pub output: Receiver<Vec<u8>>,
    pub progress: Receiver<()>,
}

type BridgeSink = Box<dyn Send + Sync + ClonableSink<BridgeMessage, GenericError> + Unpin>;

type BridgePoll = Box<dyn Send + Sync + ClonableSendableFuture<BridgeId> + Unpin>;

struct BridgeState {
    new_bridge_poll: Sender<BridgePoll>,
    kill_switches: Mutex<HashMap<BridgeId, OneshotSender<()>>>,
    send_counter: Counter,
    send_success_counter: Counter,
    receive_counter: Counter,
    bridge_sinks: RwLock<HashMap<BridgeId, (BridgeSink, AbortHandle)>>,
    bridge_avail_mutex: Mutex<()>,
    bridge_avail_cv: Condvar,
    bridge_inward: Sender<(BridgeId, BridgeMessage)>,
}

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("unknown bridge type")]
    UnknownBridgeType,
    #[error("broken pipe: {0}, backtrace: {1:?}")]
    BrokenPipe(GenericError, Bt),
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    #[error("token: {0}")]
    SignOn(String),
    #[error("stream: {0}, backtrace: {1:?}")]
    Stream(GenericError, Bt),
    #[error("bridge: {0}, backtrace: {1:?}")]
    Bridge(GenericError, Bt),
    #[error("fail to spawn")]
    Spawn,
}

#[derive(Default, Clone)]
struct Counter {
    counters: Arc<RwLock<HashMap<BridgeId, AtomicU64>>>,
}

pub struct Bridge<G> {
    pub tx: Box<dyn Send + ClonableSink<Pomerium<G, BridgeMessage, ()>, GenericError> + Unpin>,
    pub rx:
        Box<dyn Send + Stream<Item = Result<Pomerium<G, BridgeMessage, ()>, GenericError>> + Unpin>,
    pub poll: Box<dyn Send + Future<Output = ()> + Unpin>,
}

pub struct BridgeBuilder<G> {
    _p: PhantomData<fn() -> G>,
}

impl<G> BridgeBuilder<G>
where
    G: 'static + Guard<BridgeMessage, ()>,
    GenericError: From<G::Error>,
{
    pub fn new() -> Self {
        Self { _p: PhantomData }
    }
    pub async fn build<S>(
        &self,
        r#type: &BridgeType,
        id: &BridgeId,
        half: BridgeHalf,
        spawn: S,
    ) -> Result<Bridge<G>, SessionError>
    where
        S: Spawn + Send + Sync + 'static,
        S::Error: 'static,
    {
        match r#type {
            BridgeType::Grpc(params) => grpc::GrpcBridge
                .build(id, params, half, spawn)
                .await
                .map_err(|e| SessionError::Bridge(Box::new(e), <_>::default())),
            BridgeType::Unix(params) => grpc::UnixBridge
                .build(id, params, half, spawn)
                .await
                .map_err(|e| SessionError::Bridge(Box::new(e), <_>::default())),
            // _ => Err(SessionError::UnknownBridgeType),
        }
    }
}

pub enum BridgeMessage {
    Payload {
        raw_shard: RawShard,
        raw_shard_id: RawShardId,
    },
    PayloadFeedback {
        stream: u8,
        feedback: PayloadFeedback,
    },
}

#[derive(Clone, Copy, Debug)]
pub enum PayloadFeedback {
    Ok {
        serial: u64,
        id: u8,
        quorum: u8,
    },
    Full {
        queue_len: usize,
        serial: u64,
    },
    OutOfBound {
        start: u64,
        queue_len: usize,
        serial: u64,
    },
    Duplicate {
        serial: u64,
        id: u8,
        quorum: u8,
    },
    Malformed {
        serial: u64,
    },
    Complete {
        serial: u64,
    },
}

pub struct SafeGuard {
    aead: ChaCha20Poly1305,
    mackey: Vec<u8>,
}

impl Debug for SafeGuard {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("SafeGuard").finish()
    }
}

impl SafeGuard {
    fn derive_key(input: &[u8]) -> [u8; 32] {
        let mut key = [0; 32];
        for chunk in input.chunks(32) {
            for (k, c) in key.iter_mut().zip(chunk.iter().copied()) {
                *k ^= c;
            }
        }
        key
    }
    fn new(key: &[u8]) -> Self {
        let enckey = SafeGuard::derive_key(key);
        let mut mackey = key.to_vec();
        mackey.extend(&[0, 0]);
        mackey.extend(&enckey);
        mackey.extend(", hmac, blake2b".as_bytes());
        Self {
            aead: ChaCha20Poly1305::new(GenericArray::from_slice(&enckey)),
            mackey,
        }
    }
    fn encode_message<P: ProstMessage>(payload: P) -> Vec<u8> {
        let mut buf = vec![];
        payload.encode(&mut buf).expect("sufficient space");
        buf
    }
    fn decode_message<P: ProstMessage + Default>(data: Vec<u8>) -> Result<P, GenericError> {
        let data = VecDeque::from(data);
        P::decode(data).map_err(|e| Box::new(e) as GenericError)
    }
}

impl<'a> From<&'a [u8]> for SafeGuard {
    fn from(key: &'_ [u8]) -> Self {
        Self::new(key)
    }
}

pub trait Tag {
    fn into_bytes(&self) -> Vec<u8>;
}

impl Tag for () {
    fn into_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

impl Tag for (SessionId, u64) {
    fn into_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend(self.0.as_bytes());
        buf.extend(&self.1.to_le_bytes());
        buf
    }
}

pub trait ProstMessageMapping: Sized {
    type MapTo: ProstMessage + Default + From<Self> + TryInto<Self>;
    type Tag: Tag;
}

impl ProstMessageMapping for ClientMessageVariant {
    type MapTo = wire::ClientMessageVariant;
    type Tag = (SessionId, u64);
}

impl ProstMessageMapping for Params {
    type MapTo = wire::Params;
    type Tag = ();
}

impl ProstMessageMapping for BridgeMessage {
    type MapTo = wire::BridgeMessage;
    type Tag = ();
}

type HmacBlake2b = Hmac<Blake2b>;

impl<P, T> Guard<P, T> for SafeGuard
where
    P: ProstMessageMapping<Tag = T>,
    T: Tag,
    <P::MapTo as TryInto<P>>::Error: 'static + StdError + Send + Sync,
{
    type Error = GenericError;
    fn encode(&self, payload: P) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let payload = <P as ProstMessageMapping>::MapTo::from(payload);
        let payload = Self::encode_message(payload);
        let mut buf = self
            .aead
            .encrypt(GenericArray::from_slice(&nonce), &payload[..])
            .expect("correct key sizes and bounds");
        let mut mac =
            HmacBlake2b::new_varkey(&self.mackey).expect("should except variable length key");
        mac.update(&nonce);
        mac.update(&(buf.len() as u64).to_le_bytes());
        mac.update(&buf);
        buf.splice(
            ..0,
            mac.finalize()
                .into_bytes()
                .into_iter()
                .chain(nonce.to_vec()),
        );
        buf
    }
    fn encode_with_tag(&self, payload: P, tag: &T) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let payload = <P as ProstMessageMapping>::MapTo::from(payload);
        let payload = Self::encode_message(payload);
        let tag = tag.into_bytes();
        let mut buf = self
            .aead
            .encrypt(
                GenericArray::from_slice(&nonce),
                Payload {
                    msg: &payload,
                    aad: &tag,
                },
            )
            .expect("correct key sizes and bounds");
        let mut mac =
            HmacBlake2b::new_varkey(&self.mackey).expect("should except variable length key");
        mac.update(&nonce);
        mac.update(&(tag.len() as u64).to_le_bytes());
        mac.update(&tag);
        mac.update(&(buf.len() as u64).to_le_bytes());
        mac.update(&buf);
        buf.splice(
            ..0,
            mac.finalize()
                .into_bytes()
                .into_iter()
                .chain(nonce.to_vec()),
        );
        buf
    }
    fn decode(&self, data: &[u8]) -> Result<P, Self::Error> {
        let mac_length = <HmacBlake2b as Mac>::OutputSize::to_usize();
        if data.len() < 12 + mac_length {
            return Err(err_msg("truncated data"));
        }
        let mac_code = &data[..mac_length];
        let nonce = &data[mac_length..mac_length + 12];
        let data = &data[mac_length + 12..];
        let mut mac =
            HmacBlake2b::new_varkey(&self.mackey).expect("should except variable length key");
        mac.update(&nonce);
        mac.update(&(data.len() as u64).to_le_bytes());
        mac.update(data);
        mac.verify(mac_code)?;
        let buf = self
            .aead
            .decrypt(GenericArray::from_slice(&nonce), data)
            .map_err(|e| {
                trace!("decode error: {:?}", Bt::new());
                err_msg(format!("decode: {:?}", e))
            })?;
        let payload: <P as ProstMessageMapping>::MapTo = Self::decode_message(buf)?;
        Ok(payload.try_into()?)
    }
    fn decode_with_tag(&self, data: &[u8], tag: &T) -> Result<P, Self::Error> {
        let mac_length = <HmacBlake2b as Mac>::OutputSize::to_usize();
        if data.len() < 12 + mac_length {
            return Err(err_msg("truncated data") as GenericError);
        }
        let mac_code = &data[..mac_length];
        let nonce = &data[mac_length..mac_length + 12];
        let data = &data[mac_length + 12..];
        let tag = tag.into_bytes();
        let mut mac =
            HmacBlake2b::new_varkey(&self.mackey).expect("should except variable length key");
        mac.update(&nonce);
        mac.update(&(tag.len() as u64).to_le_bytes());
        mac.update(&tag);
        mac.update(&(data.len() as u64).to_le_bytes());
        mac.update(data);
        mac.verify(mac_code)?;
        let buf = self
            .aead
            .decrypt(
                GenericArray::from_slice(&nonce),
                Payload {
                    msg: data,
                    aad: &tag,
                },
            )
            .map_err(|e| {
                trace!("decode_with_tag error: {:?}", Bt::new());
                err_msg(format!("decode: {:?}", e))
            })?;
        let payload: <P as ProstMessageMapping>::MapTo = Self::decode_message(buf)?;
        Ok(payload.try_into()?)
    }
}
