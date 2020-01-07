use std::{
    collections::{BTreeMap, HashMap, HashSet},
    convert::TryInto,
    fmt::Debug,
    fmt::{Formatter, Result as FmtResult},
    marker::PhantomData,
    net::SocketAddr,
    num::Wrapping,
    path::PathBuf,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use aead::{Aead, NewAead, Payload};
use aes_gcm_siv::Aes256GcmSiv;
use async_std::sync::{Arc, Mutex, RwLock};
use dyn_clone::{clone_box, DynClone};
use failure::{err_msg, Backtrace, Error as TopError, Fail};
use futures::{
    channel::mpsc::{channel, unbounded, Receiver, Sender, UnboundedReceiver, UnboundedSender},
    future::{pending, BoxFuture, Fuse},
    join,
    prelude::*,
    select,
    stream::{repeat, FuturesUnordered},
};
use generic_array::GenericArray;
use log::error;
use lru::LruCache;
use prost::Message as ProstMessage;
use rand::{rngs::StdRng, seq::IteratorRandom, CryptoRng, RngCore, SeedableRng};
use sha3::Digest;
use sss::lattice::{
    Anke, AnkeIdentity, AnkePublic, AnkeSessionKeyPart, AnkeSessionKeyPartR, Boris, BorisIdentity,
    BorisPublic, BorisSessionKeyPart, BorisSessionKeyPartR, Init, PrivateKey, PublicKey,
    Reconciliator, SessionKeyPart, SessionKeyPartMix, SessionKeyPartMixParallelSampler,
    SessionKeyPartParallelSampler, Signature,
};

use crate::{
    bridge::{grpc, BridgeHalf, ConstructibleBridge},
    protocol::{
        CodecError, QuorumError, RSCodec, RawShard, RawShardId, ReceiveError, ReceiveQueue,
        RemoteRecvError, SendError, SendQueue, ShardState, TaskProgressNotifier,
    },
    GenericError, Redact,
};

pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/protocol.rs"));
}

mod convert;
pub use convert::WireError;

#[derive(From, Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Debug, Deref)]
pub struct InitIdentity(String);
#[derive(From, Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Debug, Deref)]
pub struct Identity(String);

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
    pub addr: SocketAddr,
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

#[derive(Debug)]
pub enum Message<G> {
    KeyExchange(KeyExchangeMessage),
    Params(Redact<Pomerium<G, Params, ()>>),
    Client(ClientMessage<G>),
    Session(SessionId),
    SessionLogOnChallenge(Vec<u8>),
    SessionLogOn(SessionLogOn),
}

#[derive(Debug)]
pub struct SessionLogOn {
    pub init_identity: InitIdentity,
    pub identity: Identity,
    pub session: SessionId,
    pub challenge: Vec<u8>,
    pub signature: Signature,
}

impl SessionLogOn {
    pub fn generate_body(
        init_identity: &InitIdentity,
        identity: &Identity,
        session: &SessionId,
        challenge: &[u8],
    ) -> Vec<u8> {
        let mut body = challenge.to_vec();
        body.extend(session.as_bytes());
        body.extend(init_identity.as_bytes());
        body.extend(identity.as_bytes());
        body
    }
    pub fn recover_body(&self) -> Vec<u8> {
        Self::generate_body(
            &self.init_identity,
            &self.identity,
            &self.session,
            &self.challenge,
        )
    }
}

#[derive(Debug)]
pub struct ClientMessage<G> {
    variant: Redact<Pomerium<G, ClientMessageVariant, (SessionId, u64)>>,
    serial: u64,
    session: SessionId,
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
    correction: u8,
    entropy: u8,
    window: usize,
}

#[derive(Debug)]
pub enum KeyExchangeMessage {
    Offer(Identity, InitIdentity),
    Accept(Identity, InitIdentity),
    Reject(Identity, InitIdentity),
    AnkePart(Redact<SessionKeyPart>),
    BorisPart(Redact<SessionKeyPart>, Redact<Reconciliator>),
}

#[derive(Fail, Debug, From)]
pub enum KeyExchangeError {
    #[fail(display = "unknown message received")]
    UnknownMessage(Backtrace),
    #[fail(display = "message decoding: {}", _0)]
    Message(#[cause] TopError, Backtrace),
    #[fail(display = "sending message: {}", _0)]
    MessageSink(#[cause] TopError, Backtrace),
    #[fail(display = "message receiving terminated")]
    Terminated(Backtrace),
    #[fail(display = "all authentication attempts failed")]
    Authentication,
    #[fail(display = "unknown init parameter")]
    UnknownInit(Backtrace),
    #[fail(display = "client key exchange need to supply channel parameters")]
    NoParams,
    #[fail(display = "session: {}", _0)]
    Session(GenericError),
}

#[derive(Clone, Copy, Debug)]
pub enum KeyExchangeRole {
    Anke,
    Boris,
}

pub struct KeyExchange<R> {
    pub retries: Option<u32>,
    pub init_db: BTreeMap<InitIdentity, Init>,
    pub identity_db: BTreeMap<InitIdentity, BTreeMap<Identity, PrivateKey>>,
    pub allowed_identities: HashMap<InitIdentity, HashMap<Identity, PublicKey>>,
    pub identity_sequence: Vec<(InitIdentity, Identity)>,
    pub session_key_part_sampler: SessionKeyPartParallelSampler<R>,
    pub anke_session_key_part_mix_sampler: SessionKeyPartMixParallelSampler<R, Anke>,
    pub boris_session_key_part_mix_sampler: SessionKeyPartMixParallelSampler<R, Boris>,
    pub anke_data: Vec<u8>,
    pub boris_data: Vec<u8>,
}

pub async fn key_exchange_anke<R, G, MsgStream, MsgSink, MsgStreamErr>(
    kex: KeyExchange<R>,
    message_stream: MsgStream,
    message_sink: MsgSink,
    seeder: impl Fn(&[u8]) -> R::Seed,
    params: Params,
) -> Result<SessionBootstrap, KeyExchangeError>
where
    R: RngCore + CryptoRng + SeedableRng,
    G: 'static + Debug + Guard<Params, ()> + for<'a> From<&'a [u8]>,
    G::Error: Debug,
    MsgStream: Stream<Item = Result<Message<G>, MsgStreamErr>> + Unpin,
    MsgSink: Sink<Message<G>> + Unpin,
    MsgStreamErr: 'static + Send + Sync,
    TopError: From<MsgSink::Error> + From<MsgStreamErr>,
{
    use bitvec::prelude::*;
    let mut message_stream =
        message_stream.map_err(|e| KeyExchangeError::Message(e.into(), <_>::default()));
    let mut message_sink =
        message_sink.sink_map_err(|e| KeyExchangeError::Message(e.into(), <_>::default()));
    let KeyExchange {
        mut retries,
        init_db,
        identity_db,
        allowed_identities,
        identity_sequence,
        session_key_part_sampler,
        anke_session_key_part_mix_sampler,
        anke_data,
        ..
    } = kex;
    // Anke initiate negotiation
    let mut key = None;
    for (init_ident, ident) in identity_sequence {
        let key_ = if let Some(key) = identity_db.get(&init_ident).and_then(|ids| ids.get(&ident)) {
            key
        } else {
            continue;
        };
        message_sink
            .send(Message::KeyExchange(KeyExchangeMessage::Offer(
                ident.clone(),
                init_ident.clone(),
            )))
            .await?;
        match message_stream.next().await {
            None => return Err(KeyExchangeError::Terminated(<_>::default())),
            Some(m) => match m? {
                Message::KeyExchange(KeyExchangeMessage::Accept(ident_, init_ident_))
                    if ident_ == ident && init_ident_ == init_ident =>
                {
                    key = Some((init_ident, ident, key_));
                    break;
                }
                Message::KeyExchange(KeyExchangeMessage::Reject(ident_, init_ident_))
                    if ident_ == ident && init_ident_ == init_ident => {}
                _ => return Err(KeyExchangeError::UnknownMessage(<_>::default())),
            },
        }
        if let Some(countdown) = &mut retries {
            if *countdown > 0 {
                *countdown -= 1
            } else {
                break;
            }
        }
    }
    let (init_ident, anke_ident, anke_key) = key.ok_or_else(|| KeyExchangeError::Authentication)?;
    let init = init_db
        .get(&init_ident)
        .ok_or_else(|| KeyExchangeError::UnknownInit(<_>::default()))?
        .clone();
    let anke_pub = anke_key.public_key(&init);
    // expect Boris to negotiate keys
    let mut boris_pub = None;
    while boris_pub.is_none() {
        match message_stream.next().await {
            None => return Err(KeyExchangeError::Terminated(<_>::default())),
            Some(m) => match m? {
                Message::KeyExchange(KeyExchangeMessage::Offer(ident, init_ident_))
                    if init_ident_ == init_ident =>
                {
                    if let Some(identites) = allowed_identities.get(&init_ident) {
                        if let Some(pub_key) = identites.get(&ident) {
                            boris_pub = Some((ident, pub_key.clone()))
                        }
                    }
                }
                _ => return Err(KeyExchangeError::UnknownMessage(<_>::default())),
            },
        }
        if let Some(countdown) = &mut retries {
            if *countdown > 0 {
                *countdown -= 1
            } else {
                break;
            }
        }
    }
    let (boris_ident, boris_pub) = boris_pub.ok_or_else(|| KeyExchangeError::Authentication)?;
    let (anke_session_part, anke_random) =
        SessionKeyPart::generate(&session_key_part_sampler, &init);
    message_sink
        .send(Message::KeyExchange(KeyExchangeMessage::AnkePart(
            anke_session_part.clone().into(),
        )))
        .await?;
    let shared_key = match message_stream.next().await {
        None => return Err(KeyExchangeError::Terminated(<_>::default())),
        Some(m) => match m? {
            Message::KeyExchange(KeyExchangeMessage::BorisPart(
                Redact(boris_session_part),
                Redact(reconciliator),
            )) => {
                let (anke_part_mix, _, _) = SessionKeyPartMix::<Anke>::generate::<R, _, _>(
                    seeder,
                    &anke_session_key_part_mix_sampler,
                    AnkePublic(&anke_data, &anke_pub),
                    BorisPublic(&anke_data, &boris_pub),
                    AnkeSessionKeyPart(&anke_session_part),
                    BorisSessionKeyPart(&boris_session_part),
                    AnkeIdentity(&anke_key),
                    AnkeSessionKeyPartR(&anke_random),
                );
                let shared_key = anke_part_mix.reconciliate(&reconciliator);
                let mut v = BitVec::<LittleEndian, u8>::new();
                v.extend(shared_key.iter().copied());
                v.into_vec()
            }
            _ => return Err(KeyExchangeError::UnknownMessage(<_>::default())),
        },
    };
    let outbound_guard = G::from(&shared_key);
    let message = Message::Params(Redact(Pomerium::encode(&outbound_guard, params.clone())));
    message_sink.send(message).await?;
    let session_id = match message_stream.next().await {
        None => return Err(KeyExchangeError::Terminated(<_>::default())),
        Some(m) => match m? {
            Message::Session(session_id) => session_id,
            _ => return Err(KeyExchangeError::UnknownMessage(<_>::default())),
        },
    };
    Ok(SessionBootstrap {
        role: KeyExchangeRole::Anke,
        anke_identity: anke_ident,
        boris_identity: boris_ident,
        params,
        session_key: shared_key,
        session_id,
        init_identity: init_ident,
    })
}

pub async fn key_exchange_boris<R, G, MsgStream, MsgSink, MsgStreamErr>(
    kex: KeyExchange<R>,
    message_stream: MsgStream,
    message_sink: MsgSink,
    seeder: impl Fn(&[u8]) -> R::Seed,
    session_id: SessionId,
) -> Result<SessionBootstrap, KeyExchangeError>
where
    R: RngCore + CryptoRng + SeedableRng,
    G: 'static + Debug + Guard<Params, ()> + for<'a> From<&'a [u8]>,
    G::Error: Debug,
    MsgStream: Stream<Item = Result<Message<G>, MsgStreamErr>> + Unpin,
    MsgSink: Sink<Message<G>> + Unpin,
    MsgStreamErr: 'static + Send + Sync,
    TopError: From<MsgSink::Error> + From<MsgStreamErr>,
{
    use bitvec::prelude::*;
    let mut message_stream =
        message_stream.map_err(|e| KeyExchangeError::Message(e.into(), <_>::default()));
    let mut message_sink =
        message_sink.sink_map_err(|e| KeyExchangeError::Message(e.into(), <_>::default()));
    let KeyExchange {
        mut retries,
        init_db,
        identity_db,
        allowed_identities,
        identity_sequence,
        session_key_part_sampler,
        boris_session_key_part_mix_sampler,
        anke_data,
        boris_data,
        ..
    } = kex;
    // Anke offers keys in negotiation
    let mut anke_pub = None;
    let mut init_ident = None;
    while anke_pub.is_none() {
        match message_stream.next().await {
            None => return Err(KeyExchangeError::Terminated(<_>::default())),
            Some(m) => match m? {
                Message::KeyExchange(KeyExchangeMessage::Offer(ident, init_ident_))
                    if identity_db.contains_key(&init_ident_)
                        && init_db.contains_key(&init_ident_) =>
                {
                    if let Some(identites) = allowed_identities.get(&init_ident_) {
                        if let Some(pub_key) = identites.get(&ident) {
                            init_ident = Some(init_ident_);
                            anke_pub = Some((ident, pub_key.clone()))
                        }
                    }
                }
                _ => return Err(KeyExchangeError::UnknownMessage(<_>::default())),
            },
        }
        if let Some(countdown) = &mut retries {
            if *countdown > 0 {
                *countdown -= 1
            } else {
                break;
            }
        }
    }
    let (anke_ident, anke_pub) = anke_pub.ok_or_else(|| KeyExchangeError::Authentication)?;
    let init_ident = init_ident.unwrap();
    let init = init_db.get(&init_ident).unwrap();
    // Boris negotiate keys
    let mut key = None;
    for (init_ident_, ident) in identity_sequence {
        if init_ident_ != init_ident {
            continue;
        }
        let key_ = if let Some(key) = identity_db.get(&init_ident).and_then(|ids| ids.get(&ident)) {
            key
        } else {
            continue;
        };
        message_sink
            .send(Message::KeyExchange(KeyExchangeMessage::Offer(
                ident.clone(),
                init_ident.clone(),
            )))
            .await?;
        match message_stream.next().await {
            None => return Err(KeyExchangeError::Terminated(<_>::default())),
            Some(m) => match m? {
                Message::KeyExchange(KeyExchangeMessage::Accept(ident_, init_ident_))
                    if ident_ == ident && init_ident_ == init_ident =>
                {
                    key = Some((ident, key_));
                    break;
                }
                Message::KeyExchange(KeyExchangeMessage::Reject(ident_, init_ident_))
                    if ident_ == ident && init_ident_ == init_ident => {}
                _ => return Err(KeyExchangeError::UnknownMessage(<_>::default())),
            },
        }
        if let Some(countdown) = &mut retries {
            if *countdown > 0 {
                *countdown -= 1
            } else {
                break;
            }
        }
    }
    let (boris_ident, boris_key) = key.ok_or_else(|| KeyExchangeError::Authentication)?;
    let boris_pub = boris_key.public_key(&init);
    let (boris_session_part, boris_random) =
        SessionKeyPart::generate(&session_key_part_sampler, &init);
    let anke_session_part = match message_stream.next().await {
        None => return Err(KeyExchangeError::Terminated(<_>::default())),
        Some(m) => match m? {
            Message::KeyExchange(KeyExchangeMessage::AnkePart(Redact(part))) => part,
            _ => return Err(KeyExchangeError::UnknownMessage(<_>::default())),
        },
    };
    let (boris_part_mix, _, _) = SessionKeyPartMix::<Boris>::generate::<R, _, _>(
        seeder,
        &boris_session_key_part_mix_sampler,
        AnkePublic(&anke_data, &anke_pub),
        BorisPublic(&boris_data, &boris_pub),
        AnkeSessionKeyPart(&anke_session_part),
        BorisSessionKeyPart(&boris_session_part),
        BorisIdentity(&boris_key),
        BorisSessionKeyPartR(&boris_random),
    );
    let reconciliator = boris_part_mix.reconciliator();
    let shared_key = boris_part_mix.reconciliate(&reconciliator);
    let mut v = BitVec::<LittleEndian, u8>::new();
    v.extend(shared_key.iter().copied());
    let shared_key = v.into_vec();

    let inbound_guard = G::from(&shared_key);
    message_sink
        .send(Message::KeyExchange(KeyExchangeMessage::BorisPart(
            Redact(boris_session_part),
            Redact(reconciliator),
        )))
        .await?;
    let params = match message_stream.next().await {
        None => return Err(KeyExchangeError::Terminated(<_>::default())),
        Some(m) => match m? {
            Message::Params(Redact(pomerium)) => pomerium.decode(&inbound_guard).map_err(|e| {
                error!("key_exchange: params: {:?}", e);
                KeyExchangeError::NoParams
            })?,
            _ => return Err(KeyExchangeError::UnknownMessage(<_>::default())),
        },
    };
    message_sink
        .send(Message::Session(session_id.clone()))
        .await?;
    Ok(SessionBootstrap {
        role: KeyExchangeRole::Anke,
        anke_identity: anke_ident,
        boris_identity: boris_ident,
        params,
        session_key: shared_key,
        session_id,
        init_identity: init_ident,
    })
}

#[derive(Hash, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BridgeId {
    pub up: String,
    pub down: String,
}

#[derive(From, Hash, Clone, Display, Debug, PartialEq, Eq, PartialOrd, Ord, Deref)]
pub struct SessionId(String);

pub struct Session<G> {
    local_serial: AtomicU64,
    remote_serial: AtomicU64,
    inbound_guard: Arc<G>,
    outbound_guard: Arc<G>,
    send_counter: Counter,
    send_success_counter: Counter,
    receive_counter: Counter,
    session_key: Vec<u8>,
    codec: Arc<RSCodec>,
    output: Sender<Vec<u8>>,
    receive_timeout: Duration,
    send_cooldown: Duration,
    error_reports: Sender<(u8, u64, HashSet<u8>)>,
    master_sink: Box<dyn Send + Sync + ClonableSink<Message<G>, GenericError>>,
    bridge_builder: BridgeBuilder<G>,
    bridge_drivers: Pin<
        Arc<RwLock<FuturesUnordered<Fuse<Box<dyn Future<Output = ()> + Send + Sync + Unpin>>>>>,
    >,
    role: KeyExchangeRole,
    pub session_id: SessionId,
    pub params: Params,
    pub anke_identity: Identity,
    pub boris_identity: Identity,
    pub init_identity: InitIdentity,
}

pub struct SessionStream {
    send_queue: Arc<SendQueue>,
    receive_queue: Arc<ReceiveQueue>,
    bridges_in_tx: Box<dyn ClonableSink<BridgeMessage, SessionError> + Send + Sync + Unpin>,
    input_tx: Sender<Vec<u8>>,
}

#[derive(Debug)]
pub enum StreamRequest {
    Reset { stream: u8, window: usize },
}

pub trait ClonableFuture<O>: DynClone + Future<Output = O> {
    fn clone_box(&self) -> Box<dyn ClonableFuture<O>>;
    fn clone_pin_box(&self) -> Pin<Box<dyn ClonableFuture<O>>> {
        ClonableFuture::clone_box(self).into()
    }
}

impl<T, O> ClonableFuture<O> for T
where
    T: 'static + Clone + Future<Output = O>,
{
    fn clone_box(&self) -> Box<dyn ClonableFuture<O>> {
        clone_box(self)
    }
}

pub trait ClonableSendableFuture<O>: Send + ClonableFuture<O> {
    fn clone_box(&self) -> Box<dyn Send + ClonableSendableFuture<O>>;
    fn clone_pin_box(&self) -> Pin<Box<dyn Send + ClonableSendableFuture<O>>> {
        ClonableSendableFuture::clone_box(self).into()
    }
}

impl<T, O> ClonableSendableFuture<O> for T
where
    T: 'static + Send + Clone + Future<Output = O>,
{
    fn clone_box(&self) -> Box<dyn Send + ClonableSendableFuture<O>> {
        clone_box(self)
    }
}

pub trait ClonableSink<T, E>: DynClone + Sink<T, Error = E> {
    fn clone_box(&self) -> Box<dyn Send + Sync + ClonableSink<T, E>>;
    fn clone_pin_box(&self) -> Pin<Box<dyn Send + Sync + ClonableSink<T, E>>> {
        ClonableSink::clone_box(self).into()
    }
}

impl<X, T, E> ClonableSink<T, E> for X
where
    X: 'static + Send + Sync + Clone + Sink<T, Error = E>,
{
    fn clone_box(&self) -> Box<dyn Send + Sync + ClonableSink<T, E>> {
        clone_box(self)
    }
}

pub struct SessionBootstrap {
    role: KeyExchangeRole,
    params: Params,
    session_key: Vec<u8>,
    session_id: SessionId,
    anke_identity: Identity,
    boris_identity: Identity,
    init_identity: InitIdentity,
}

pub struct SessionHandle<G> {
    pub session: Pin<Arc<Session<G>>>,
    pub poll: BoxFuture<'static, Result<(), SessionError>>,
    pub input: Sender<Vec<u8>>,
    pub output: Receiver<Vec<u8>>,
    pub progress: UnboundedReceiver<()>,
}

impl<G> Session<G>
where
    G: 'static
        + Send
        + Sync
        + for<'a> From<&'a [u8]>
        + Guard<ClientMessageVariant, (SessionId, u64), Error = GenericError>
        + Guard<BridgeMessage, (), Error = GenericError>,
{
    pub fn new<Timeout: 'static + Send + Future<Output = ()>>(
        session_bootstrap: SessionBootstrap,
        master_messages: Receiver<Message<G>>,
        master_sink: Box<dyn Send + Sync + ClonableSink<Message<G>, GenericError>>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> Timeout,
    ) -> Result<SessionHandle<G>, SessionError> {
        let SessionBootstrap {
            role,
            params,
            session_key,
            anke_identity,
            boris_identity,
            init_identity,
            session_id,
        } = session_bootstrap;
        let (input_tx, input) = channel(4096);
        let (output, output_rx) = channel(4096);
        let (error_reports, error_reports_rx) = channel(4096);
        let (progress, progress_rx) = unbounded();
        let bridge_drivers = FuturesUnordered::new();
        bridge_drivers.push(
            (Box::new(pending()) as Box<dyn Future<Output = ()> + Send + Sync + Unpin>).fuse(),
        );
        let session = Arc::pin(Self {
            role,
            local_serial: <_>::default(),
            remote_serial: <_>::default(),
            inbound_guard: Arc::new(G::from(&session_key)),
            outbound_guard: Arc::new(G::from(&session_key)),
            send_counter: <_>::default(),
            send_success_counter: <_>::default(),
            receive_counter: <_>::default(),
            session_key: session_key.to_vec(),
            codec: Arc::new(RSCodec::new(params.correction).map_err(SessionError::Codec)?),
            output,
            receive_timeout: Duration::new(0, 10000),
            send_cooldown: Duration::new(0, 10000),
            error_reports,
            master_sink,
            bridge_builder: BridgeBuilder::new(),
            bridge_drivers: Arc::pin(RwLock::new(bridge_drivers)),
            session_id: session_id.clone(),
            params,
            anke_identity,
            boris_identity,
            init_identity,
        });
        let poll = Pin::clone(&session)
            .process_stream(
                input,
                error_reports_rx,
                master_messages,
                progress,
                timeout_generator.clone(),
            )
            .boxed();
        Ok(SessionHandle {
            session,
            poll,
            input: input_tx,
            output: output_rx,
            progress: progress_rx,
        })
    }

    async fn send_master_message(
        self: Pin<&Self>,
        message: Message<G>,
    ) -> Result<(), SessionError> {
        ClonableSink::clone_pin_box(&*self.master_sink)
            .send(message)
            .await
            .map_err(|e| SessionError::BrokenPipe(e, <_>::default()))
    }

    async fn invite_bridge_proposal(self: Pin<&Self>) -> Result<(), SessionError> {
        let serial = self.remote_serial.fetch_add(1, Ordering::Relaxed);
        let message = Message::Client(ClientMessage {
            serial,
            session: self.session_id.clone(),
            variant: Redact(Pomerium::encode(
                &*self.outbound_guard,
                ClientMessageVariant::BridgeNegotiate(BridgeNegotiationMessage::ProposeAsk),
            )),
        });
        self.send_master_message(message).await
    }

    async fn reset_remote_stream(self: Pin<&Self>, stream: u8) -> Result<(), SessionError> {
        let serial = self.remote_serial.fetch_add(1, Ordering::Relaxed);
        let message = Message::Client(ClientMessage {
            serial,
            session: self.session_id.clone(),
            variant: Redact(Pomerium::encode(
                &*self.outbound_guard,
                ClientMessageVariant::Stream(StreamRequest::Reset {
                    window: self.params.window,
                    stream,
                }),
            )),
        });
        self.send_master_message(message).await
    }

    async fn construct_bridge_proposals(self: Pin<&Self>) -> Vec<BridgeAsk> {
        // TODO: provide other bridge types
        let mut asks = vec![];
        for _ in 0..3 {
            let (id, params, poll) = match grpc::bridge().await {
                Ok(r) => r,
                Err(e) => {
                    error!("bridge engineer: {}", e);
                    continue;
                }
            };
            self.bridge_drivers.read().await.push(poll.fuse());
            asks.push(BridgeAsk {
                r#type: BridgeType::Grpc(params),
                id,
            })
        }
        asks
    }

    async fn answer_ask_proposal(self: Pin<&Self>) -> Result<(), SessionError> {
        // TODO: proposal
        let proposals = self.as_ref().construct_bridge_proposals().await;
        let serial = self.remote_serial.fetch_add(1, Ordering::Relaxed);
        let message = Message::Client(ClientMessage {
            serial,
            session: self.session_id.clone(),
            variant: Redact(Pomerium::encode(
                &*self.outbound_guard,
                ClientMessageVariant::BridgeNegotiate(BridgeNegotiationMessage::AskProposal(
                    proposals,
                )),
            )),
        });
        self.send_master_message(message).await
    }

    async fn apply_proposal(
        self: Pin<&Self>,
        proposals: &[BridgeAsk],
        poll_bridges_in: &mut HashMap<
            BridgeId,
            Box<dyn Send + Sync + ClonableSendableFuture<BridgeId> + Unpin>,
        >,
        bridges_in_tx: Sender<(BridgeId, BridgeMessage)>,
        bridges_out: &mut HashMap<
            BridgeId,
            Box<dyn Send + Sync + ClonableSink<BridgeMessage, GenericError> + Unpin>,
        >,
    ) -> Vec<BridgeAsk> {
        let mut success = vec![];
        let half = match self.role {
            KeyExchangeRole::Anke => BridgeHalf::Down,
            KeyExchangeRole::Boris => BridgeHalf::Up,
        };
        for BridgeAsk { r#type, id } in proposals {
            match self.bridge_builder.build(r#type, id, half).await {
                Ok(Bridge { tx, rx, poll }) => {
                    let (mapping_tx, mapping_rx) = unbounded();
                    let inbound_guard = Arc::clone(&self.inbound_guard);
                    let outbound_guard = Arc::clone(&self.outbound_guard);
                    bridges_out.insert(
                        id.clone(),
                        Box::new(mapping_tx.sink_map_err(|e| Box::new(e) as GenericError)) as _,
                    );
                    let mut poll_outbound = mapping_rx
                        .map(move |m| Ok(Pomerium::encode(&*outbound_guard, m)))
                        .forward(tx)
                        .unwrap_or_else({
                            move |e| {
                                error!("poll_outbound: {}", e);
                            }
                        })
                        .boxed()
                        .fuse();
                    let mut poll_inbound = rx
                        .and_then(move |p| {
                            let inbound_guard = Arc::clone(&inbound_guard);
                            async move { p.decode(&inbound_guard) }
                        })
                        .map_ok({
                            let id = id.clone();
                            move |p| (id.clone(), p)
                        })
                        .forward(bridges_in_tx.clone().sink_err_into())
                        .unwrap_or_else({
                            move |e| {
                                error!("bridges_in_tx: {}", e);
                            }
                        })
                        .boxed()
                        .fuse();
                    let mut poll = poll.fuse();
                    poll_bridges_in.insert(id.clone(), {
                        let id = id.clone();
                        Box::new(
                            async move {
                                select! {
                                    () = poll_inbound => id,
                                    () = poll_outbound => id,
                                    () = poll => id,
                                }
                            }
                            .boxed()
                            .shared(),
                        )
                    });
                    success.push(BridgeAsk {
                        r#type: r#type.clone(),
                        id: id.clone(),
                    });
                }
                Err(e) => error!("bridge id={:?} error={}", id, e),
            }
        }
        success
    }

    fn update_local_serial(&self, serial: u64) -> u64 {
        let serial = serial + 1;
        loop {
            let local_serial = self.local_serial.load(Ordering::Relaxed);
            if Wrapping(serial) - Wrapping(serial) < Wrapping(1 << 63) {
                break local_serial;
            } else if self
                .local_serial
                .compare_exchange(local_serial, serial, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break serial;
            }
        }
    }

    fn update_remote_serial(&self, serial: u64) -> u64 {
        let serial = serial + 1;
        loop {
            let remote_serial = self.remote_serial.load(Ordering::Relaxed);
            if Wrapping(serial) - Wrapping(serial) < Wrapping(1 << 63) {
                break remote_serial;
            } else if self
                .remote_serial
                .compare_exchange(remote_serial, serial, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break serial;
            }
        }
    }

    async fn notify_serial(
        self: Pin<&Self>,
        serial: u64,
        failure: bool,
    ) -> Result<(), SessionError> {
        let tag = (self.session_id.clone(), serial);
        let message = Message::Client(ClientMessage {
            serial: serial,
            session: self.session_id.clone(),
            variant: Redact(Pomerium::encode_with_tag(
                &*self.outbound_guard,
                if failure {
                    ClientMessageVariant::Err
                } else {
                    ClientMessageVariant::Ok
                },
                &tag,
            )),
        });
        self.send_master_message(message).await
    }

    async fn ask_bridge(self: Pin<&Self>, proposals: Vec<BridgeAsk>) -> Result<(), SessionError> {
        let serial = self.remote_serial.fetch_add(1, Ordering::Relaxed);
        let tag = (self.session_id.clone(), serial);
        let message = Message::Client(ClientMessage {
            serial,
            session: self.session_id.clone(),
            variant: Redact(Pomerium::encode_with_tag(
                &*self.outbound_guard,
                ClientMessageVariant::BridgeNegotiate(BridgeNegotiationMessage::Ask(proposals)),
                &tag,
            )),
        });
        self.send_master_message(message).await
    }

    fn assert_valid_serial(&self, serial: u64) -> Result<u64, u64> {
        let local_serial = self.local_serial.load(Ordering::Relaxed);
        let diff = Wrapping(serial) - Wrapping(local_serial);
        if diff == Wrapping(0) || diff > Wrapping(1 << 63) {
            Err(local_serial)
        } else {
            Ok(serial)
        }
    }

    async fn answer_bridge_health_query(self: Pin<&Self>) -> Result<(), SessionError> {
        let serial = self.remote_serial.fetch_add(1, Ordering::Relaxed);
        let tag = (self.session_id.clone(), serial);
        let health = self
            .receive_counter
            .counters
            .read()
            .await
            .iter()
            .map(|(id, recvs)| (id.clone(), recvs.load(Ordering::Relaxed)))
            .collect();
        let message = Message::Client(ClientMessage {
            serial,
            session: self.session_id.clone(),
            variant: Redact(Pomerium::encode_with_tag(
                &*self.outbound_guard,
                ClientMessageVariant::BridgeNegotiate(BridgeNegotiationMessage::Health(health)),
                &tag,
            )),
        });
        self.send_master_message(message).await
    }

    async fn process_stream<Timeout: 'static + Send + Future<Output = ()>>(
        self: Pin<Arc<Self>>,
        input: Receiver<Vec<u8>>,
        error_reports: Receiver<(u8, u64, HashSet<u8>)>,
        master_messages: Receiver<Message<G>>,
        progress: UnboundedSender<()>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> Timeout,
    ) -> Result<(), SessionError> {
        let hall_of_fame: RwLock<
            LruCache<u8, Mutex<LruCache<u64, HashMap<u8, Option<BridgeId>>>>>,
        > = RwLock::new(LruCache::new(256));
        let (bridges_out_tx, bridges_out_rx) = channel(4096);
        let (bridges_in_tx, bridges_in_rx) = channel(4096);
        let stream_polls: Arc<
            RwLock<
                HashMap<
                    u8,
                    (
                        SessionStream,
                        Pin<Box<dyn Sync + ClonableSendableFuture<()>>>,
                    ),
                >,
            >,
        > = <_>::default();
        let bridges_out: RwLock<
            HashMap<
                BridgeId,
                Box<dyn Send + Sync + ClonableSink<BridgeMessage, GenericError> + Unpin>,
            >,
        > = <_>::default();
        let bridge_polls: RwLock<
            HashMap<BridgeId, Box<dyn Send + Sync + ClonableSendableFuture<BridgeId> + Unpin>>,
        > = <_>::default();
        let mut error_reports = error_reports
            .map(Ok)
            .try_for_each(|(stream, serial, errors)| {
                let hall_of_fame = &hall_of_fame;
                let receive_counter = &self.receive_counter;
                let mut progress = progress.clone();
                async move {
                    let recvs = if let Some(stream) = hall_of_fame.read().await.peek(&stream) {
                        if let Some(recvs) = stream.lock().await.pop(&serial) {
                            recvs
                        } else {
                            return Ok(());
                        }
                    } else {
                        return Ok(());
                    };
                    for bridge_id in recvs.into_iter().filter_map(|(id, bridge_id)| {
                        if errors.contains(&id) {
                            None
                        } else {
                            bridge_id
                        }
                    }) {
                        if let Some(counter) = receive_counter.counters.read().await.get(&bridge_id)
                        {
                            counter.fetch_add(1, Ordering::Relaxed);
                        } else {
                            receive_counter
                                .counters
                                .write()
                                .await
                                .entry(bridge_id)
                                .or_default()
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    progress
                        .send(())
                        .await
                        .map_err(|e| SessionError::BrokenPipe(Box::new(e), <_>::default()))
                }
            })
            .boxed()
            .fuse();
        let mut input = input
            .map(Ok)
            .try_for_each_concurrent(4096, {
                |input| {
                    async {
                        let mut input_tx = loop {
                            if let Some((_, (session_stream, _))) = stream_polls
                                .read()
                                .await
                                .iter()
                                .choose(&mut StdRng::from_entropy())
                            {
                                break session_stream.input_tx.clone();
                            }
                        };
                        input_tx.send(input).await
                    }
                }
            })
            .boxed()
            .fuse();
        let mut poll_bridges_out = bridges_out_rx
            .map(Ok::<_, String>)
            .try_for_each_concurrent(4096, {
                |outbound| {
                    async {
                        let mut rng = StdRng::from_entropy();
                        let (bridge_id, mut tx) = loop {
                            if let Some((bridge_id, bridge)) =
                                bridges_out.read().await.iter().choose(&mut rng)
                            {
                                break (bridge_id.clone(), ClonableSink::clone_pin_box(&**bridge));
                            }
                        };
                        match tx.send(outbound).await {
                            Err(e) => error!("poll_bridges_out: {}", e),
                            _ => (),
                        }
                        if let Some(counter) =
                            self.send_counter.counters.read().await.get(&bridge_id)
                        {
                            counter.fetch_add(1, Ordering::Relaxed);
                        } else {
                            self.send_counter
                                .counters
                                .write()
                                .await
                                .entry(bridge_id)
                                .or_default()
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(())
                    }
                }
            })
            .boxed()
            .fuse();
        let mut poll_bridges_in = bridges_in_rx
            .for_each_concurrent(4096, {
                let stream_polls = &stream_polls;
                let hall_of_fame = &hall_of_fame;
                move |(bridge_id, inbound)| {
                    async move {
                        let stream = match &inbound {
                            BridgeMessage::PayloadFeedback { stream, .. } => *stream,
                            BridgeMessage::Payload { raw_shard_id, .. } => raw_shard_id.stream,
                        };
                        let report = if let BridgeMessage::Payload {
                            raw_shard_id: RawShardId { stream, serial, id },
                            ..
                        } = &inbound
                        {
                            Some((*stream, *serial, *id, bridge_id))
                        } else {
                            None
                        };
                        match loop {
                            let stream_polls = stream_polls.read().await;
                            if let Some((session_stream, _)) = stream_polls.get(&stream) {
                                break ClonableSink::clone_pin_box(&*session_stream.bridges_in_tx);
                            }
                        }
                        .send(inbound)
                        .await
                        {
                            Ok(_) => {
                                if let Some((stream, serial, id, bridge_id)) = report {
                                    let fame = hall_of_fame.read().await;
                                    if let Some(stream) = fame.peek(&stream) {
                                        let mut stream = stream.lock().await;
                                        if let Some(serial) = stream.peek_mut(&serial) {
                                            let id = serial.entry(id).or_default();
                                            if id.is_some() {
                                                id.take();
                                            }
                                        } else {
                                            let mut map = HashMap::new();
                                            map.insert(id, Some(bridge_id));
                                            stream.put(serial, map);
                                        }
                                    } else {
                                        drop(fame);
                                        let mut fame = hall_of_fame.write().await;
                                        if let Some(stream) = fame.peek(&stream) {
                                            let mut stream = stream.lock().await;
                                            if let Some(serial) = stream.peek_mut(&serial) {
                                                let id = serial.entry(id).or_default();
                                                if let Some(bridge_id_) = id {
                                                    if *bridge_id_ != bridge_id {
                                                        id.take();
                                                    }
                                                }
                                            } else {
                                                let mut map = HashMap::new();
                                                map.insert(id, Some(bridge_id));
                                                stream.put(serial, map);
                                            }
                                        } else {
                                            let mut table = LruCache::new(255);
                                            let mut map = HashMap::new();
                                            map.insert(id, Some(bridge_id));
                                            table.put(serial, map);
                                            fame.put(stream, Mutex::new(table));
                                        }
                                    }
                                }
                            }
                            Err(e) => error!("poll_bridges_in: {}", e),
                        }
                    }
                }
            })
            .boxed()
            .fuse();
        let mut poll_master_messages = master_messages
            .map(Ok)
            .try_for_each(|request| {
                let this = &self;
                let stream_polls = &stream_polls;
                let bridge_polls = &bridge_polls;
                let bridges_in_tx = bridges_in_tx.clone();
                let bridges_out_tx = bridges_out_tx.clone();
                let bridges_out = &bridges_out;
                let timeout_generator = timeout_generator.clone();
                let mut progress = progress.clone();
                async move {
                    match request {
                        Message::Client(ClientMessage {
                            serial,
                            session,
                            variant: Redact(variant),
                        }) => {
                            let tag = (session.clone(), serial);
                            match variant.decode_with_tag(&this.inbound_guard, &tag) {
                                Ok(variant) => {
                                    // prevent replay
                                    if let Err(local_serial) = this.assert_valid_serial(serial) {
                                        return this
                                            .as_ref()
                                            .notify_serial(local_serial, true)
                                            .await;
                                    }
                                    match variant {
                                        ClientMessageVariant::BridgeNegotiate(negotiation) => {
                                            match negotiation {
                                                BridgeNegotiationMessage::ProposeAsk => {
                                                    this.as_ref().answer_ask_proposal().await?
                                                }
                                                BridgeNegotiationMessage::Ask(proposals) => {
                                                    this.as_ref()
                                                        .apply_proposal(
                                                            &proposals,
                                                            &mut *bridge_polls.write().await,
                                                            bridges_in_tx.clone(),
                                                            &mut *bridges_out.write().await,
                                                        )
                                                        .await;
                                                }
                                                BridgeNegotiationMessage::Retract(bridges_) => {
                                                    let mut bridges_out = bridges_out.write().await;
                                                    for BridgeRetract(id) in bridges_ {
                                                        bridges_out.remove(&id);
                                                        bridge_polls.write().await.remove(&id);
                                                    }
                                                }
                                                BridgeNegotiationMessage::AskProposal(
                                                    proposals,
                                                ) => {
                                                    let asks = this
                                                        .as_ref()
                                                        .apply_proposal(
                                                            &proposals,
                                                            &mut *bridge_polls.write().await,
                                                            bridges_in_tx.clone(),
                                                            &mut *bridges_out.write().await,
                                                        )
                                                        .await;
                                                    this.as_ref().ask_bridge(asks).await?
                                                }
                                                BridgeNegotiationMessage::QueryHealth => {
                                                    this.as_ref()
                                                        .answer_bridge_health_query()
                                                        .await?
                                                }
                                                BridgeNegotiationMessage::Health(health) => {
                                                    let mut counters = this
                                                        .send_success_counter
                                                        .counters
                                                        .write()
                                                        .await;
                                                    for (id, count) in health {
                                                        counters
                                                            .entry(id)
                                                            .or_default()
                                                            .fetch_add(count, Ordering::Relaxed);
                                                    }
                                                }
                                            }
                                        }
                                        ClientMessageVariant::Stream(request) => match request {
                                            StreamRequest::Reset { stream, window } => {
                                                let (session_stream, poll) = this.new_stream(
                                                    stream,
                                                    window,
                                                    bridges_out_tx.clone(),
                                                    timeout_generator.clone(),
                                                );
                                                stream_polls.write().await.insert(
                                                    stream,
                                                    (session_stream, Box::pin(poll.shared())),
                                                );
                                            }
                                        },
                                        ClientMessageVariant::Ok | ClientMessageVariant::Err => {
                                            this.update_remote_serial(serial);
                                            return progress.send(()).await.map_err(|e| {
                                                SessionError::BrokenPipe(
                                                    Box::new(e),
                                                    <_>::default(),
                                                )
                                            });
                                        }
                                    }
                                    this.as_ref()
                                        .notify_serial(this.update_local_serial(serial), false)
                                        .await?;
                                    progress.send(()).await.map_err(|e| {
                                        SessionError::BrokenPipe(Box::new(e), <_>::default())
                                    })
                                }
                                Err(e) => {
                                    error!("decode error: {}", e);
                                    Ok(())
                                }
                            }
                        }
                        _ => Ok(()),
                    }
                }
            })
            .boxed()
            .fuse();

        let mut poll_streams = async {
            let mut progress = progress.clone();
            loop {
                let polls: Vec<_> = stream_polls
                    .read()
                    .await
                    .iter()
                    .map(|(stream, (_, polls))| {
                        let stream: u8 = *stream;
                        let polls = ClonableSendableFuture::clone_pin_box(&**polls);
                        polls.map(move |_| stream).boxed()
                    })
                    .collect();
                if polls.is_empty() {
                    let (session_stream, poll) = self.new_stream(
                        0,
                        self.params.window,
                        bridges_out_tx.clone(),
                        timeout_generator.clone(),
                    );
                    stream_polls
                        .write()
                        .await
                        .insert(0, (session_stream, Box::pin(poll.shared())));
                    self.as_ref().reset_remote_stream(0).await?
                } else {
                    let (stream, _, _) = future::select_all(polls).await;
                    stream_polls.write().await.remove(&stream);
                }
                progress
                    .send(())
                    .await
                    .map_err(|e| SessionError::BrokenPipe(Box::new(e), <_>::default()))?
            }
        }
        .boxed()
        .fuse();
        let mut poll_bridges = async {
            let mut progress = progress.clone();
            let mut last_invite = Instant::now();
            let invite_cooldown = Duration::new(10, 0);
            loop {
                let polls: Vec<_> = bridge_polls
                    .read()
                    .await
                    .values()
                    .map(|poll| ClonableSendableFuture::clone_pin_box(&**poll))
                    .collect();
                if polls.is_empty() {
                    let now = Instant::now();
                    if now.duration_since(last_invite) > invite_cooldown {
                        self.as_ref().invite_bridge_proposal().await?;
                        last_invite = Instant::now();
                    } else {
                        timeout_generator(Duration::new(0, 3000000)).await;
                        continue;
                    }
                } else {
                    let (bridge, _, _) = future::select_all(polls).await;
                    bridge_polls.write().await.remove(&bridge);
                    self.send_counter.counters.write().await.remove(&bridge);
                    self.send_success_counter
                        .counters
                        .write()
                        .await
                        .remove(&bridge);
                    self.receive_counter.counters.write().await.remove(&bridge);
                }
                progress
                    .send(())
                    .await
                    .map_err(|e| SessionError::BrokenPipe(Box::new(e), <_>::default()))?
            }
        }
        .boxed()
        .fuse();
        let mut poll_bridge_drivers =
            async { while let Some(_) = self.bridge_drivers.write().await.next().await {} }
                .boxed()
                .fuse();
        select! {
            result = error_reports => result,
            _ = poll_bridges_in => Ok(()),
            _ = poll_bridges_out => Ok(()),
            _ = poll_master_messages => Ok(()),
            _ = poll_bridge_drivers => Ok(()),
            result = poll_streams => result,
            result = poll_bridges => result,
            result = input => {
                result.map_err(|e| SessionError::BrokenPipe(Box::new(e), <_>::default()))
            }
        }
    }

    pub fn new_stream<Timeout: 'static + Send + Future<Output = ()>>(
        &self,
        stream: u8,
        window: usize,
        bridges_out_tx: Sender<BridgeMessage>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> Timeout,
    ) -> (SessionStream, impl 'static + Future<Output = ()> + Send) {
        let (input_tx, input_rx) = channel(window);
        let (task_notifiers_tx, task_notifiers_rx) = channel(window);
        let (bridges_in_tx, bridges_in_rx) = unbounded();
        let bridges_in_tx = Box::new(
            bridges_in_tx
                .sink_map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default())),
        ) as _;
        let task_notifiers_tx = task_notifiers_tx.sink_map_err(|e| Box::new(e) as GenericError);
        let (payload_tx, payload_rx) = unbounded();
        let (feedback_tx, feedback_rx) = unbounded();
        let poll_bridges_in = bridges_in_rx.map(Ok::<_, GenericError>).try_fold(
            (payload_tx, feedback_tx),
            move |(mut payload_tx, mut feedback_tx), message| {
                async move {
                    match message {
                        BridgeMessage::Payload {
                            raw_shard,
                            raw_shard_id,
                        } => {
                            payload_tx.send((raw_shard, raw_shard_id)).await?;
                        }
                        BridgeMessage::PayloadFeedback {
                            feedback,
                            stream: stream_,
                        } if stream == stream_ => {
                            feedback_tx.send(feedback).await?;
                        }
                        _ => eprintln!("unknown message"),
                    }
                    Ok((payload_tx, feedback_tx))
                }
            },
        );
        let task_notifiers: Arc<RwLock<BTreeMap<u64, TaskProgressNotifier>>> = <_>::default();
        let poll_task_notifiers = task_notifiers_rx.for_each({
            let task_notifiers = Arc::clone(&task_notifiers);
            move |(serial, task_notifier)| {
                let task_notifiers = Arc::clone(&task_notifiers);
                async move {
                    task_notifiers.write().await.insert(serial, task_notifier);
                }
            }
        });

        let send_queue = Arc::new(SendQueue::new(
            stream,
            window,
            Box::new(task_notifiers_tx) as _,
        ));
        let receive_queue = Arc::new(ReceiveQueue::new());

        let poll_feedback = {
            let task_notifiers_ptr = Arc::clone(&task_notifiers);
            let send_queue = Arc::clone(&send_queue);
            let timeout_generator = timeout_generator.clone();
            let send_cooldown = self.send_cooldown;
            let mut feedback_rx = feedback_rx.fuse();
            async move {
                loop {
                    let task_notifiers = task_notifiers_ptr.read().await;
                    if task_notifiers.len() > window {
                        drop(task_notifiers);
                        let mut task_notifiers = task_notifiers_ptr.write().await;
                        let serials: HashSet<_> = task_notifiers.keys().copied().collect();
                        if task_notifiers.len() > window {
                            for serial in serials {
                                if let Some(_) =
                                    task_notifiers.get(&serial).and_then(|n| n.upgrade())
                                {
                                    task_notifiers.remove(&serial);
                                }
                            }
                        }
                    } else {
                        if let Some(feedback) = feedback_rx.next().await {
                            match feedback {
                                PayloadFeedback::Ok { serial, id, quorum } => {
                                    if let Some(notifier) =
                                        task_notifiers.get(&serial).and_then(|n| n.upgrade())
                                    {
                                        if let Err(e) =
                                            notifier.lock().await.send(Ok((id, quorum))).await
                                        {
                                            error!("pipe: {}", e);
                                        }
                                    }
                                }
                                PayloadFeedback::Duplicate { serial, id, quorum } => {
                                    if let Some(notifier) =
                                        task_notifiers.get(&serial).and_then(|n| n.upgrade())
                                    {
                                        if let Err(e) =
                                            notifier.lock().await.send(Ok((id, quorum))).await
                                        {
                                            error!("pipe: {}", e);
                                        }
                                    }
                                }
                                PayloadFeedback::Full { serial, queue_len } => {
                                    error!("backpressure, serial={}, queue={}", serial, queue_len);
                                    send_queue
                                        .block_sending(timeout_generator(send_cooldown))
                                        .await
                                }
                                PayloadFeedback::OutOfBound {
                                    serial,
                                    start,
                                    queue_len,
                                } => error!(
                                    "out of bound: serial={}, start={}, queue={}",
                                    serial, start, queue_len
                                ),
                                PayloadFeedback::Malformed { serial } => {
                                    if let Some(notifier) =
                                        task_notifiers.get(&serial).and_then(|n| n.upgrade())
                                    {
                                        if let Err(e) = notifier
                                            .lock()
                                            .await
                                            .send(Err(RemoteRecvError::Malformed))
                                            .await
                                        {
                                            error!("pipe: {}", e);
                                        }
                                    }
                                }
                                PayloadFeedback::Complete { serial } => {
                                    if let Some(notifier) =
                                        task_notifiers.get(&serial).and_then(|n| n.upgrade())
                                    {
                                        if let Err(e) = notifier
                                            .lock()
                                            .await
                                            .send(Err(RemoteRecvError::Complete))
                                            .await
                                        {
                                            error!("pipe: {}", e);
                                        }
                                    }
                                }
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        };

        let poll_send_pending = {
            let send_queue = Arc::clone(&send_queue);
            move |_| {
                let send_queue = Arc::clone(&send_queue);
                async move {
                    loop {
                        match send_queue.pop().await {
                            Some(data) => return data,
                            _ => (),
                        }
                    }
                }
            }
        };
        let poll_send_pending = repeat(())
            .map(poll_send_pending)
            .buffer_unordered(window)
            .map(|(raw_shard, raw_shard_id)| {
                Ok(BridgeMessage::Payload {
                    raw_shard,
                    raw_shard_id,
                })
            })
            .forward(bridges_out_tx.clone())
            .map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()));

        let poll_recv = {
            let receive_queue = Arc::clone(&receive_queue);
            let codec = Arc::clone(&self.codec);
            repeat(()).filter_map(move |_| {
                let receive_queue = Arc::clone(&receive_queue);
                let codec = Arc::clone(&codec);
                async move { receive_queue.poll(&codec).await }
            })
        };
        let poll_recv = {
            let receive_queue = Arc::clone(&receive_queue);
            let codec = Arc::clone(&self.codec);
            let timeout = self.receive_timeout;
            let timeout_generator = timeout_generator.clone();
            let mut bridges_out_tx = bridges_out_tx.clone();
            let mut error_reports = self.error_reports.clone();
            let mut output = self.output.clone();
            async move {
                let mut poll_recv = Box::pin(poll_recv.fuse());
                loop {
                    let front = select! {
                        front = poll_recv.next() => {
                            if let Some(front) = front {
                                front
                            } else {
                                break
                            }
                        },
                        _ = timeout_generator(timeout).fuse() => {
                            if let Some(front) = receive_queue.pop_front().await {
                                front.poll(&codec)
                            } else {
                                continue
                            }
                        }
                    };
                    match front {
                        Ok((serial, data, errors)) => {
                            // hall of shame
                            let (data, errors) = join!(
                                output.send(data),
                                error_reports.send((stream, serial, errors))
                            );
                            data?;
                            errors?;
                            bridges_out_tx
                                .send(BridgeMessage::PayloadFeedback {
                                    stream,
                                    feedback: PayloadFeedback::Complete { serial },
                                })
                                .await?;
                        }
                        Err(e) => {
                            // TODO: fine grained error reporting
                            error!("pop front: {}", e)
                        }
                    }
                }
                Ok::<_, GenericError>(())
            }
        };

        let mut shard_state = ShardState::default();
        for chunk in sha3::Sha3_512::digest(&self.session_key).chunks(32) {
            for (s, c) in chunk.iter().zip(shard_state.key.iter_mut()) {
                *c ^= s
            }
        }
        for chunk in sha3::Sha3_512::new()
            .chain(&self.session_key)
            .chain(b", stream=")
            .chain(&[stream])
            .result()
            .chunks(32)
        {
            for (s, c) in chunk.iter().zip(shard_state.stream_key.iter_mut()) {
                *c ^= s
            }
        }

        let poll_admit = {
            let receive_queue = Arc::clone(&receive_queue);
            let shard_state = shard_state;
            payload_rx
                .fuse()
                .filter_map(move |(raw_shard, raw_shard_id)| {
                    let receive_queue = Arc::clone(&receive_queue);
                    let serial = raw_shard_id.serial;
                    async move {
                        match receive_queue
                            .admit(raw_shard, raw_shard_id, &shard_state)
                            .await
                        {
                            Ok((id, quorum_size)) => Some(PayloadFeedback::Ok {
                                serial,
                                id,
                                quorum: quorum_size,
                            }),
                            Err(ReceiveError::Full(queue_len)) => {
                                Some(PayloadFeedback::Full { queue_len, serial })
                            }
                            Err(ReceiveError::OutOfBound(start, queue_len)) => {
                                Some(PayloadFeedback::OutOfBound {
                                    start,
                                    queue_len,
                                    serial,
                                })
                            }
                            Err(ReceiveError::Quorum(QuorumError::Duplicate(id, quorum))) => {
                                Some(PayloadFeedback::Duplicate { serial, id, quorum })
                            }
                            Err(ReceiveError::Quorum(QuorumError::Malformed { .. }))
                            | Err(ReceiveError::Quorum(QuorumError::MismatchContent(..))) => {
                                Some(PayloadFeedback::Malformed { serial })
                            }
                            Err(e) => {
                                error!("admission: {}", e);
                                None
                            }
                        }
                    }
                })
                .map(move |feedback| Ok(BridgeMessage::PayloadFeedback { stream, feedback }))
                .forward(bridges_out_tx.clone())
        };
        let poll_send = input_rx.map(Ok).try_for_each_concurrent(window, {
            let send_queue = Arc::clone(&send_queue);
            let shard_state = shard_state;
            let codec = Arc::clone(&self.codec);
            let timeout_generator = timeout_generator.clone();
            let timeout = self.send_cooldown;
            move |input| {
                let send_queue = Arc::clone(&send_queue);
                let codec = Arc::clone(&codec);
                let timeout_generator = timeout_generator.clone();
                async move {
                    match send_queue
                        .send(&input, &shard_state, &codec, timeout_generator, timeout)
                        .await
                    {
                        Ok(_) => (),
                        Err(SendError::BrokenPipe) => {
                            return Err(SessionError::BrokenPipe(
                                Box::new(SendError::BrokenPipe.compat()),
                                <_>::default(),
                            ))
                        }
                        Err(e) => error!("send: {}", e),
                    }
                    Ok(())
                }
            }
        });

        let poll_all = async move {
            select! {
                _ = poll_bridges_in.boxed().fuse() => (),
                _ = poll_task_notifiers.boxed().fuse() => (),
                _ = poll_feedback.boxed().fuse() => (),
                _ = poll_send_pending.boxed().fuse() => (),
                _ = poll_recv.fuse() => (),
                _ = poll_admit.boxed().fuse() => (),
                _ = poll_send.boxed().fuse() => (),
            }
        };

        (
            SessionStream {
                send_queue,
                receive_queue,
                bridges_in_tx,
                input_tx,
            },
            poll_all,
        )
    }
}

#[derive(Fail, Debug)]
pub enum SessionError {
    #[fail(display = "unknown bridge type")]
    UnknownBridgeType,
    #[fail(display = "broken pipe: {}", _0)]
    BrokenPipe(GenericError, Backtrace),
    #[fail(display = "codec: {}", _0)]
    Codec(#[cause] CodecError),
    #[fail(display = "token: {:?}", _0)]
    SignOn(String),
    #[fail(display = "stream: {}", _0)]
    Stream(GenericError, Backtrace),
    #[fail(display = "bridge: {}", _0)]
    Bridge(GenericError, Backtrace),
}

#[derive(Default)]
struct Counter {
    counters: RwLock<HashMap<BridgeId, AtomicU64>>,
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
    pub async fn build(
        &self,
        r#type: &BridgeType,
        id: &BridgeId,
        half: BridgeHalf,
    ) -> Result<Bridge<G>, SessionError> {
        match r#type {
            BridgeType::Grpc(params) => grpc::GrpcBridge
                .build(id, params, half)
                .await
                .map_err(|e| SessionError::Bridge(Box::new(e.compat()), <_>::default())),
            BridgeType::Unix(params) => grpc::UnixBridge
                .build(id, params, half)
                .await
                .map_err(|e| SessionError::Bridge(Box::new(e.compat()), <_>::default())),
            _ => Err(SessionError::UnknownBridgeType),
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

pub(crate) struct SafeGuard {
    aead: Aes256GcmSiv,
}

impl Debug for SafeGuard {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "<SafeGuard>")
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
        let key = SafeGuard::derive_key(key);
        Self {
            aead: Aes256GcmSiv::new(*GenericArray::from_slice(&key)),
        }
    }
    fn encode_message<P: ProstMessage>(payload: P) -> Vec<u8> {
        let mut buf = vec![];
        payload.encode(&mut buf).expect("sufficient space");
        buf
    }
    fn decode_message<P: ProstMessage + Default>(data: Vec<u8>) -> Result<P, GenericError> {
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

pub(crate) trait ProstMessageMapping: Sized {
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

impl<P, T> Guard<P, T> for SafeGuard
where
    P: ProstMessageMapping<Tag = T>,
    T: Tag,
    <P::MapTo as TryInto<P>>::Error: 'static + Send + Sync,
    GenericError: From<<P::MapTo as TryInto<P>>::Error>,
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
        buf.splice(..0, nonce.to_vec());
        buf
    }
    fn encode_with_tag(&self, payload: P, tag: &T) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let payload = <P as ProstMessageMapping>::MapTo::from(payload);
        let payload = Self::encode_message(payload);
        let mut buf = self
            .aead
            .encrypt(
                GenericArray::from_slice(&nonce),
                Payload {
                    msg: &payload,
                    aad: &tag.into_bytes(),
                },
            )
            .expect("correct key sizes and bounds");
        buf.splice(..0, nonce.to_vec());
        buf
    }
    fn decode(&self, data: &[u8]) -> Result<P, Self::Error> {
        if data.len() < 12 {
            return Err(Box::new(err_msg("truncated data").compat()));
        }
        let mut nonce = [0u8; 12];
        nonce[..].copy_from_slice(&data[..12]);
        let (_, data) = data.split_at(12);
        let buf = self
            .aead
            .decrypt(GenericArray::from_slice(&nonce), data)
            .map_err(|e| Box::new(err_msg(format!("decode: {:?}", e)).compat()))?;
        let payload: <P as ProstMessageMapping>::MapTo = Self::decode_message(buf)?;
        Ok(payload.try_into()?)
    }
    fn decode_with_tag(&self, data: &[u8], tag: &T) -> Result<P, Self::Error> {
        if data.len() < 12 {
            return Err(Box::new(err_msg("truncated data").compat()));
        }
        let mut nonce = [0u8; 12];
        nonce[..].copy_from_slice(&data[..12]);
        let (_, data) = data.split_at(12);
        let buf = self
            .aead
            .decrypt(
                GenericArray::from_slice(&nonce),
                Payload {
                    msg: data,
                    aad: &tag.into_bytes(),
                },
            )
            .map_err(|e| Box::new(err_msg(format!("decode: {:?}", e)).compat()))?;
        let payload: <P as ProstMessageMapping>::MapTo = Self::decode_message(buf)?;
        Ok(payload.try_into()?)
    }
}
