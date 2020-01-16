use core::{
    convert::TryInto,
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
    num::Wrapping,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    time::Instant,
};

use aead::{Aead, NewAead, Payload};
use aes_gcm_siv::Aes256GcmSiv;
use async_std::sync::{Arc, Mutex, RwLock, RwLockReadGuard};
use failure::{err_msg, Backtrace, Error as TopError, Fail};
use futures::{
    channel::mpsc::{channel, Receiver, Sender},
    future::{BoxFuture, Fuse},
    join,
    prelude::*,
    select,
    stream::{iter, unfold, FuturesUnordered},
};
use generic_array::GenericArray;
use log::{debug, error, info, trace};
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
    utils::{ClonableSendableFuture, ClonableSink, Spawn, WakerQueue},
    GenericError, Redact,
};

pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/protocol.rs"));
}

mod apply_proposal;
mod bridges;
mod bridges_in;
mod bridges_out;
mod convert;
mod error_reports;
mod input;
mod key_exchange;
mod master_messages;
mod new_stream;
mod streams;
pub use convert::WireError;
pub use key_exchange::{key_exchange_anke, key_exchange_boris};

#[derive(From, Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Debug, Deref)]
pub struct InitIdentity(String);

impl From<&'_ Init> for InitIdentity {
    fn from(Init(init): &'_ Init) -> Self {
        let mut digest = sha3::Sha3_512::new();
        for bytes in init.into_coeff_bytes() {
            digest.input(bytes);
        }
        Self(format!("{:x}", digest.result()))
    }
}

#[derive(From, Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Debug, Deref)]
pub struct Identity(String);

impl From<&'_ PublicKey> for Identity {
    fn from(PublicKey(key): &'_ PublicKey) -> Self {
        let mut digest = sha3::Sha3_512::new();
        for bytes in key.into_coeff_bytes() {
            digest.input(bytes);
        }
        Self(format!("{:x}", digest.result()))
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
    pub correction: u8,
    pub entropy: u8,
    pub window: usize,
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
    #[fail(display = "unknown message received, {}", _0)]
    UnknownMessage(Backtrace),
    #[fail(display = "message decoding: {}", _0)]
    Message(#[cause] TopError, Backtrace),
    #[fail(display = "sending message: {}", _0)]
    MessageSink(#[cause] TopError, Backtrace),
    #[fail(display = "message receiving terminated: {}", _0)]
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

#[derive(Hash, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BridgeId {
    pub up: String,
    pub down: String,
}

#[derive(From, Hash, Clone, Display, Debug, PartialEq, Eq, PartialOrd, Ord, Deref)]
pub struct SessionId(String);

type StreamPolls = HashMap<
    u8,
    (
        SessionStream,
        Pin<Box<dyn Sync + ClonableSendableFuture<()>>>,
    ),
>;

type BridgePolls = HashMap<
    BridgeId,
    (
        Box<dyn Send + Sync + ClonableSink<BridgeMessage, GenericError> + Unpin>,
        Box<dyn Send + Sync + ClonableSendableFuture<BridgeId> + Unpin>,
    ),
>;

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

    // internal states
    error_reports: Sender<(u8, u64, HashSet<u8>)>,
    master_sink: Box<dyn Send + Sync + ClonableSink<Message<G>, GenericError>>,
    bridge_builder: BridgeBuilder<G>,
    bridge_drivers: Pin<
        Arc<RwLock<FuturesUnordered<Fuse<Box<dyn Future<Output = ()> + Send + Sync + Unpin>>>>>,
    >,
    stream_polls: Arc<RwLock<StreamPolls>>,
    stream_polls_waker_queue: WakerQueue,
    bridge_polls_waker_queue: WakerQueue,
    bridge_polls: Arc<RwLock<BridgePolls>>,
    hall_of_fame: Arc<RwLock<LruCache<u8, Mutex<LruCache<u64, HashMap<u8, Option<BridgeId>>>>>>>,
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
    pub progress: Receiver<()>,
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
    pub fn new<T, S>(
        session_bootstrap: SessionBootstrap,
        master_messages: Receiver<Message<G>>,
        master_sink: Box<dyn Send + Sync + ClonableSink<Message<G>, GenericError>>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
        spawn: S,
    ) -> Result<SessionHandle<G>, SessionError>
    where
        S: Spawn + Clone + Send + Sync + 'static,
        T: 'static + Send + Future<Output = ()>,
    {
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
        let (progress, progress_rx) = channel(4096);
        let (bridges_out_tx, bridges_out_rx) = channel(4096);
        let (bridges_in_tx, bridges_in_rx) = channel(4096);
        let bridge_drivers = FuturesUnordered::new();
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
            receive_timeout: Duration::new(0, 1_000_000_00),
            send_cooldown: Duration::new(0, 1_000_000_00),
            stream_polls_waker_queue: <_>::default(),
            bridge_polls_waker_queue: <_>::default(),

            error_reports,
            master_sink,
            bridge_builder: BridgeBuilder::new(),
            bridge_drivers: Arc::pin(RwLock::new(bridge_drivers)),
            stream_polls: <_>::default(),
            bridge_polls: <_>::default(),
            hall_of_fame: Arc::new(RwLock::new(LruCache::new(256))),

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
                bridges_out_tx,
                bridges_out_rx,
                bridges_in_tx,
                bridges_in_rx,
                timeout_generator.clone(),
                spawn,
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

    // processes
    async fn handle_bridge_drivers<T>(
        self: Pin<&Self>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
    ) where
        T: 'static + Send + Future<Output = ()>,
    {
        loop {
            trace!("{:?}: poll_bridge_drivers", self.role);
            let mut bridge_drivers = self.bridge_drivers.write().await;
            if bridge_drivers.len() > 0 {
                bridge_drivers.next().await;
            } else {
                drop(bridge_drivers);
                timeout_generator(Duration::new(1, 0)).await;
            }
        }
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
        trace!("{:?}: invite bridge proposals", self.role);
        let serial = self.remote_serial.fetch_add(1, Ordering::Relaxed);
        let message = Message::Client(ClientMessage {
            serial,
            session: self.session_id.clone(),
            variant: Redact(Pomerium::encode_with_tag(
                &*self.outbound_guard,
                ClientMessageVariant::BridgeNegotiate(BridgeNegotiationMessage::ProposeAsk),
                &(self.session_id.clone(), serial),
            )),
        });
        self.send_master_message(message).await
    }

    async fn reset_remote_stream(self: Pin<&Self>, stream: u8) -> Result<(), SessionError> {
        let serial = self.remote_serial.fetch_add(1, Ordering::Relaxed);
        let message = Message::Client(ClientMessage {
            serial,
            session: self.session_id.clone(),
            variant: Redact(Pomerium::encode_with_tag(
                &*self.outbound_guard,
                ClientMessageVariant::Stream(StreamRequest::Reset {
                    window: self.params.window,
                    stream,
                }),
                &(self.session_id.clone(), serial),
            )),
        });
        self.send_master_message(message).await
    }

    async fn construct_bridge_proposals<S>(self: Pin<&Self>, spawn: S) -> Vec<BridgeAsk>
    where
        S: Spawn + Clone + Send + Sync + 'static,
    {
        // TODO: provide other bridge types
        let mut asks = vec![];
        for _ in 0..3 {
            trace!("{:?}: building bridge", self.role);
            let (id, params, poll) = match grpc::bridge(spawn.clone()).await {
                Ok(r) => r,
                Err(e) => {
                    error!("{:?}: bridge engineer: {}", self.role, e);
                    continue;
                }
            };
            self.bridge_drivers.read().await.push(poll.fuse());
            trace!("{:?}: bridge constructed", self.role);
            asks.push(BridgeAsk {
                r#type: BridgeType::Grpc(params),
                id,
            })
        }
        trace!("{:?}: constructed bridge proposals", self.role);
        asks
    }

    async fn answer_ask_proposal<S>(self: Pin<&Self>, spawn: S) -> Result<(), SessionError>
    where
        S: Spawn + Clone + Send + Sync + 'static,
    {
        // TODO: proposal
        let proposals = self.as_ref().construct_bridge_proposals(spawn).await;
        let serial = self.remote_serial.fetch_add(1, Ordering::Relaxed);
        let message = Message::Client(ClientMessage {
            serial,
            session: self.session_id.clone(),
            variant: Redact(Pomerium::encode_with_tag(
                &*self.outbound_guard,
                ClientMessageVariant::BridgeNegotiate(BridgeNegotiationMessage::AskProposal(
                    proposals,
                )),
                &(self.session_id.clone(), serial),
            )),
        });
        self.send_master_message(message).await
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
        trace!("{:?}: notify peer the serial", self.role);
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
        if diff > Wrapping(1 << 63) {
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

    async fn process_stream<T: 'static + Send + Future<Output = ()>>(
        self: Pin<Arc<Self>>,
        input: Receiver<Vec<u8>>,
        error_reports: Receiver<(u8, u64, HashSet<u8>)>,
        master_messages: Receiver<Message<G>>,
        progress: Sender<()>,
        bridges_out_tx: Sender<BridgeMessage>,
        bridges_out_rx: Receiver<BridgeMessage>,
        bridges_in_tx: Sender<(BridgeId, BridgeMessage)>,
        bridges_in_rx: Receiver<(BridgeId, BridgeMessage)>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
        spawn: impl Spawn + Clone + Send + Sync + 'static,
    ) -> Result<(), SessionError> {
        let mut error_reports = spawn
            .spawn({
                let this = Pin::clone(&self);
                let progress = progress.clone();
                async move {
                    this.as_ref()
                        .handle_error_reports(error_reports, progress)
                        .await
                }
            })
            .boxed()
            .fuse();
        let mut input = spawn
            .spawn({
                let this = Pin::clone(&self);
                async move {
                    info!("input start");
                    this.as_ref().handle_input(input).await.unwrap(); // TODO: don't panic
                    Ok(())
                }
            })
            .boxed()
            .fuse();
        let mut poll_bridges_out = spawn
            .spawn({
                let this = Pin::clone(&self);
                async move { this.as_ref().handle_bridges_out(bridges_out_rx).await }
            })
            .boxed()
            .fuse();
        let mut poll_bridges_in = spawn
            .spawn({
                let this = Pin::clone(&self);
                let timeout_generator = timeout_generator.clone();
                async move {
                    this.as_ref()
                        .handle_bridges_in(bridges_in_rx, timeout_generator)
                        .await
                }
            })
            .boxed()
            .fuse();
        let mut poll_master_messages = spawn
            .spawn({
                let this = Pin::clone(&self);
                let progress = progress.clone();
                let timeout_generator = timeout_generator.clone();
                let spawn = spawn.clone();
                let bridges_out_tx = bridges_out_tx.clone();
                async move {
                    this.handle_master_messages(
                        master_messages,
                        bridges_in_tx,
                        bridges_out_tx,
                        progress,
                        timeout_generator,
                        spawn,
                    )
                    .await
                }
            })
            .boxed()
            .fuse();

        let mut poll_streams = spawn
            .spawn({
                let this = Pin::clone(&self);
                let timeout_generator = timeout_generator.clone();
                let spawn = spawn.clone();
                async move {
                    this.as_ref()
                        .handle_streams(bridges_out_tx, timeout_generator, spawn)
                        .await
                }
            })
            .boxed()
            .fuse();
        let mut poll_bridges = spawn
            .spawn({
                let this = Pin::clone(&self);
                let progress = progress.clone();
                let invite_cooldown = Duration::new(10, 0);
                let timeout_generator = timeout_generator.clone();
                async move {
                    this.handle_bridges(invite_cooldown, progress, timeout_generator)
                        .await
                }
            })
            .boxed()
            .fuse();
        let mut poll_bridge_drivers = spawn
            .spawn({
                let this = Pin::clone(&self);
                async move { this.as_ref().handle_bridge_drivers(timeout_generator).await }
            })
            .boxed()
            .fuse();
        select! {
            result = error_reports => match result {
                Ok(Err(e)) => {
                    error!("{:?}: error_reports: {:?}", self.role, e);
                    Ok(())
                },
                Err(e) => {
                    error!("{:?}: error_reports: {:?}", self.role, e);
                    Ok(())
                },
                _ => Ok(()),
            },
            _ = poll_bridges_in => Ok(()),
            _ = poll_bridges_out => Ok(()),
            _ = poll_master_messages => Ok(()),
            _ = poll_bridge_drivers => Ok(()),
            r = poll_streams => match r {
                Ok(Err(e)) => {
                    Err(e)
                }
                Err(e) => {
                    error!("{:?}: poll_streams: {:?}", self.role, e);
                    Ok(())
                }
                _ => Ok(()),
            },
            r = poll_bridges => match r {
                Ok(Err(e)) => {
                    Err(e)
                }
                Err(e) => {
                    error!("{:?}: poll_streams: {:?}", self.role, e);
                    Ok(())
                }
                _ => Ok(()),
            },
            result = input => match result {
                Ok(Err(e)) => {
                    error!("{:?}: input: {:?}", self.role, e);
                    Err(e)
                },
                Err(e) => {
                    error!("{:?}: input: {:?}", self.role, e);
                    Ok(())
                }
                _ => Ok(()),
            }
        }
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
                .map_err(|e| SessionError::Bridge(Box::new(e.compat()), <_>::default())),
            BridgeType::Unix(params) => grpc::UnixBridge
                .build(id, params, half, spawn)
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
            .map_err(|e| {
                trace!("decode error: {}", Backtrace::new());
                Box::new(err_msg(format!("decode: {:?}", e)).compat())
            })?;
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
        let tag = tag.into_bytes();
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
                trace!("decode_with_tag error: {}", Backtrace::new());
                Box::new(err_msg(format!("decode: {:?}", e)).compat())
            })?;
        let payload: <P as ProstMessageMapping>::MapTo = Self::decode_message(buf)?;
        Ok(payload.try_into()?)
    }
}
