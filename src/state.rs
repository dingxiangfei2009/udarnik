use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Debug,
    marker::PhantomData,
    ops::Deref,
    pin::Pin,
    sync::atomic::AtomicU64,
    task::{Context, Poll},
    time::Duration,
};

use async_std::sync::{Arc, Mutex, RwLock};
use crossbeam::queue::ArrayQueue;
use dyn_clone::{clone_box, DynClone};
use failure::{Backtrace, Error as TopError, Fail};
use futures::{
    channel::mpsc::{channel, unbounded, Receiver, Sender},
    future::{BoxFuture, FusedFuture, FutureExt, Shared},
    join,
    prelude::*,
    select,
    stream::{repeat, BoxStream},
};
use log::error;
use rand::{rngs::StdRng, seq::IteratorRandom, CryptoRng, RngCore, SeedableRng};
use sha3::Digest;
use sss::lattice::{
    Anke, AnkeIdentity, AnkePublic, AnkeSessionKeyPart, AnkeSessionKeyPartR, Boris, BorisIdentity,
    BorisPublic, BorisSessionKeyPart, BorisSessionKeyPartR, Init, PrivateKey, PublicKey,
    Reconciliator, SessionKeyPart, SessionKeyPartMix, SessionKeyPartMixParallelSampler,
    SessionKeyPartParallelSampler,
};

use crate::{
    protocol::{
        QuorumError, RSCodec, RawShard, RawShardId, ReceiveError, ReceiveQueue, RemoteRecvError,
        SendError, SendQueue, ShardState, TaskProgressNotifier, TaskProgressNotifierSink,
    },
    GenericError, Redact,
};

#[derive(Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Debug, Deref)]
pub struct InitIdentity(String);
#[derive(Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Debug, Deref)]
pub struct Identity(String);

pub trait Guard<P> {
    type Error;
    fn encode(&self, payload: P) -> Vec<u8>;
    fn decode(&self, data: &[u8]) -> Result<P, Self::Error>;
}

#[derive(Debug)]
pub struct Pomerium<Guard, Payload> {
    data: Vec<u8>,
    _p: PhantomData<fn() -> (Guard, Payload)>,
}

impl<G, P> Pomerium<G, P>
where
    G: Guard<P>,
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
}

#[derive(Debug)]
pub enum BridgeNegotiationMessage {
    Ask(Vec<BridgeAsk>),
    Retract(Vec<BridgeRetract>),
    ProposeAsk,
    AskProposal(Vec<BridgeAsk>),
}

#[derive(Clone, Debug)]
pub struct BridgeAsk {
    r#type: BridgeType,
    id: BridgeId,
}

#[derive(Clone, Debug)]
pub enum BridgeType {}

#[derive(Clone, Debug)]
pub struct BridgeRetract {
    id: BridgeId,
}

#[derive(Debug)]
pub enum Message<G> {
    KeyExchange(KeyExchangeMessage),
    Pomerium(Redact<Pomerium<G, ClientMessage>>),
}

#[derive(Debug)]
pub enum ClientMessage {
    BridgeNegotiate(BridgeNegotiationMessage),
    Params(ParamsMessage),
    Bridge(Redact<BridgeMessage>),
    Stream(StreamRequest),
    Ok,
}

#[derive(Debug)]
pub struct ParamsMessage {
    correction: u8,
    entropy: u8,
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
pub enum Error<G: 'static + Debug> {
    #[fail(display = "unknown message received")]
    UnknownMessage(Message<G>, Backtrace),
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
}

pub enum KeyExchangeRole {
    Anke,
    Boris,
}

pub struct KeyExchange<R> {
    role: KeyExchangeRole,
    retries: Option<u32>,
    init_db: BTreeMap<InitIdentity, Init>,
    identity_db: BTreeMap<InitIdentity, BTreeMap<Identity, PrivateKey>>,
    allowed_identities: HashMap<InitIdentity, HashMap<Identity, PublicKey>>,
    identity_sequence: Vec<(InitIdentity, Identity)>,
    session_key_part_sampler: SessionKeyPartParallelSampler<R>,
    anke_session_key_part_mix_sampler: SessionKeyPartMixParallelSampler<R, Anke>,
    boris_session_key_part_mix_sampler: SessionKeyPartMixParallelSampler<R, Boris>,
    anke_data: Vec<u8>,
    boris_data: Vec<u8>,
}

pub async fn key_exchange<R, G, MsgStream, MsgSink, MsgStreamErr>(
    kex: KeyExchange<R>,
    message_stream: MsgStream,
    message_sink: MsgSink,
    seeder: impl Fn(&[u8]) -> R::Seed,
) -> Result<(Identity, Vec<u8>), Error<G>>
where
    R: RngCore + CryptoRng + SeedableRng,
    G: 'static + Debug,
    MsgStream: Stream<Item = Result<Message<G>, MsgStreamErr>> + Unpin,
    MsgSink: Sink<Message<G>> + Unpin,
    MsgStreamErr: 'static + From<MsgSink::Error> + Send + Sync,
    TopError: From<MsgSink::Error> + From<MsgStreamErr>,
{
    use bitvec::prelude::*;
    let mut message_stream = message_stream.map_err(|e| Error::Message(e.into(), <_>::default()));
    let mut message_sink = message_sink.sink_map_err(|e| Error::Message(e.into(), <_>::default()));
    let KeyExchange {
        role,
        mut retries,
        init_db,
        identity_db,
        allowed_identities,
        identity_sequence,
        session_key_part_sampler,
        anke_session_key_part_mix_sampler,
        boris_session_key_part_mix_sampler,
        anke_data,
        boris_data,
    } = kex;
    match role {
        KeyExchangeRole::Anke => {
            // Anke initiate negotiation
            let mut key = None;
            for (init_ident, ident) in identity_sequence {
                let key_ = if let Some(key) =
                    identity_db.get(&init_ident).and_then(|ids| ids.get(&ident))
                {
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
                    None => return Err(Error::Terminated(<_>::default())),
                    Some(m) => match m? {
                        Message::KeyExchange(KeyExchangeMessage::Accept(ident_, init_ident_))
                            if ident_ == ident && init_ident_ == init_ident =>
                        {
                            key = Some((init_ident, key_));
                            break;
                        }
                        Message::KeyExchange(KeyExchangeMessage::Reject(ident_, init_ident_))
                            if ident_ == ident && init_ident_ == init_ident => {}
                        m => return Err(Error::UnknownMessage(m, <_>::default())),
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
            let (init_ident, anke_key) = key.ok_or_else(|| Error::Authentication)?;
            let init = init_db
                .get(&init_ident)
                .ok_or_else(|| Error::UnknownInit(<_>::default()))?
                .clone();
            let anke_pub = anke_key.public_key(&init);
            // expect Boris to negotiate keys
            let mut boris_pub = None;
            while boris_pub.is_none() {
                match message_stream.next().await {
                    None => return Err(Error::Terminated(<_>::default())),
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
                        m => return Err(Error::UnknownMessage(m, <_>::default())),
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
            let (boris_ident, boris_pub) = boris_pub.ok_or_else(|| Error::Authentication)?;
            let (anke_session_part, anke_random) =
                SessionKeyPart::generate(&session_key_part_sampler, &init);
            message_sink
                .send(Message::KeyExchange(KeyExchangeMessage::AnkePart(
                    anke_session_part.clone().into(),
                )))
                .await?;
            match message_stream.next().await {
                None => return Err(Error::Terminated(<_>::default())),
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
                        Ok((boris_ident, v.into_vec()))
                    }
                    m => return Err(Error::UnknownMessage(m, <_>::default())),
                },
            }
        }
        KeyExchangeRole::Boris => {
            // Anke offers keys in negotiation
            let mut anke_pub = None;
            let mut init_ident = None;
            while anke_pub.is_none() {
                match message_stream.next().await {
                    None => return Err(Error::Terminated(<_>::default())),
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
                        m => return Err(Error::UnknownMessage(m, <_>::default())),
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
            let (anke_ident, anke_pub) = anke_pub.ok_or_else(|| Error::Authentication)?;
            let init_ident = init_ident.unwrap();
            let init = init_db.get(&init_ident).unwrap();
            // Boris negotiate keys
            let mut key = None;
            for (init_ident_, ident) in identity_sequence {
                if init_ident_ != init_ident {
                    continue;
                }
                let key_ = if let Some(key) =
                    identity_db.get(&init_ident).and_then(|ids| ids.get(&ident))
                {
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
                    None => return Err(Error::Terminated(<_>::default())),
                    Some(m) => match m? {
                        Message::KeyExchange(KeyExchangeMessage::Accept(ident_, init_ident_))
                            if ident_ == ident && init_ident_ == init_ident =>
                        {
                            key = Some(key_);
                            break;
                        }
                        Message::KeyExchange(KeyExchangeMessage::Reject(ident_, init_ident_))
                            if ident_ == ident && init_ident_ == init_ident => {}
                        m => return Err(Error::UnknownMessage(m, <_>::default())),
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
            let boris_key = key.ok_or_else(|| Error::Authentication)?;
            let boris_pub = boris_key.public_key(&init);
            let (boris_session_part, boris_random) =
                SessionKeyPart::generate(&session_key_part_sampler, &init);
            let anke_session_part = match message_stream.next().await {
                None => return Err(Error::Terminated(<_>::default())),
                Some(m) => match m? {
                    Message::KeyExchange(KeyExchangeMessage::AnkePart(Redact(part))) => part,
                    m => return Err(Error::UnknownMessage(m, <_>::default())),
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
            message_sink
                .send(Message::KeyExchange(KeyExchangeMessage::BorisPart(
                    Redact(boris_session_part),
                    Redact(reconciliator),
                )))
                .await?;
            Ok((anke_ident, v.into_vec()))
        }
    }
}

#[derive(Hash, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BridgeId {
    up: String,
    down: String,
}

pub struct Session<G> {
    inbound_guard: Arc<G>,
    outbound_guard: Arc<G>,
    send: RwLock<Counter>,
    receive: RwLock<Counter>,
    session_key: Vec<u8>,
    codec: Arc<RSCodec>,
    bridges_out_tx: Sender<BridgeMessage>,
    output: Sender<Vec<u8>>,
    input: ArrayQueue<Vec<u8>>,
    receive_timeout: Duration,
    send_cooldown: Duration,
    error_reports: Sender<(u64, HashSet<u8>)>,
    master_messages: Mutex<Box<dyn Stream<Item = Message<G>> + Unpin>>,
    master_sink: Box<dyn ClonableSink<Message<G>, GenericError>>,
    bridge_builder: BridgeBuilder<G>,
}

pub struct SessionStream {
    send_queue: Arc<SendQueue>,
    receive_queue: Arc<ReceiveQueue>,
    shard_state: ShardState,
    task_notifiers: Arc<RwLock<BTreeMap<u64, TaskProgressNotifier>>>,
    bridges_in_tx: Box<dyn Sink<BridgeMessage, Error = SessionError> + Send + Unpin>,
    input_tx: Sender<Vec<u8>>,
}

#[derive(Debug)]
pub enum StreamRequest {
    Reset { stream: u8, window: usize },
}

trait ClonableFuture<O>: DynClone + Future<Output = O> {
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

trait ClonableSendableFuture<O>: Send + ClonableFuture<O> {
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

async fn a<O>(x: impl Send + ClonableFuture<O>) {
    let b = Box::pin(x) as Pin<Box<dyn Send + ClonableFuture<O>>>;
    let x = &b;
    let c = Pin::from(<_ as ClonableFuture<O>>::clone_box(&**x));
    b.await;
    c.await;
}

trait ClonableSink<T, E>: DynClone + Sink<T, Error = E> {
    fn clone_box(&self) -> Box<dyn Send + ClonableSink<T, E>>;
    fn clone_pin_box(&self) -> Pin<Box<dyn Send + ClonableSink<T, E>>> {
        ClonableSink::clone_box(self).into()
    }
}

impl<X, T, E> ClonableSink<T, E> for X
where
    X: 'static + Send + Clone + Sink<T, Error = E>,
{
    fn clone_box(&self) -> Box<dyn Send + ClonableSink<T, E>> {
        clone_box(self)
    }
}

impl<G> Session<G>
where
    G: 'static + Guard<ClientMessage, Error = GenericError>,
{
    async fn propose_ask(self: Pin<&Self>) -> Result<(), SessionError> {
        // TODO: proposal
        let message = Message::Pomerium(Redact(Pomerium::encode(
            &*self.outbound_guard,
            ClientMessage::BridgeNegotiate(BridgeNegotiationMessage::AskProposal(vec![])),
        )));
        ClonableSink::clone_pin_box(&*self.master_sink)
            .send(message)
            .await
            .map_err(|e| SessionError::BrokenPipe(e, <_>::default()))
    }

    async fn apply_proposal(
        self: Pin<&Self>,
        proposals: &[BridgeAsk],
        bridges: &mut HashMap<BridgeId, Bridge<G>>,
    ) -> Vec<BridgeAsk> {
        let mut success = vec![];
        for BridgeAsk { r#type, id } in proposals {
            match self.bridge_builder.build(r#type, id).await {
                Ok(bridge) => {
                    bridges.insert(id.clone(), bridge);
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

    async fn ask_bridge(self: Pin<&Self>, proposals: Vec<BridgeAsk>) -> Result<(), SessionError> {
        let message = Message::Pomerium(Redact(Pomerium::encode(
            &*self.outbound_guard,
            ClientMessage::BridgeNegotiate(BridgeNegotiationMessage::Ask(proposals)),
        )));
        ClonableSink::clone_pin_box(&*self.master_sink)
            .send(message)
            .await
            .map_err(|e| SessionError::BrokenPipe(e, <_>::default()))
    }

    async fn process_stream<Timeout: 'static + Send + Future<Output = ()>>(
        self: Pin<&Self>,
        mut input: Receiver<Vec<u8>>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> Timeout,
    ) -> Result<(), SessionError> {
        let mut stream_polls: RwLock<
            BTreeMap<u8, (SessionStream, Pin<Box<dyn ClonableSendableFuture<()>>>)>,
        > = <_>::default();
        let mut bridges: HashMap<BridgeId, Bridge<G>> = <_>::default();
        loop {
            let all_polls: Vec<_> = stream_polls
                .read()
                .await
                .iter()
                .map(|(stream, (_, polls))| {
                    let stream: u8 = *stream;
                    let polls = ClonableSendableFuture::clone_pin_box(&**polls);
                    polls.map(move |_| stream).boxed()
                })
                .collect();
            let all_polls = if all_polls.is_empty() {
                future::pending().boxed()
            } else {
                future::select_all(all_polls).boxed()
            };
            let mut master_messages = self.master_messages.lock().await;
            select! {
                request = master_messages.next().fuse() =>
                    if let Some(request) = request {
                        match request {
                            Message::Pomerium(Redact(message)) =>
                                match message.decode(&self.inbound_guard) {
                                    Ok(ClientMessage::BridgeNegotiate(message)) =>
                                        match message {
                                            BridgeNegotiationMessage::ProposeAsk => {
                                                self.propose_ask().await?
                                            }
                                            BridgeNegotiationMessage::Ask(proposals) => {
                                                self.apply_proposal(&proposals, &mut bridges).await;
                                            }
                                            BridgeNegotiationMessage::Retract(bridges_) => {
                                                for BridgeRetract { id } in bridges_ {
                                                    bridges.remove(&id);
                                                }
                                            }
                                            BridgeNegotiationMessage::AskProposal(proposals) => {
                                                let asks = self.apply_proposal(&proposals, &mut bridges).await;
                                                self.ask_bridge(asks).await?
                                            }
                                        }
                                    Ok(ClientMessage::Stream(message)) =>
                                        match message {
                                            StreamRequest::Reset { stream, window } => {
                                                let (session_stream, poll) =
                                                    self.new_stream(
                                                        stream,
                                                        window,
                                                        timeout_generator.clone()
                                                    );
                                                stream_polls.write().await.insert(
                                                    stream,
                                                    (session_stream, Box::pin(poll.shared()))
                                                );
                                            }
                                        }
                                    Ok(_) => {}
                                    Err(e) => {
                                        error!("decode error: {}", e);
                                    }
                                },
                            _ => (),
                        }
                    },
                (stream, _, _) = all_polls.fuse() => {
                    stream_polls.write().await.remove(&stream);
                },
                () = if self.input.is_empty() {
                    future::pending().boxed().fuse()
                } else {
                    async {()}.boxed().fuse()
                } =>
                {
                    let input = self.input.pop().expect("non-empty");
                    let task = async {
                        let mut input_tx = loop {
                            if let Some((_, (session_stream, _))) = stream_polls
                                .read()
                                .await
                                .iter()
                                .choose(&mut StdRng::from_entropy())
                            {
                                break session_stream.input_tx.clone()
                            }
                        };
                        input_tx.send(input).await
                    };
                }
            }
        }
    }

    pub fn new_stream<Timeout: 'static + Send + Future<Output = ()>>(
        &self,
        stream: u8,
        window: usize,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> Timeout,
    ) -> (SessionStream, impl 'static + Future<Output = ()> + Send) {
        let (input_tx, input_rx) = channel(window);
        let (task_notifiers_tx, task_notifier_rx) = channel(window);
        let (bridges_in_tx, bridges_in_rx) = unbounded();
        let bridges_in_tx = Box::new(
            bridges_in_tx
                .sink_map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default())),
        )
            as Box<dyn Sink<BridgeMessage, Error = SessionError> + Send + Unpin>;
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
        let task_notifiers = Arc::new(RwLock::new(BTreeMap::<u64, TaskProgressNotifier>::new()));
        let poll_task_notifiers = task_notifier_rx.for_each({
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
            .forward(self.bridges_out_tx.clone())
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
            let mut bridges_out_tx = self.bridges_out_tx.clone();
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
                            let (data, errors) =
                                join!(output.send(data), error_reports.send((serial, errors)));
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
                .forward(self.bridges_out_tx.clone())
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
                shard_state,
                bridges_in_tx,
                task_notifiers,
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
}

pub struct Counter {
    counters: HashMap<BridgeId, AtomicU64>,
}

pub struct Bridge<G> {
    pub tx: Box<dyn Sink<Message<G>, Error = GenericError> + Unpin>,
    pub rx: Box<dyn Stream<Item = Result<Message<G>, GenericError>> + Unpin>,
}

pub struct BridgeBuilder<G> {
    _p: PhantomData<fn() -> G>,
}

impl<G> BridgeBuilder<G> {
    pub async fn build(
        &self,
        r#type: &BridgeType,
        id: &BridgeId,
    ) -> Result<Bridge<G>, SessionError> {
        match r#type {
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
