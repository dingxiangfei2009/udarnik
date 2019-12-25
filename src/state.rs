use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    marker::PhantomData,
    sync::atomic::AtomicU64,
};

use failure::{Backtrace, Error as TopError, Fail};
use futures::prelude::*;
use rand::{CryptoRng, RngCore, SeedableRng};
use sss::lattice::{
    Anke, AnkeIdentity, AnkePublic, AnkeSessionKeyPart, AnkeSessionKeyPartR, Boris, BorisIdentity,
    BorisPublic, BorisSessionKeyPart, BorisSessionKeyPartR, Init, PrivateKey, PublicKey,
    Reconciliator, SessionKeyPart, SessionKeyPartMix, SessionKeyPartMixParallelSampler,
    SessionKeyPartParallelSampler,
};

use crate::Redact;

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
    pub fn decode(&self, guard: &G) -> Result<P, G::Error> {
        guard.decode(&self.data)
    }
}

#[derive(Debug)]
pub enum BridgeMessage {
    Ask(Vec<BridgeAsk>),
    Retract(Vec<BridgeRetract>),
    ProposeAsk,
}

#[derive(Debug)]
pub struct BridgeAsk {}

#[derive(Debug)]
pub struct BridgeRetract {}

#[derive(Debug)]
pub enum Message<G: Debug> {
    KeyExchange(KeyExchangeMessage),
    Pomerium(Pomerium<G, ClientMessage>),
}

#[derive(Debug)]
pub enum ClientMessage {
    Bridge(BridgeMessage),
    Params(ParamsMessage),
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

#[derive(Hash, Clone, Debug, Display, Deref)]
pub struct BridgeId(String);

pub struct Session<G> {
    guard: G,
    receive_queue: crate::protocol::ReceiveQueue,
    send: Counter,
    receive: Counter,
    bridges: HashMap<BridgeId, Bridge>,
}

pub struct Counter {
    counters: HashMap<BridgeId, AtomicU64>,
}

pub struct Bridge {}

// pub async fn negotiate_bridges<G, MsgStream, MsgSink, MsgStreamErr>(
//     session: &Session<G>,
//     message_stream: MsgStream,
//     message_sink: MsgSink,
// ) -> Result<(), Error<G>>
// where
//     G: 'static + Debug,
//     MsgStream: Stream<Item = Result<Message<G>, MsgStreamErr>> + Unpin,
//     MsgSink: Sink<Message<G>> + Unpin,
//     MsgStreamErr: 'static + From<MsgSink::Error> + Send + Sync,
//     TopError: From<MsgSink::Error> + From<MsgStreamErr>,
// {
//     let mut message_stream = message_stream.map_err(|e| Error::Message(e.into(), <_>::default()));
//     let mut message_sink = message_sink.sink_map_err(|e| Error::Message(e.into(), <_>::default()));
//     todo!()
// }
