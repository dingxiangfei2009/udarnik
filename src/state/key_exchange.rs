use super::*;

use bitvec::prelude::*;
use rand::rngs::OsRng;

pub async fn key_exchange_anke<R, H, G, S, MsgStream, MsgSink, MsgStreamErr>(
    ident: &KeyExchangeAnkeIdentity<R, H>,
    message_stream: MsgStream,
    message_sink: MsgSink,
    seeder: S,
    params: Params,
) -> Result<SessionBootstrap, KeyExchangeError>
where
    R: RngCore + CryptoRng + SeedableRng,
    H: Digest,
    G: 'static + Debug + Guard<Params, ()> + for<'a> From<&'a [u8]>,
    G::Error: Debug,
    MsgStream: Stream<Item = Result<Message<G>, MsgStreamErr>> + Unpin,
    MsgSink: Sink<Message<G>> + Unpin,
    MsgStreamErr: 'static + StdError + Send + Sync,
    MsgSink::Error: 'static + StdError + Send + Sync,
    S: Fn(&[u8]) -> R::Seed,
{
    match ident {
        KeyExchangeAnkeIdentity::RLWE(ident) => {
            key_exchange_rlwe_anke(ident, message_stream, message_sink, seeder, params).await
        }
        KeyExchangeAnkeIdentity::McEliece(ident) => {
            key_exchange_mceliece_anke(ident, message_stream, message_sink, params).await
        }
    }
}

async fn key_exchange_mceliece_anke<H, G, MsgStream, MsgSink, MsgStreamErr>(
    ident: &McElieceAnkeIdentity<H>,
    message_stream: MsgStream,
    message_sink: MsgSink,
    params: Params,
) -> Result<SessionBootstrap, KeyExchangeError>
where
    H: Digest,
    G: 'static + Debug + Guard<Params, ()> + for<'a> From<&'a [u8]>,
    G::Error: Debug,
    MsgStream: Stream<Item = Result<Message<G>, MsgStreamErr>> + Unpin,
    MsgSink: Sink<Message<G>> + Unpin,
    MsgStreamErr: 'static + StdError + Send + Sync,
    MsgSink::Error: 'static + StdError + Send + Sync,
{
    let mut message_stream =
        message_stream.map_err(|e| KeyExchangeError::Message(Box::new(e), <_>::default()));
    let mut message_sink =
        message_sink.sink_map_err(|e| KeyExchangeError::Message(Box::new(e), <_>::default()));

    let (
        anke_session_key,
        McElieceCiphertext {
            c_0: c0, c_1: c1, ..
        },
    ) = ident.boris_pub.encapsulate::<H, _>(&mut OsRng);
    message_sink
        .send(Message::KeyExchange(KeyExchangeMessage::McEliece(
            McElieceKeyExchange::Anke {
                anke_identity: ident.anke_identity.clone(),
                boris_identity: ident.boris_identity.clone(),
                c0,
                c1,
            },
        )))
        .await?;
    let boris_session_key = match message_stream
        .next()
        .await
        .ok_or_else(|| KeyExchangeError::Terminated(<_>::default()))??
    {
        Message::KeyExchange(KeyExchangeMessage::McEliece(McElieceKeyExchange::Boris {
            c0,
            c1,
        })) => {
            let ctxt = <McElieceCiphertext<H>>::new(c0, c1);
            ident.anke_pri.decapsulate(ctxt)
        }
        _ => return Err(KeyExchangeError::UnknownMessage(<_>::default())),
    };
    let mut shared_key = vec![0; std::cmp::max(anke_session_key.len(), boris_session_key.len())];
    for i in 0..anke_session_key.len() {
        shared_key[i] ^= anke_session_key[i];
    }
    for i in 0..boris_session_key.len() {
        shared_key[i] ^= boris_session_key[i];
    }
    let outbound_guard = G::from(&shared_key);
    let message = Message::Params(Pomerium::encode(&outbound_guard, params.clone()));
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
        params,
        session_key: shared_key,
        session_id,
    })
}

async fn key_exchange_rlwe_anke<R, G, MsgStream, MsgSink, MsgStreamErr>(
    ident: &RLWEAnkeIdentity<R>,
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
    MsgStreamErr: 'static + StdError + Send + Sync,
    MsgSink::Error: 'static + StdError + Send + Sync,
{
    let mut message_stream =
        message_stream.map_err(|e| KeyExchangeError::Message(Box::new(e), <_>::default()));
    let mut message_sink =
        message_sink.sink_map_err(|e| KeyExchangeError::Message(Box::new(e), <_>::default()));
    let (anke_session_part, anke_random) =
        SessionKeyPart::generate(&ident.session_key_part_sampler, &ident.init);
    message_sink
        .send(Message::KeyExchange(KeyExchangeMessage::RLWE(
            RLWEKeyExchange::AnkePart {
                part: anke_session_part.clone().into(),
                anke_identity: ident.anke_identity.to_string(),
                boris_identity: ident.boris_identity.to_string(),
                init_identity: ident.init_identity.to_string(),
            },
        )))
        .await?;
    info!("anke: anke session part");
    let shared_key = match message_stream
        .next()
        .await
        .ok_or_else(|| KeyExchangeError::Terminated(<_>::default()))??
    {
        Message::KeyExchange(KeyExchangeMessage::RLWE(RLWEKeyExchange::BorisPart {
            part: boris_session_part,
            reconciliator,
        })) => {
            info!("anke: boris session part");
            let (anke_part_mix, _, _) = SessionKeyPartMix::<Anke>::generate::<R, _, _>(
                seeder,
                &ident.anke_session_key_part_mix_sampler,
                AnkePublic(&ident.anke_data, &ident.anke_pub),
                BorisPublic(&ident.boris_data, &ident.boris_pub),
                AnkeSessionKeyPart(&anke_session_part),
                BorisSessionKeyPart(&boris_session_part),
                AnkeIdentity(&ident.anke_pri),
                AnkeSessionKeyPartR(&anke_random),
            );
            let shared_key = anke_part_mix.reconciliate(&reconciliator);
            let mut v = BitVec::<Lsb0, u8>::new();
            v.extend(shared_key.iter().copied());
            v.into_vec()
        }
        _ => return Err(KeyExchangeError::UnknownMessage(<_>::default())),
    };
    let outbound_guard = G::from(&shared_key);
    let message = Message::Params(Pomerium::encode(&outbound_guard, params.clone()));
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
        params,
        session_key: shared_key,
        session_id,
    })
}

pub async fn key_exchange_boris<R, H, G, S, MsgStream, MsgSink, MsgStreamErr, Ident>(
    ident: Ident,
    message_stream: MsgStream,
    message_sink: MsgSink,
    seeder: S,
    session_id: SessionId,
) -> Result<SessionBootstrap, KeyExchangeError>
where
    R: RngCore + CryptoRng + SeedableRng,
    H: Digest,
    G: 'static + Debug + Guard<Params, ()> + for<'a> From<&'a [u8]>,
    G::Error: Debug,
    MsgStream: Stream<Item = Result<Message<G>, MsgStreamErr>> + Unpin,
    MsgSink: Sink<Message<G>> + Unpin,
    MsgStreamErr: 'static + Send + Sync,
    GenericError: From<MsgSink::Error> + From<MsgStreamErr>,
    S: Fn(&[u8]) -> R::Seed,
    Ident: AsRef<KeyExchangeBorisIdentity<R, H>>,
{
    let ident = ident.as_ref();
    let mut message_stream = message_stream
        .map_err(|e| KeyExchangeError::Message(e.into(), <_>::default()))
        .peekable();
    let message_sink =
        message_sink.sink_map_err(|e| KeyExchangeError::Message(e.into(), <_>::default()));
    match Pin::new(&mut message_stream)
        .peek()
        .await
        .ok_or_else(|| KeyExchangeError::Terminated(<_>::default()))?
    {
        Ok(Message::KeyExchange(KeyExchangeMessage::RLWE(_))) => {
            key_exchange_rlwe_boris(
                &ident.rlwe,
                message_stream,
                message_sink,
                seeder,
                session_id,
            )
            .await
        }
        Ok(Message::KeyExchange(KeyExchangeMessage::McEliece(_))) => {
            key_exchange_mceliece_boris(&ident.mc, message_stream, message_sink, session_id).await
        }
        _ => Err(KeyExchangeError::UnknownMessage(<_>::default())),
    }
}

async fn key_exchange_mceliece_boris<H, G, MsgStream, MsgSink>(
    ident: &McElieceBorisIdentity<H>,
    mut message_stream: MsgStream,
    mut message_sink: MsgSink,
    session_id: SessionId,
) -> Result<SessionBootstrap, KeyExchangeError>
where
    H: Digest,
    G: 'static + Debug + Guard<Params, ()> + for<'a> From<&'a [u8]>,
    G::Error: Debug,
    MsgStream: Stream<Item = Result<Message<G>, KeyExchangeError>> + Unpin,
    MsgSink: Sink<Message<G>, Error = KeyExchangeError> + Unpin,
{
    let (anke_session_key, anke_pub) = match message_stream
        .next()
        .await
        .ok_or_else(|| KeyExchangeError::Terminated(<_>::default()))??
    {
        Message::KeyExchange(KeyExchangeMessage::McEliece(McElieceKeyExchange::Anke {
            anke_identity,
            boris_identity,
            c0,
            c1,
        })) => {
            let anke_identity: Identity = anke_identity.into();
            let boris_identity: Identity = boris_identity.into();
            let anke_pub = ident
                .allowed_identities
                .get(&anke_identity)
                .ok_or_else(|| KeyExchangeError::Terminated(<_>::default()))?;
            let boris_pri = ident
                .identities
                .get(&boris_identity)
                .ok_or_else(|| KeyExchangeError::Terminated(<_>::default()))?;
            let ctxt = <McElieceCiphertext<H>>::new(c0, c1);
            let session_key = boris_pri.decapsulate(ctxt);
            (session_key, anke_pub)
        }
        _ => return Err(KeyExchangeError::UnknownMessage(<_>::default())),
    };
    let (
        boris_session_key,
        McElieceCiphertext {
            c_0: c0, c_1: c1, ..
        },
    ) = anke_pub.encapsulate::<H, _>(&mut OsRng);
    message_sink
        .send(Message::KeyExchange(KeyExchangeMessage::McEliece(
            McElieceKeyExchange::Boris { c0, c1 },
        )))
        .await?;
    let mut shared_key = vec![0; std::cmp::max(anke_session_key.len(), boris_session_key.len())];
    for i in 0..anke_session_key.len() {
        shared_key[i] ^= anke_session_key[i];
    }
    for i in 0..boris_session_key.len() {
        shared_key[i] ^= boris_session_key[i];
    }
    let inbound_guard = G::from(&shared_key);
    let params = match message_stream
        .next()
        .await
        .ok_or_else(|| KeyExchangeError::Terminated(<_>::default()))??
    {
        Message::Params(pomerium) => pomerium.decode(&inbound_guard).map_err(|e| {
            error!("key_exchange: params: {:?}", e);
            KeyExchangeError::NoParams
        })?,
        _ => return Err(KeyExchangeError::UnknownMessage(<_>::default())),
    };
    info!("boris: new session: {}", session_id);
    message_sink
        .send(Message::Session(session_id.clone()))
        .await?;
    info!("boris: session {}: key exchange finished", session_id);
    Ok(SessionBootstrap {
        role: KeyExchangeRole::Boris,
        params,
        session_key: shared_key,
        session_id,
    })
}

async fn key_exchange_rlwe_boris<R, G, MsgStream, MsgSink>(
    ident: &RLWEBorisIdentity<R>,
    mut message_stream: MsgStream,
    mut message_sink: MsgSink,
    seeder: impl Fn(&[u8]) -> R::Seed,
    session_id: SessionId,
) -> Result<SessionBootstrap, KeyExchangeError>
where
    R: RngCore + CryptoRng + SeedableRng,
    G: 'static + Debug + Guard<Params, ()> + for<'a> From<&'a [u8]>,
    G::Error: Debug,
    MsgStream: Stream<Item = Result<Message<G>, KeyExchangeError>> + Unpin,
    MsgSink: Sink<Message<G>, Error = KeyExchangeError> + Unpin,
{
    let (anke_pub, init, boris_key, anke_session_part) = match message_stream
        .next()
        .await
        .ok_or_else(|| KeyExchangeError::Terminated(<_>::default()))??
    {
        Message::KeyExchange(KeyExchangeMessage::RLWE(RLWEKeyExchange::AnkePart {
            part,
            anke_identity,
            boris_identity,
            init_identity,
        })) => {
            info!(
                "boris: anke offer: init={:?}, ident={:?}",
                init_identity, anke_identity,
            );
            let init_identity = init_identity.into();
            let anke_pub = ident
                .allowed_identities
                .get(&init_identity)
                .and_then(|db| db.get(&anke_identity.into()))
                .ok_or_else(|| KeyExchangeError::Terminated(<_>::default()))?;
            let init = ident
                .init_db
                .get(&init_identity)
                .ok_or_else(|| KeyExchangeError::Terminated(<_>::default()))?;
            let boris_key = ident
                .identity_db
                .get(&init_identity)
                .and_then(|db| db.get(&boris_identity.into()))
                .ok_or_else(|| KeyExchangeError::Terminated(<_>::default()))?;
            (anke_pub, init, boris_key, part)
        }
        _ => return Err(KeyExchangeError::UnknownMessage(<_>::default())),
    };
    let boris_pub = boris_key.public_key(&init);
    let (boris_session_part, boris_random) =
        SessionKeyPart::generate(&ident.session_key_part_sampler, &init);
    let (boris_part_mix, _, _) = SessionKeyPartMix::<Boris>::generate::<R, _, _>(
        seeder,
        &ident.boris_session_key_part_mix_sampler,
        AnkePublic(&ident.anke_data, &anke_pub),
        BorisPublic(&ident.boris_data, &boris_pub),
        AnkeSessionKeyPart(&anke_session_part),
        BorisSessionKeyPart(&boris_session_part),
        BorisIdentity(&boris_key),
        BorisSessionKeyPartR(&boris_random),
    );
    let reconciliator = boris_part_mix.reconciliator();
    let shared_key = boris_part_mix.reconciliate(&reconciliator);
    let mut v = BitVec::<Lsb0, u8>::new();
    v.extend(shared_key.iter().copied());
    let shared_key = v.into_vec();

    let inbound_guard = G::from(&shared_key);
    message_sink
        .send(Message::KeyExchange(KeyExchangeMessage::RLWE(
            RLWEKeyExchange::BorisPart {
                part: boris_session_part,
                reconciliator,
            },
        )))
        .await?;
    info!("boris: boris session part");
    let params = match message_stream
        .next()
        .await
        .ok_or_else(|| KeyExchangeError::Terminated(<_>::default()))??
    {
        Message::Params(pomerium) => pomerium.decode(&inbound_guard).map_err(|e| {
            error!("key_exchange: params: {:?}", e);
            KeyExchangeError::NoParams
        })?,
        _ => return Err(KeyExchangeError::UnknownMessage(<_>::default())),
    };
    info!("boris: new session: {}", session_id);
    message_sink
        .send(Message::Session(session_id.clone()))
        .await?;
    info!("boris: session {}: key exchange finished", session_id);
    Ok(SessionBootstrap {
        role: KeyExchangeRole::Boris,
        params,
        session_key: shared_key,
        session_id,
    })
}
