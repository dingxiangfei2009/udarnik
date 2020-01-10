use super::*;

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
                    if let Some(pub_key) = allowed_identities
                        .get(&init_ident)
                        .and_then(|db| db.get(&ident))
                    {
                        boris_pub = Some((ident.clone(), pub_key.clone()));
                        message_sink
                            .send(Message::KeyExchange(KeyExchangeMessage::Accept(
                                ident,
                                init_ident_,
                            )))
                            .await?;
                    } else {
                        message_sink
                            .send(Message::KeyExchange(KeyExchangeMessage::Reject(
                                ident,
                                init_ident_,
                            )))
                            .await?;
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
    info!(
        "anke: init={:?} anke={:?} boris={:?}",
        init_ident, anke_ident, boris_ident
    );
    let (anke_session_part, anke_random) =
        SessionKeyPart::generate(&session_key_part_sampler, &init);
    message_sink
        .send(Message::KeyExchange(KeyExchangeMessage::AnkePart(
            anke_session_part.clone().into(),
        )))
        .await?;
    info!("anke: anke session part");
    let shared_key = match message_stream.next().await {
        None => return Err(KeyExchangeError::Terminated(<_>::default())),
        Some(m) => match m? {
            Message::KeyExchange(KeyExchangeMessage::BorisPart(
                Redact(boris_session_part),
                Redact(reconciliator),
            )) => {
                info!("anke: boris session part");
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
                    info!(
                        "boris: anke offer: init={:?}, ident={:?}",
                        init_ident_, ident
                    );
                    if let Some(pub_key) = allowed_identities
                        .get(&init_ident_)
                        .and_then(|db| db.get(&ident))
                    {
                        init_ident = Some(init_ident_.clone());
                        anke_pub = Some((ident.clone(), pub_key.clone()));
                        message_sink
                            .send(Message::KeyExchange(KeyExchangeMessage::Accept(
                                ident,
                                init_ident_,
                            )))
                            .await?;
                    } else {
                        message_sink
                            .send(Message::KeyExchange(KeyExchangeMessage::Reject(
                                ident,
                                init_ident_,
                            )))
                            .await?;
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
    info!(
        "boris: choose anke: init={:?}, ident={:?}",
        init_ident, anke_ident
    );
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
    info!("boris: anke accept: ident={:?}", boris_ident);
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
    info!("boris: anke session part");
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
    info!("boris: boris session part");
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
    info!("boris: new session: {}", session_id);
    message_sink
        .send(Message::Session(session_id.clone()))
        .await?;
    info!("boris: session {}: key exchange finished", session_id);
    Ok(SessionBootstrap {
        role: KeyExchangeRole::Boris,
        anke_identity: anke_ident,
        boris_identity: boris_ident,
        params,
        session_key: shared_key,
        session_id,
        init_identity: init_ident,
    })
}
