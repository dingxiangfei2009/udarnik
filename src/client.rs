use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
    fmt::Debug,
    pin::Pin,
    time::Duration,
};

use backtrace::Backtrace as Bt;
use futures::{
    channel::{
        mpsc::{channel, Receiver, Sender},
        oneshot::Receiver as OneshotReceiver,
    },
    pin_mut,
    prelude::*,
    select,
};
use http::Uri;
use log::{error, info, trace};
use rand::{CryptoRng, RngCore, SeedableRng};
use sss::lattice::{
    Init, PrivateKey, PublicKey, SessionKeyPart, SessionKeyPartMix, SigningKey, SIGN_K,
};
use thiserror::Error;
use tonic::{Request, Status};

use crate::{
    protocol::signature_hasher,
    reference_seeder_chacha,
    state::{
        key_exchange_anke, wire, ClientMessageVariant, Guard, Identity, InitIdentity, KeyExchange,
        KeyExchangeError, Message, Params, SafeGuard, Session, SessionError, SessionHandle,
        SessionId, SessionLogOn, WireError,
    },
    utils::Spawn,
    GenericError,
};

pub struct ClientBootstrap {
    pub addr: Uri,
    pub params: Params,
    pub allowed_identities: HashMap<InitIdentity, HashMap<Identity, PublicKey>>,
    pub anke_data: Vec<u8>,
    pub boris_data: Vec<u8>,
    pub identity_db: BTreeMap<InitIdentity, BTreeMap<Identity, PrivateKey>>,
    pub identity_sequence: Vec<(InitIdentity, Identity)>,
    pub init_db: BTreeMap<InitIdentity, Init>,
    pub retries: Option<u32>,
    pub sign_db: BTreeMap<InitIdentity, BTreeMap<Identity, SigningKey>>,
}

#[derive(Error, Debug, From)]
pub enum ClientError {
    #[error("connection reset")]
    Reset(Bt),
    #[error("broken pipe")]
    Pipe(Bt),
    #[error("network: {0}")]
    Net(Status, Bt),
    #[error("wire: {0}")]
    Wire(WireError, Bt),
    #[error("crypto: no init")]
    NoInit,
    #[error("crypto: no signing key")]
    NoSigningKey,
    #[error("session: {0}")]
    Session(SessionError),
    #[error("transport: {0}")]
    Transport(tonic::transport::Error, Bt),
    #[error("key exchange: {0}")]
    KeyExchange(KeyExchangeError),
    #[error("spawn: {0}")]
    Spawn(String),
}

async fn reconnect<G>(
    client: &mut wire::master_client::MasterClient<tonic::transport::channel::Channel>,
    session: &Session<G>,
    init_db: &BTreeMap<InitIdentity, Init>,
    sign_db: &BTreeMap<InitIdentity, BTreeMap<Identity, SigningKey>>,
    h: impl Fn(Vec<u8>) -> Vec<u8>,
) -> Result<
    (
        Sender<Message<G>>,
        Pin<Box<dyn Stream<Item = Result<Message<G>, ClientError>> + Send + Sync + 'static>>,
    ),
    ClientError,
>
where
    G: 'static
        + Send
        + Sync
        + Guard<ClientMessageVariant, (SessionId, u64)>
        + for<'a> From<&'a [u8]>
        + Debug,
    G::Error: Debug,
{
    trace!("client: contacting master");
    let (mut message_sink, master_in) = channel(4096);
    let mut message_stream = Box::pin(
        client
            .client(Request::new(master_in.map(wire::Message::from)))
            .await
            .map_err(|e| ClientError::Net(e, <_>::default()))?
            .into_inner()
            .map_err(|e| ClientError::Net(e, <_>::default()))
            .and_then(|m| async {
                Message::<G>::try_from(m).map_err(|e| ClientError::Wire(e, <_>::default()))
            }),
    )
        as Pin<Box<dyn Stream<Item = Result<Message<G>, ClientError>> + Send + Sync + 'static>>;
    let challenge = if let Message::SessionLogOnChallenge(challenge) = message_stream
        .next()
        .await
        .ok_or_else(|| ClientError::Pipe(<_>::default()))??
    {
        challenge
    } else {
        Err(ClientError::Pipe(<_>::default()))?
    };
    trace!("client: master challenge");
    let Session {
        init_identity,
        anke_identity,
        session_id,
        ..
    } = session;
    let body = SessionLogOn::generate_body(init_identity, anke_identity, session_id, &challenge);
    let init = init_db.get(init_identity).ok_or(ClientError::NoInit)?;
    let signature = if let Some(key) = sign_db
        .get(init_identity)
        .and_then(|db| db.get(anke_identity))
    {
        let mut rng = rand::rngs::OsRng;
        trace!("client: signing challenge");
        key.sign(&mut rng, init, body, SIGN_K, h)
    } else {
        return Err(ClientError::NoSigningKey);
    };
    trace!("client: send signature");
    message_sink
        .send(Message::<G>::SessionLogOn(SessionLogOn {
            init_identity: init_identity.clone(),
            identity: anke_identity.clone(),
            session: session_id.clone(),
            challenge,
            signature,
        }))
        .await
        .map_err(|_| ClientError::Pipe(<_>::default()))?;
    Ok((message_sink, message_stream))
}

async fn client_impl<G, R, S, Sp, TimeGen, Timeout>(
    bootstrap: ClientBootstrap,
    seeder: S,
    input: Receiver<Vec<u8>>,
    output: Sender<Vec<u8>>,
    terminate: OneshotReceiver<()>,
    spawn: Sp,
    timeout_generator: TimeGen,
) -> Result<(), ClientError>
where
    G: 'static + Send + Sync + Guard<Params, ()> + for<'a> From<&'a [u8]> + Debug,
    G::Error: Debug,
    R: 'static + Send + Sync + SeedableRng + RngCore + CryptoRng,
    S: Send + Sync + Clone + Fn(&[u8]) -> R::Seed,
    Sp: Spawn + Clone + Send + Sync + 'static,
    TimeGen: 'static + Clone + Send + Sync + Fn(Duration) -> Timeout,
    Timeout: 'static + Future<Output = ()> + Send + Sync,
{
    #[derive(Error, Debug)]
    #[error("{0}")]
    struct BoxError(#[from] GenericError);

    let ClientBootstrap {
        addr,
        params,
        allowed_identities,
        anke_data,
        boris_data,
        identity_db,
        identity_sequence,
        init_db,
        retries,
        sign_db,
    } = bootstrap;
    let mut client = wire::master_client::MasterClient::connect(addr)
        .await
        .map_err(|e| ClientError::Transport(e, <_>::default()))?;
    let (message_sink, master_in) = channel(4096);
    let message_stream = client
        .key_exchange(Request::new(master_in.map(wire::Message::from)))
        .await
        .map_err(|e| ClientError::Net(e, <_>::default()))?
        .into_inner()
        .map_err(|e| Box::new(e) as GenericError)
        .and_then(|m| async { Message::<G>::try_from(m).map_err(|e| Box::new(e) as GenericError) })
        .map_err(BoxError)
        .boxed();
    let kex = KeyExchange {
        retries,
        init_db: init_db.clone(),
        identity_db,
        allowed_identities,
        identity_sequence,
        session_key_part_sampler: SessionKeyPart::parallel_sampler::<R>(2, 4096),
        anke_session_key_part_mix_sampler: SessionKeyPartMix::parallel_sampler::<R>(2, 4096),
        boris_session_key_part_mix_sampler: SessionKeyPartMix::parallel_sampler::<R>(2, 4096),
        anke_data,
        boris_data,
    };
    let session_bootstrap = key_exchange_anke(kex, message_stream, message_sink, seeder, params)
        .await
        .map_err(ClientError::KeyExchange)?;

    let (master_sink, master_in) = channel(4096);
    let (mut master_out, master_messages) = channel(4096);
    let master_sink = Box::new(master_sink.sink_map_err(|e| Box::new(e) as GenericError));
    let SessionHandle {
        session,
        poll,
        input: session_input,
        output: session_output,
        mut progress,
    } = Session::<SafeGuard>::new(
        session_bootstrap,
        master_messages,
        master_sink,
        timeout_generator.clone(),
        spawn.clone(),
    )?;
    info!("client: session assigned, {}", session.session_id);
    let master_in = crate::utils::Peekable::new(master_in);
    let timeout_generator_ = timeout_generator.clone();
    let master_adapter =
        async move {
            pin_mut!(master_in);
            let timeout_generator = timeout_generator_;
            loop {
                select! {
                    _ = timeout_generator(Duration::new(300, 0)).fuse() =>
                        info!("client: reconnect to master to receive directives"),
                    r = master_in.as_mut().peek().fuse() =>
                        if let None = r {
                            error!("client: master_in: broken pipe");
                            break
                        },
                }
                trace!("client: want to send message to master");
                let (mut client_send, mut client_recv) =
                    match reconnect(&mut client, &session, &init_db, &sign_db, signature_hasher)
                        .await
                    {
                        Ok(p) => p,
                        Err(ClientError::Pipe(e)) => {
                            error!("pipe: {:?}", e);
                            continue;
                        }
                        Err(ClientError::Net(s, e)) => {
                            error!("net: status: {}\n{:?}", s, e);
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                let (progress_tx, mut progress_rx) = channel(4096);
                let mut progress = progress_tx.clone();
                let mut poll_send = async {
                    while let Some(msg) = master_in.as_mut().next().await {
                        client_send
                            .send(msg)
                            .await
                            .map_err(|_| ClientError::Pipe(<_>::default()))?;
                        progress
                            .send(())
                            .await
                            .map_err(|_| ClientError::Pipe(<_>::default()))?;
                    }
                    Ok::<_, ClientError>(())
                }
                .boxed()
                .fuse();
                let mut progress = progress_tx;
                let mut poll_recv = async {
                    while let Some(msg) = client_recv.next().await {
                        master_out
                            .send(msg?)
                            .await
                            .map_err(|_| ClientError::Pipe(<_>::default()))?;
                        progress
                            .send(())
                            .await
                            .map_err(|_| ClientError::Pipe(<_>::default()))?;
                    }
                    Ok::<_, ClientError>(())
                }
                .boxed()
                .fuse();
                let mut progress = async {
                    loop {
                        select! {
                            () = progress_rx.select_next_some().fuse() => (),
                            () = timeout_generator(Duration::new(300, 0)).fuse() => {
                                error!("client: master pipe: close connection due to inactivity");
                                break
                            }
                        }
                    }
                }
                .boxed()
                .fuse();
                select! {
                    r = poll_send => if let Err(e) = r {
                        error!("client: {}", e)
                    },
                    r = poll_recv => if let Err(e) = r {
                        error!("client: {}", e)
                    },
                    _ = progress => info!("client: closing master connection due to no activity"),
                }
            }
            Ok::<_, ClientError>(())
        };
    let mut master_adapter = spawn
        .spawn(master_adapter)
        .map_err(|e| ClientError::Spawn(format!("{:?}", e)))
        .boxed()
        .fuse();
    let progress = async move {
        loop {
            select! {
                () = progress.select_next_some().fuse() => (),
                () = timeout_generator(Duration::new(300, 0)).fuse() => {
                    error!("client: stopping due to inactivity");
                    break
                }
            }
        }
    };
    let mut progress = spawn
        .spawn(progress)
        .map_err(|e| ClientError::Spawn(format!("{:?}", e)))
        .boxed()
        .fuse();
    let mut terminate = terminate.fuse();
    let mut poll = spawn
        .spawn(poll)
        .map_err(|e| ClientError::Spawn(format!("{:?}", e)))
        .fuse();
    let input = input.map(Ok).forward(session_input).map_err(|e| {
        error!("session_input: {:?}", e);
        ClientError::Pipe(<_>::default())
    });
    let mut input = spawn
        .spawn(input)
        .map_err(|e| ClientError::Spawn(format!("{:?}", e)))
        .boxed()
        .fuse();
    let output = session_output
        .map(Ok)
        .try_for_each(move |m| {
            let output = output.clone();
            async move { output.clone().send(m).await }
        })
        .map_err(|_| ClientError::Pipe(<_>::default()));
    let mut output = spawn
        .spawn(output)
        .map_err(|e| ClientError::Spawn(format!("{:?}", e)))
        .boxed()
        .fuse();
    select! {
        r = master_adapter => r??,
        r = progress => r?,
        r = terminate => r.map_err(|_| ClientError::Pipe(<_>::default()))?,
        r = poll => r??,
        r = input => r??,
        r = output => r??,
    }
    Ok(())
}

pub async fn client<S, TimeGen, Timeout>(
    bootstrap: ClientBootstrap,
    input: Receiver<Vec<u8>>,
    output: Sender<Vec<u8>>,
    terminate: OneshotReceiver<()>,
    spawn: S,
    timeout_generator: TimeGen,
) -> Result<(), ClientError>
where
    S: Spawn + Clone + Send + Sync + 'static,
    TimeGen: 'static + Clone + Send + Sync + Fn(Duration) -> Timeout,
    Timeout: 'static + Future<Output = ()> + Send + Sync,
{
    client_impl::<SafeGuard, rand_chacha::ChaChaRng, _, _, _, _>(
        bootstrap,
        reference_seeder_chacha,
        input,
        output,
        terminate,
        spawn,
        timeout_generator,
    )
    .inspect_err(|e| error!("client: {}", e))
    .await
}
