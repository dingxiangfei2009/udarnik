use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
    fmt::Debug,
    pin::Pin,
    time::Duration,
};

use async_std::task::sleep;
use failure::{Backtrace, Error as TopError, Fail};
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
use log::{error, info};
use rand::{CryptoRng, RngCore, SeedableRng};
use sss::lattice::{
    Init, PrivateKey, PublicKey, SessionKeyPart, SessionKeyPartMix, SigningKey, SIGN_K,
};
use tonic::{Request, Status};

use crate::{
    protocol::signature_hasher,
    state::{
        key_exchange_anke, wire, ClientMessageVariant, Guard, Identity, InitIdentity, KeyExchange,
        KeyExchangeError, Message, Params, SafeGuard, Session, SessionError, SessionHandle,
        SessionId, SessionLogOn, WireError,
    },
    GenericError,
};

pub struct ClientBootstrap<S> {
    addr: Uri,
    params: Params,
    allowed_identities: HashMap<InitIdentity, HashMap<Identity, PublicKey>>,
    anke_data: Vec<u8>,
    boris_data: Vec<u8>,
    identity_db: BTreeMap<InitIdentity, BTreeMap<Identity, PrivateKey>>,
    identity_sequence: Vec<(InitIdentity, Identity)>,
    init_db: BTreeMap<InitIdentity, Init>,
    retries: Option<u32>,
    sign_db: BTreeMap<InitIdentity, BTreeMap<Identity, SigningKey>>,
    seeder: S,
}

#[derive(Fail, Debug, From)]
pub enum ClientError {
    #[fail(display = "connection reset")]
    Reset(Backtrace),
    #[fail(display = "broken pipe")]
    Pipe(Backtrace),
    #[fail(display = "network: {}", _0)]
    Net(Status, Backtrace),
    #[fail(display = "wire: {}", _0)]
    Wire(WireError, Backtrace),
    #[fail(display = "crypto: no init")]
    NoInit,
    #[fail(display = "crypto: no signing key")]
    NoSigningKey,
    #[fail(display = "session: {}", _0)]
    Session(SessionError),
    #[fail(display = "transport: {}", _0)]
    Transport(tonic::transport::Error, Backtrace),
    #[fail(display = "key exchange: {}", _0)]
    KeyExchange(KeyExchangeError),
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
    let (mut message_sink, master_in) = channel(4096);
    let mut message_stream = Box::pin(
        client
            .client(Request::new(master_in.map(wire::Message::from)))
            .await
            .map_err(|e| ClientError::Net(e, <_>::default()))?
            .into_inner()
            .map_err(|e| ClientError::Net(e, <_>::default()))
            .and_then(|m| {
                async {
                    Message::<G>::try_from(m).map_err(|e| ClientError::Wire(e, <_>::default()))
                }
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
        key.sign(&mut rng, init, body, SIGN_K, h)
    } else {
        return Err(ClientError::NoSigningKey);
    };
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

pub async fn client<G, R, S>(
    bootstrap: ClientBootstrap<S>,
    input: Receiver<Vec<u8>>,
    output: Sender<Vec<u8>>,
    terminate: OneshotReceiver<()>,
) -> Result<(), ClientError>
where
    G: 'static + Send + Sync + Guard<Params, ()> + for<'a> From<&'a [u8]> + Debug,
    G::Error: Debug,
    R: 'static + Send + Sync + SeedableRng + RngCore + CryptoRng,
    S: Send + Sync + Clone + Fn(&[u8]) -> R::Seed,
{
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
        seeder,
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
        .and_then(|m| {
            async { Message::<G>::try_from(m).map_err(|e| Box::new(e.compat()) as GenericError) }
        })
        .map_err(TopError::from_boxed_compat)
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
    let master_sink = Box::new(master_sink.sink_map_err(|e| Box::new(e) as GenericError)) as _;
    let SessionHandle {
        session,
        poll,
        input,
        output,
        mut progress,
    } = Session::<SafeGuard>::new(
        session_bootstrap,
        master_messages,
        master_sink,
        |duration| async_std::task::sleep(duration).boxed(),
    )?;
    let master_in = crate::utils::Peekable::new(master_in);
    let mut master_adapter =
        async move {
            pin_mut!(master_in);
            // let (client_out_tx, client_out_rx) = channel(4096);
            // let (client_in_tx, client_in_rx) = channel(4096);
            // let send = async {};
            // let recv = async {};
            while let Some(_) = master_in.as_mut().peek().await {
                let (mut client_send, mut client_recv) =
                    match reconnect(&mut client, &session, &init_db, &sign_db, signature_hasher)
                        .await
                    {
                        Ok(p) => p,
                        Err(ClientError::Pipe(e)) => {
                            error!("pipe: {}", e);
                            continue;
                        }
                        Err(ClientError::Net(s, e)) => {
                            error!("net: status: {}\n{}", s, e);
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
                            () = sleep(Duration::new(300, 0)).fuse() => break,
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
        }
        .boxed()
        .fuse();
    let mut progress = async {
        loop {
            select! {
                () = progress.select_next_some().fuse() => (),
                () = sleep(Duration::new(300, 0)).fuse() => break,
            }
        }
    }
    .boxed()
    .fuse();
    let mut terminate = terminate.fuse();
    let mut poll = poll.fuse();
    select! {
        r = master_adapter => r?,
        () = progress => (),
        r = terminate => r.map_err(|_| ClientError::Pipe(<_>::default()))?,
        r = poll => r?,
    }
    Ok(())
}
