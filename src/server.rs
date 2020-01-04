use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
    fmt::Debug,
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use async_std::{
    sync::{Arc, Mutex, RwLock},
    task::sleep,
};
use failure::Fail;
use futures::{
    channel::mpsc::{channel, Receiver, Sender},
    future::{pending, select_all},
    prelude::*,
    select,
};
use log::{error, info};
use pin_utils::unsafe_pinned;
use rand::{CryptoRng, RngCore, SeedableRng};
use sss::lattice::{
    Init, PrivateKey, PublicKey, SessionKeyPart, SessionKeyPartMix, VerificationKey,
};
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use crate::{
    protocol::signature_hasher,
    reference_seeder_chacha,
    state::{
        key_exchange_boris, wire, Guard, Identity, InitIdentity, KeyExchange, Message, Params,
        SafeGuard, Session, SessionBootstrap, SessionError, SessionHandle, SessionId, SessionLogOn,
    },
    utils::TryFutureStream,
    GenericError,
};

pub struct SessionState<G> {
    session: Pin<Arc<Session<G>>>,
    master_in: Sender<Message<G>>,
    master_out: Pin<Arc<Mutex<Receiver<Message<G>>>>>,
}

impl<G> Clone for SessionState<G> {
    fn clone(&self) -> Self {
        Self {
            session: Pin::clone(&self.session),
            master_in: self.master_in.clone(),
            master_out: Pin::clone(&self.master_out),
        }
    }
}

struct UdarnikServer<G, R, S, TimeGen, Timeout> {
    sessions: Arc<RwLock<HashMap<SessionId, SessionState<G>>>>,
    verify_db: Arc<BTreeMap<InitIdentity, BTreeMap<Identity, VerificationKey>>>,
    retries: Option<u32>,
    init_db: Arc<BTreeMap<InitIdentity, Init>>,
    identity_db: BTreeMap<InitIdentity, BTreeMap<Identity, PrivateKey>>,
    allowed_identities: HashMap<InitIdentity, HashMap<Identity, PublicKey>>,
    identity_sequence: Vec<(InitIdentity, Identity)>,
    anke_data: Vec<u8>,
    boris_data: Vec<u8>,
    seeder: S,
    new_sessions: Sender<SessionBootstrap>,
    timeout_generator: TimeGen,
    _p: PhantomData<fn() -> (R, Timeout)>,
}

impl<G, R, S, TimeGen, Timeout> UdarnikServer<G, R, S, TimeGen, Timeout>
where
    R: 'static + Send + CryptoRng + RngCore + SeedableRng,
    TimeGen: 'static + Clone + Send + Sync + Fn(Duration) -> Timeout,
    Timeout: 'static + Send + Sync + Future<Output = ()>,
{
    fn handle_session(
        &self,
        mut message_stream: impl Stream<Item = Result<Message<G>, SessionError>> + Send + Sync + Unpin,
        mut message_sink: impl Sink<Message<G>, Error = SessionError> + Send + Sync + Unpin,
        h: impl Fn(Vec<u8>) -> Vec<u8>,
    ) -> impl Future<Output = Result<(), SessionError>> {
        let init_db = Arc::clone(&self.init_db);
        let verify_db = Arc::clone(&self.verify_db);
        let sessions = Arc::clone(&self.sessions);
        let mut rng = R::from_entropy();
        let mut challenge = vec![0u8; 256];
        rng.fill_bytes(&mut challenge);
        let orig_challenge = challenge.clone();
        let timeout_generator = self.timeout_generator.clone();
        async move {
            message_sink
                .send(Message::SessionLogOnChallenge(challenge))
                .await?;
            if let Some(m) = message_stream.next().await {
                match m? {
                    Message::SessionLogOn(logon) => {
                        if logon.challenge != orig_challenge {
                            return Err(SessionError::SignOn("unexpected message".into()));
                        }
                        if let (Some(key), Some(init)) = (
                            verify_db
                                .get(&logon.init_identity)
                                .and_then(|t| t.get(&logon.identity)),
                            init_db.get(&logon.init_identity),
                        ) {
                            if key.verify(&logon.recover_body(), logon.signature, init, h) {
                                let SessionState {
                                    mut master_in,
                                    master_out,
                                    ..
                                } = {
                                    let sessions = sessions.read().await;
                                    if let Some(state) = sessions.get(&logon.session) {
                                        if state.session.init_identity == logon.init_identity
                                            && state.session.anke_identity == logon.identity
                                        {
                                            SessionState::clone(state)
                                        } else {
                                            return Err(SessionError::SignOn(
                                                "unexpected message".into(),
                                            ));
                                        }
                                    } else {
                                        return Err(SessionError::SignOn(
                                            "unexpected message".into(),
                                        ));
                                    }
                                };
                                let (progress_tx, mut progress_rx) = channel(4096);
                                let master_in = {
                                    let mut progress = progress_tx.clone();
                                    async move {
                                        while let Some(msg) = message_stream.next().await {
                                            master_in
                                                .send(msg?)
                                                .map_err(|e| {
                                                    SessionError::BrokenPipe(
                                                        Box::new(e),
                                                        <_>::default(),
                                                    )
                                                })
                                                .await?;
                                            progress.send(()).await.map_err(|e| {
                                                SessionError::BrokenPipe(
                                                    Box::new(e),
                                                    <_>::default(),
                                                )
                                            })?;
                                        }
                                        Ok::<_, SessionError>(())
                                    }
                                };

                                let master_out = {
                                    let mut progress = progress_tx;
                                    async move {
                                        while let Some(msg) =
                                            { master_out.lock().await.next() }.await
                                        {
                                            message_sink.send(msg).await?;
                                            progress.send(()).await.map_err(|e| {
                                                SessionError::BrokenPipe(
                                                    Box::new(e),
                                                    <_>::default(),
                                                )
                                            })?;
                                        }
                                        Ok::<_, SessionError>(())
                                    }
                                };
                                let progress = async {
                                    loop {
                                        let mut timeout = Pin::from(Box::new(timeout_generator(
                                            Duration::new(300, 0),
                                        ))
                                            as Box<dyn Future<Output = ()> + Send + Sync>)
                                        .fuse();
                                        select! {
                                            _ = progress_rx.next() => (),
                                            _ = timeout => break
                                        }
                                    }
                                };
                                let mut master_in = Pin::from(Box::new(master_in)
                                    as Box<
                                        dyn Future<Output = Result<(), SessionError>> + Send + Sync,
                                    >)
                                .fuse();
                                let mut master_out = Pin::from(Box::new(master_out)
                                    as Box<
                                        dyn Future<Output = Result<(), SessionError>> + Send + Sync,
                                    >)
                                .fuse();
                                let mut progress = Pin::from(Box::new(progress)
                                    as Box<dyn Future<Output = ()> + Send + Sync>)
                                .fuse();
                                select! {
                                    r = master_in => r?,
                                    r = master_out => r?,
                                    _ = progress => (),
                                }
                            }
                        }
                    }
                    _ => return Err(SessionError::SignOn("unexpected message".into())),
                }
            }
            Ok(())
        }
    }
}

#[tonic::async_trait]
impl<G, R, S, TimeGen, Timeout> wire::master_server::Master
    for Pin<Arc<UdarnikServer<G, R, S, TimeGen, Timeout>>>
where
    G: 'static + Send + Sync + Guard<Params, ()> + for<'a> From<&'a [u8]> + Debug,
    G::Error: Debug,
    R: 'static + Send + Sync + SeedableRng + RngCore + CryptoRng,
    S: 'static + Send + Sync + Clone + Fn(&[u8]) -> R::Seed,
    TimeGen: 'static + Clone + Send + Sync + Fn(Duration) -> Timeout,
    Timeout: 'static + Future<Output = ()> + Send + Sync,
{
    type KeyExchangeStream =
        Pin<Box<dyn 'static + Send + Sync + Stream<Item = Result<wire::Message, Status>>>>;
    type ClientStream =
        Pin<Box<dyn 'static + Send + Sync + Stream<Item = Result<wire::Message, Status>>>>;

    async fn key_exchange(
        &self,
        request: Request<Streaming<wire::Message>>,
    ) -> Result<Response<Self::KeyExchangeStream>, Status> {
        let request = request.into_inner().and_then(|m| {
            async { Message::<G>::try_from(m).map_err(|e| Status::aborted(format!("{}", e))) }
        });
        let request =
            Pin::from(Box::new(request)
                as Box<
                    dyn Stream<Item = Result<Message<G>, Status>> + Send + Sync,
                >);
        let kex = KeyExchange {
            retries: self.retries,
            init_db: <_>::clone(&*self.init_db),
            identity_db: self.identity_db.clone(),
            allowed_identities: self.allowed_identities.clone(),
            identity_sequence: self.identity_sequence.clone(),
            session_key_part_sampler: SessionKeyPart::parallel_sampler::<R>(2, 4096),
            anke_session_key_part_mix_sampler: SessionKeyPartMix::parallel_sampler::<R>(2, 4096),
            boris_session_key_part_mix_sampler: SessionKeyPartMix::parallel_sampler::<R>(2, 4096),
            anke_data: self.anke_data.to_vec(),
            boris_data: self.boris_data.to_vec(),
        };
        let seeder = self.seeder.clone();
        let (message_sink, message_stream) = channel(4096);
        let mut new_sessions = self.new_sessions.clone();
        let session_id = SessionId::from(uuid::Uuid::new_v4().to_string());
        let kex_result = key_exchange_boris(kex, request, message_sink, seeder, session_id)
            .map_err(|e| Box::new(e.compat()) as GenericError)
            .and_then(move |r| {
                async move {
                    new_sessions
                        .send(r)
                        .await
                        .map_err(|e| Box::new(e) as GenericError)
                }
            });
        let stream = TryFutureStream {
            complete: Some(Box::new(Pin::from(Box::new(kex_result)))),
            stream: Some(Box::new(message_stream.map(wire::Message::from).map(Ok))),
        };
        Ok(Response::new(Box::pin(
            stream.map_err(|e| Status::aborted(format!("{}", e))),
        )))
    }

    async fn client(
        &self,
        request: Request<Streaming<wire::Message>>,
    ) -> Result<Response<Self::ClientStream>, Status> {
        let request = request
            .into_inner()
            .and_then(|m| {
                {
                    async {
                        Message::<G>::try_from(m).map_err(|e| Status::aborted(format!("{}", e)))
                    }
                }
            })
            .map_err(|e| {
                SessionError::Stream(Box::new(e.compat()) as GenericError, <_>::default())
            });
        let request = Pin::from(Box::new(request)
            as Box<dyn Stream<Item = Result<Message<G>, SessionError>> + Send + Sync>);
        let (message_sink, stream) = channel(4096);
        let complete = self.handle_session(
            request,
            message_sink.sink_map_err(|e| SessionError::BrokenPipe(Box::new(e), <_>::default())),
            signature_hasher,
        );
        let stream = TryFutureStream {
            complete: Some(Box::new(Pin::from(Box::new(complete)))),
            stream: Some(Box::new(stream.map(wire::Message::from).map(Ok))),
        };
        Ok(Response::new(Box::pin(
            stream.map_err(|e| Status::aborted(format!("{}", e))),
        )))
    }
}

pub struct ServerBootstrap {
    addr: SocketAddr,
    allowed_identities: HashMap<InitIdentity, HashMap<Identity, PublicKey>>,
    anke_data: Vec<u8>,
    boris_data: Vec<u8>,
    identity_db: BTreeMap<InitIdentity, BTreeMap<Identity, PrivateKey>>,
    identity_sequence: Vec<(InitIdentity, Identity)>,
    init_db: Arc<BTreeMap<InitIdentity, Init>>,
    retries: Option<u32>,
    verify_db: BTreeMap<InitIdentity, BTreeMap<Identity, VerificationKey>>,
}

pub type ServiceFuture<T> = Pin<Box<dyn Future<Output = T> + Send + Sync>>;

pub async fn server(bootstrap: ServerBootstrap) -> Result<(), GenericError> {
    let ServerBootstrap {
        addr,
        allowed_identities,
        anke_data,
        boris_data,
        identity_db,
        identity_sequence,
        init_db,
        retries,
        verify_db,
    } = bootstrap;
    let (new_sessions_tx, mut new_sessions) = channel(32);
    let sessions = Arc::default();
    let seeder = reference_seeder_chacha;
    let server: UdarnikServer<SafeGuard, rand_chacha::ChaChaRng, _, _, ServiceFuture<()>> =
        UdarnikServer {
            _p: PhantomData,
            allowed_identities,
            anke_data,
            boris_data,
            identity_db,
            identity_sequence,
            init_db,
            new_sessions: new_sessions_tx,
            retries,
            seeder,
            sessions: Arc::clone(&sessions),
            verify_db: Arc::new(verify_db),
            timeout_generator: |duration| {
                Pin::from(Box::new(async_std::task::sleep(duration))
                    as Box<dyn Future<Output = ()> + Send + Sync>)
            },
        };
    let server = Arc::pin(server);
    let (mut poll_session_tx, mut poll_session) = channel(32);
    let mut new_sessions = async {
        while let Some(session_bootstrap) = new_sessions.next().await {
            let timeout_generator = |duration| sleep(duration).boxed();
            let (master_in, master_messages) = channel(4096);
            let (master_sink, master_out) = channel(4096);
            let master_sink =
                Box::new(master_sink.sink_map_err(|e| Box::new(e) as GenericError)) as _;
            let SessionHandle {
                session,
                poll,
                input,
                output,
                mut progress,
            } = match Session::<SafeGuard>::new(
                session_bootstrap,
                master_messages,
                master_sink,
                timeout_generator,
            ) {
                Ok(handle) => handle,
                Err(e) => {
                    error!("session: {}", e);
                    continue;
                }
            };
            let session_id = session.session_id.clone();
            let master_out = Arc::pin(Mutex::new(master_out));
            let session_state = SessionState {
                session,
                master_in,
                master_out,
            };
            sessions
                .write()
                .await
                .insert(session_id.clone(), session_state);
            let mut poll = poll.fuse();
            let sessions = Arc::clone(&sessions);
            let mut output = output
                .for_each(|data| async move { info!("data={:?}", data) })
                .boxed()
                .fuse();
            let poll_progress_or_timeout = async move {
                loop {
                    let mut timeout = timeout_generator(Duration::new(300, 0)).fuse();
                    select! {
                        _ = progress.next().fuse() => (),
                        _ = timeout => break,
                        _ = poll => break,
                        _ = output => break,
                    }
                }
                info!("session {} is dropped", session_id);
                sessions.write().await.remove(&session_id);
            };
            if let Err(e) = poll_session_tx.send(poll_progress_or_timeout).await {
                error!("creating session: {}", e);
                break;
            }
        }
    }
    .boxed()
    .fuse();
    let mut poll_sessions = async move {
        let mut polls = vec![];
        loop {
            let mut poll_all = if polls.is_empty() {
                select_all(polls.clone()).boxed()
            } else {
                pending().boxed()
            }
            .fuse();
            select! {
                new_poll = poll_session.next() => {
                    if let Some(new_poll) = new_poll {
                        polls.push(new_poll.shared())
                    }
                },
                (_, idx, _) = poll_all => {
                    let _ = polls.remove(idx);
                },
            }
        }
    }
    .boxed()
    .fuse();
    let service = wire::master_server::MasterServer::new(server);
    let mut service = Server::builder()
        .add_service(service)
        .serve(addr)
        .boxed()
        .fuse();
    select! {
        r = service => r?,
        _ = poll_sessions => (),
        _ = new_sessions => (),
    }
    Ok(())
}
