use std::{
    collections::HashMap,
    convert::TryFrom,
    fmt::Debug,
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use async_std::sync::{Arc, Mutex, RwLock};
use digest::Digest;
use futures::{
    channel::mpsc::{channel, Receiver, Sender},
    future::{pending, select_all},
    pin_mut,
    prelude::*,
    select_biased,
};
use log::{error, info, trace, warn};
use rand::{CryptoRng, RngCore, SeedableRng};
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use crate::{
    state::{
        key_exchange_boris, wire, BridgeConstructorParams, Guard, KeyExchangeBorisIdentity,
        Message, Params, SafeGuard, Session, SessionBootstrap, SessionError, SessionHandle,
        SessionId, TimeoutParams,
    },
    utils::{Spawn, TryFutureStream},
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

struct UdarnikServer<G, R, H, S, TimeGen, Timeout> {
    sessions: Arc<RwLock<HashMap<SessionId, SessionState<G>>>>,
    kex: Arc<KeyExchangeBorisIdentity<R, H>>,
    seeder: S,
    new_sessions: Sender<SessionBootstrap>,
    timeout_generator: TimeGen,
    _p: PhantomData<fn() -> (R, Timeout)>,
}

impl<G, R, H, S, TimeGen, Timeout> UdarnikServer<G, R, H, S, TimeGen, Timeout>
where
    H: 'static,
    R: 'static + Send + CryptoRng + RngCore + SeedableRng,
    TimeGen: 'static + Clone + Send + Sync + Fn(Duration) -> Timeout,
    Timeout: 'static + Send + Sync + Future<Output = ()>,
{
    fn handle_session(
        &self,
        mut message_stream: impl Stream<Item = Result<Message<G>, SessionError>> + Send + Sync + Unpin,
        mut message_sink: impl Sink<Message<G>, Error = SessionError> + Send + Sync + Unpin,
    ) -> impl Future<Output = Result<(), SessionError>> {
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
                            return Err(SessionError::SignOn("incorrect challenge".into()));
                        }
                        let SessionState {
                            mut master_in,
                            master_out,
                            ..
                        } = {
                            let sessions = sessions.read().await;
                            if let Some(state) = sessions.get(&logon.session) {
                                SessionState::clone(state)
                            } else {
                                return Err(SessionError::SignOn("no such session".into()));
                            }
                        };
                        let session = logon.session;
                        trace!("server: session {} sign on", session);
                        let progress = AtomicBool::default();
                        let master_in = {
                            let progress = &progress;
                            async move {
                                while let Some(msg) = message_stream.next().await {
                                    master_in
                                        .send(msg?)
                                        .map_err(|e| {
                                            SessionError::BrokenPipe(Box::new(e), <_>::default())
                                        })
                                        .await?;
                                    progress.store(true, Ordering::Relaxed);
                                }
                                Ok::<_, SessionError>(())
                            }
                        }
                        .fuse();

                        let master_out = {
                            let progress = &progress;
                            async move {
                                loop {
                                    let msg = { master_out.lock().await.next().await };
                                    if let Some(msg) = msg {
                                        message_sink.send(msg).await?;
                                        progress.store(true, Ordering::Relaxed);
                                    } else {
                                        break;
                                    }
                                }
                                Ok::<_, SessionError>(())
                            }
                        }
                        .fuse();

                        let progress = async {
                            loop {
                                timeout_generator(Duration::new(300, 0)).await;
                                if progress.load(Ordering::Relaxed) {
                                    progress.store(false, Ordering::Relaxed);
                                } else {
                                    break;
                                }
                            }
                            info!("session {}: master link has no activity", session);
                        }
                        .fuse();
                        pin_mut!(master_in, master_out, progress);
                        select_biased! {
                            r = master_in => r?,
                            r = master_out => r?,
                            _ = progress => (),
                        }
                    }
                    _ => return Err(SessionError::SignOn("unexpected message type".into())),
                }
            }
            Ok(())
        }
    }
}

#[tonic::async_trait]
impl<G, R, H, S, TimeGen, Timeout> wire::master_server::Master
    for Pin<Arc<UdarnikServer<G, R, H, S, TimeGen, Timeout>>>
where
    H: 'static + Digest,
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
        info!("boris: incoming key exchange {:?}", request.remote_addr());
        let request = request.into_inner().and_then(|m| async {
            Message::<G>::try_from(m).map_err(|e| Status::aborted(format!("{}", e)))
        });
        let request =
            Pin::from(Box::new(request)
                as Box<
                    dyn Stream<Item = Result<Message<G>, Status>> + Send + Sync,
                >);
        let seeder = self.seeder.clone();
        let (message_sink, message_stream) = channel(4096);
        let mut new_sessions = self.new_sessions.clone();
        let session_id = SessionId::from(uuid::Uuid::new_v4().to_string());
        let kex_result = key_exchange_boris::<_, H, _, _, _, _, _, _>(
            Arc::clone(&self.kex),
            request,
            message_sink,
            seeder,
            session_id,
        )
        .map_err(|e| {
            info!("boris: error: {}", e);
            Box::new(e) as GenericError
        })
        .and_then(move |r| async move {
            info!("new session");
            new_sessions.send(r).await.map_err(|e| {
                info!("boris: error: {}", e);
                Box::new(e) as GenericError
            })
        });
        let stream = TryFutureStream::new(
            Box::new(Pin::from(Box::new(kex_result))),
            Box::new(message_stream.map(wire::Message::from).map(Ok)),
            true,
        );
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
            .and_then(|m| async {
                Message::<G>::try_from(m).map_err(|e| Status::aborted(format!("{}", e)))
            })
            .map_err(|e| SessionError::Stream(Box::new(e) as GenericError, <_>::default()));
        let request = Pin::from(Box::new(request)
            as Box<dyn Stream<Item = Result<Message<G>, SessionError>> + Send + Sync>);
        let (message_sink, stream) = channel(4096);
        let complete = self.handle_session(
            request,
            message_sink.sink_map_err(|e| SessionError::BrokenPipe(Box::new(e), <_>::default())),
        );
        let stream = TryFutureStream::new(
            Box::new(Pin::from(Box::new(complete))),
            Box::new(stream.map(wire::Message::from).map(Ok)),
            true,
        );
        Ok(Response::new(Box::pin(
            stream.map_err(|e| Status::aborted(format!("{}", e))),
        )))
    }
}

#[derive(Debug)]
pub struct ServerBootstrap<R, H> {
    pub addr: SocketAddr,
    pub kex: KeyExchangeBorisIdentity<R, H>,
    pub timeout_params: TimeoutParams,
    pub bridge_constructor_params: BridgeConstructorParams,
}

pub type ServiceFuture<T> = Pin<Box<dyn Future<Output = T> + Send + Sync>>;

pub async fn server<R, H, S, TimeGen, Timeout>(
    bootstrap: ServerBootstrap<R, H>,
    mut new_channel: Sender<(Sender<Vec<u8>>, Receiver<Vec<u8>>)>,
    seeder: S,
    spawn: impl Spawn + Clone + Send + Sync + 'static,
    timeout_generator: TimeGen,
) -> Result<(), GenericError>
where
    R: 'static + Send + Sync + SeedableRng + RngCore + CryptoRng,
    H: 'static + Digest,
    S: 'static + Send + Sync + Clone + Fn(&[u8]) -> R::Seed,
    TimeGen: 'static + Clone + Send + Sync + Fn(Duration) -> Timeout,
    Timeout: 'static + Future<Output = ()> + Send + Sync,
{
    let ServerBootstrap {
        addr,
        kex,
        timeout_params,
        bridge_constructor_params,
    } = bootstrap;
    let (new_sessions_tx, mut new_sessions) = channel(32);
    let sessions = Arc::default();
    let server: UdarnikServer<SafeGuard, _, _, _, _, Timeout> = UdarnikServer {
        _p: PhantomData,
        kex: Arc::new(kex),
        new_sessions: new_sessions_tx,
        seeder,
        sessions: Arc::clone(&sessions),
        timeout_generator: timeout_generator.clone(),
    };
    let server = Arc::pin(server);
    let (mut poll_session_tx, mut poll_session) = channel(32);
    let new_sessions = async {
        while let Some(session_bootstrap) = new_sessions.next().await {
            let (master_in, master_messages) = channel(4096);
            let (master_sink, master_out) = channel(4096);
            let master_sink =
                Box::new(master_sink.sink_map_err(|e| Box::new(e) as GenericError)) as _;
            let SessionHandle {
                session,
                poll,
                input,
                output,
                progress,
            } = match Session::<SafeGuard>::new(
                session_bootstrap,
                timeout_params,
                bridge_constructor_params.clone(),
                master_messages,
                master_sink,
                timeout_generator.clone(),
                spawn.clone(),
            ) {
                Ok(handle) => handle,
                Err(e) => {
                    error!("session: {}", e);
                    continue;
                }
            };
            if let Err(e) = new_channel.send((input, output)).await {
                error!("broken pipe: {}", e);
                break;
            }
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
            let timeout_generator = timeout_generator.clone();
            let timeout = async move {
                loop {
                    timeout_generator(Duration::new(30000000, 0)).await;
                    if progress.load(Ordering::Relaxed) {
                        progress.store(false, Ordering::Relaxed);
                    } else {
                        break;
                    }
                }
            }
            .fuse();
            let poll_progress_or_timeout = async move {
                pin_mut!(timeout);
                loop {
                    select_biased! {
                        _ = timeout => break,
                        _ = poll => break,
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
    .fuse();
    let poll_sessions = async move {
        let mut polls = vec![];
        loop {
            trace!("server: poll_sessions");
            let mut poll_all = if polls.is_empty() {
                pending().boxed()
            } else {
                select_all(polls.clone()).boxed()
            }
            .fuse();
            select_biased! {
                new_poll = poll_session.next() => {
                    if let Some(new_poll) = new_poll {
                        polls.push(new_poll.shared())
                    } else {
                        break;
                    }
                },
                (_, idx, _) = poll_all => {
                    let _ = polls.remove(idx);
                },
            }
        }
    }
    .fuse();
    let service = wire::master_server::MasterServer::new(server);
    let service = Server::builder().add_service(service).serve(addr).fuse();
    pin_mut!(service, poll_sessions, new_sessions);
    select_biased! {
        r = service => r?,
        _ = poll_sessions => (),
        _ = new_sessions => (),
    }
    warn!("server: terminated");
    Ok(())
}
