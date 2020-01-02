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

use async_std::sync::{Arc, Mutex, RwLock};
use failure::Fail;
use futures::{
    channel::mpsc::{channel, Receiver, Sender},
    prelude::*,
    select,
};
use pin_utils::unsafe_pinned;
use rand::{CryptoRng, RngCore, SeedableRng};
use sss::lattice::{
    Anke, Boris, Init, PrivateKey, PublicKey, SessionKeyPart, SessionKeyPartMix, SigningKey,
    VerificationKey,
};
use tonic::{Request, Response, Status, Streaming};

use crate::{
    protocol::signature_hasher,
    state::{
        key_exchange_boris, wire, ClonableSink, Guard, Identity, InitIdentity, KeyExchange,
        Message, Params, Session, SessionBootstrap, SessionError, SessionId, SessionLogOn,
    },
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
                            if key.verify(&logon.generate_body(), logon.signature, init, h) {
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

struct TryFutureStream<T, E> {
    complete: Option<Box<dyn Send + Sync + Unpin + Future<Output = Result<(), E>>>>,
    stream: Option<Box<dyn Send + Sync + Unpin + Stream<Item = Result<T, E>>>>,
}

impl<T, E> TryFutureStream<T, E> {
    unsafe_pinned!(complete: Option<Box<dyn Send + Sync + Unpin + Future<Output = Result<(), E>>>>);
    unsafe_pinned!(stream: Option<Box<dyn Send + Sync + Unpin + Stream<Item = Result<T, E>>>>);
}

impl<T, E> Stream for TryFutureStream<T, E> {
    type Item = Result<T, E>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        use Poll::*;

        let stream = self
            .as_mut()
            .stream()
            .as_pin_mut()
            .map(|stream| stream.poll_next(cx));
        let complete = self
            .as_mut()
            .complete()
            .as_pin_mut()
            .map(|complete| complete.poll(cx));
        match (stream, complete) {
            (Some(Pending), Some(Pending)) => Pending,
            (_, Some(Ready(Ok(_)))) => {
                *self.as_mut().stream() = None;
                *self.as_mut().complete() = None;
                Ready(None)
            }
            (_, Some(Ready(Err(e)))) => {
                *self.as_mut().stream() = None;
                *self.as_mut().complete() = None;
                Ready(Some(Err(e)))
            }
            (_, None) => Ready(None),
            (Some(Ready(Some(item))), Some(_)) => Ready(Some(item)),
            (Some(Ready(None)), Some(_)) => {
                *self.as_mut().stream() = None;
                Pending
            }
            _ => Ready(None),
        }
    }
}

impl<T, E> Unpin for TryFutureStream<T, E> {}

#[tonic::async_trait]
impl<G, R, S, TimeGen, Timeout> wire::server_server::Server
    for UdarnikServer<G, R, S, TimeGen, Timeout>
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

pub async fn server(bootstrap: ServerBootstrap) {
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
    // let (new_sessions_tx, new_sessions) = channel(32);
    // let server = UdarnikServer {
    //     _p: PhantomData,
    //     allowed_identities,
    //     anke_data,
    //     boris_data,
    //     identity_db,
    //     identity_sequence,
    //     init_db,
    //     new_sessions: new_sessions_tx,
    //     retries,
    //     seeder: signature_hasher,
    //     sessions: <_>::default(),
    //     verify_db: Arc::new(verify_db),
    //     timeout_generator: async_std::task::sleep,
    // };
}
