use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
    fmt::Debug,
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
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

pub struct UdarnikServer<G, R, S> {
    sessions: Arc<RwLock<HashMap<SessionId, SessionState<G>>>>,
    sign_db: Arc<BTreeMap<InitIdentity, BTreeMap<Identity, SigningKey>>>,
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
    _p: PhantomData<fn() -> R>,
}

impl<G, R, S> UdarnikServer<G, R, S>
where
    R: 'static + Send + CryptoRng + RngCore + SeedableRng,
{
    async fn handle_session(
        &self,
        mut message_stream: impl Stream<Item = Result<Message<G>, SessionError>> + Send + Sync + Unpin,
        mut message_sink: impl Sink<Message<G>, Error = SessionError> + Send + Sync + Unpin,
        h: impl Fn(Vec<u8>) -> Vec<u8>,
    ) -> Result<(), SessionError> {
        let init_db = Arc::clone(&self.init_db);
        let verify_db = Arc::clone(&self.verify_db);
        let sessions = Arc::clone(&self.sessions);
        let mut rng = R::from_entropy();
        let mut challenge = vec![0u8; 256];
        rng.fill_bytes(&mut challenge);
        let orig_challenge = challenge.clone();
        message_sink
            .send(Message::SessionLogOnChallenge(challenge))
            .await?;

        if let Some(m) = message_stream.next().await {
            match m? {
                Message::SessionLogOn(SessionLogOn {
                    session,
                    init_identity,
                    identity,
                    challenge,
                    signature,
                }) => {
                    if challenge != orig_challenge {
                        return Err(SessionError::SignOn("unexpected message".into()));
                    }
                    if let (Some(key), Some(init)) = (
                        verify_db.get(&init_identity).and_then(|t| t.get(&identity)),
                        init_db.get(&init_identity),
                    ) {
                        let mut challenge = challenge;
                        challenge.extend(session.as_bytes());
                        challenge.extend(init_identity.as_bytes());
                        challenge.extend(identity.as_bytes());

                        if key.verify(&challenge, signature, init, h) {
                            let SessionState {
                                master_in,
                                master_out,
                                ..
                            } = {
                                let sessions = sessions.read().await;
                                if let Some(state) = sessions.get(&session) {
                                    if state.session.init_identity == init_identity
                                        && state.session.anke_identity == identity
                                    {
                                        SessionState::clone(state)
                                    } else {
                                        return Err(SessionError::SignOn(
                                            "unexpected message".into(),
                                        ));
                                    }
                                } else {
                                    return Err(SessionError::SignOn("unexpected message".into()));
                                }
                            };
                            let master_in = message_stream.forward(master_in.sink_map_err(|e| {
                                SessionError::BrokenPipe(Box::new(e), <_>::default())
                            }));
                            let master_out = async {
                                while let Some(msg) = { master_out.lock().await.next() }.await {
                                    message_sink.send(msg).await?
                                }
                                Ok::<_, SessionError>(())
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
                            select! {
                                r = master_in => r?,
                                r = master_out => r?,
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
impl<G, R, S> wire::server_server::Server for UdarnikServer<G, R, S>
where
    G: 'static + Send + Sync + Guard<Params> + for<'a> From<&'a [u8]> + Debug,
    G::Error: Debug,
    R: 'static + Send + SeedableRng + RngCore + CryptoRng,
    S: 'static + Send + Sync + Clone + Fn(&[u8]) -> R::Seed,
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
        let request = request.into_inner().and_then(|m| {
            async { Message::<G>::try_from(m).map_err(|e| Status::aborted(format!("{}", e))) }
        });
        let request =
            Pin::from(Box::new(request)
                as Box<
                    dyn Stream<Item = Result<Message<G>, Status>> + Send + Sync,
                >);
        todo!()
    }
}

pub async fn server(addr: SocketAddr) {}
