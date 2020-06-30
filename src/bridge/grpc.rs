use std::{
    convert::TryFrom,
    io::Result as IoResult,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use aead::{Aead, NewAead};
use async_std::{
    io::{Read as AsyncStdRead, Write as AsyncStdWrite},
    net::{TcpListener, TcpStream},
    os::unix::net::{UnixListener, UnixStream},
    sync::{channel, Arc, Receiver, Sender},
    task::sleep,
};
use async_trait::async_trait;
use backtrace::Backtrace as Bt;
use bitvec::{order::Msb0, slice::BitSlice};
use chacha20poly1305::ChaCha20Poly1305;
use futures::{
    channel::{
        mpsc::{channel as std_channel, Sender as StdSender},
        oneshot,
    },
    future::BoxFuture,
    pin_mut,
    prelude::*,
    select, select_biased,
};
use generic_array::GenericArray;
use http::Uri;
use log::info;
use log::{error, trace};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite};
use tonic::transport::{server::Connected, Channel, Endpoint, Server};
use tonic::{Request, Response, Status, Streaming};

use super::{BridgeHalf, ConstructibleBridge};

use crate::{
    state::{
        wire, Bridge, BridgeConstructorParams, BridgeId, BridgeMessage, GrpcBridge as GrpcParams,
        Guard, Pomerium, UnixBridge as UnixParams,
    },
    utils::{Spawn, TryFutureStream},
    GenericError,
};

#[derive(Error, Debug, From)]
pub enum BridgeServerError {
    #[error("broken pipe, backtrace: {0:?}")]
    Pipe(Bt),
}

#[derive(Clone)]
pub struct BridgeChannel {
    key: [u8; 32],
    send: Sender<Vec<u8>>,
    recv: Receiver<Vec<u8>>,
}

impl BridgeChannel {
    pub fn new(key: [u8; 32]) -> Self {
        let (send, recv) = channel(65536);
        Self { key, send, recv }
    }
}

pub struct BridgeServer<S> {
    up_id: String,
    down_id: String,
    up: BridgeChannel,
    down: BridgeChannel,
    progress: Sender<()>,
    spawn: S,
}

impl<S: Spawn> BridgeServer<S> {
    fn new(spawn: S) -> (Self, Receiver<()>) {
        let up = uuid::Uuid::new_v4().to_string();
        let down = uuid::Uuid::new_v4().to_string();
        let mut up_key = [0; 32];
        let mut down_key = [0; 32];
        OsRng.fill_bytes(&mut up_key);
        OsRng.fill_bytes(&mut down_key);
        let (progress_tx, progress) = channel(256);
        (
            BridgeServer {
                up_id: up.to_string(),
                down_id: down.to_string(),
                up: BridgeChannel::new(up_key),
                down: BridgeChannel::new(down_key),
                progress: progress_tx,
                spawn,
            },
            progress,
        )
    }

    async fn process_stream(
        self: Pin<&Self>,
        mut request: impl Stream<Item = Result<wire::RawBridgeMessage, Status>>
            + Send
            + Sync
            + Unpin
            + 'static,
        response: StdSender<Result<wire::RawBridgeMessage, Status>>,
    ) -> Result<(), Status> {
        let (up, down, mut nonce) = match request
            .next()
            .await
            .ok_or_else(|| Status::aborted("broken pipe"))??
        {
            wire::RawBridgeMessage {
                variant:
                    Some(wire::raw_bridge_message::Variant::Id(wire::RawBridgeId {
                        id: Some(wire::BridgeId { up, down }),
                        nonce,
                    })),
            } => (up, down, nonce),
            _ => return Err(Status::aborted("connection reset")),
        };
        nonce.resize(12, 0);
        let nonce = Arc::pin(nonce);
        let (key, send, recv) = if (&self.up_id as &str, &self.down_id as &str) == (&up, &down) {
            (self.up.key, self.up.send.clone(), self.down.recv.clone())
        } else if (&self.up_id as &str, &self.down_id as &str) == (&down, &up) {
            (self.down.key, self.down.send.clone(), self.up.recv.clone())
        } else {
            return Err(Status::aborted("broken pipe"));
        };
        let aead = Arc::pin(ChaCha20Poly1305::new(GenericArray::from_slice(&key)));
        let aead_ = Pin::clone(&aead);
        let nonce_ = Pin::clone(&nonce);
        let progress = self.progress.clone();
        let up = self
            .spawn
            .spawn(request.try_for_each_concurrent(32, move |m| {
                let aead = Pin::clone(&aead_);
                let nonce = Pin::clone(&nonce_);
                let send = send.clone();
                let progress = progress.clone();
                async move {
                    match m {
                        wire::RawBridgeMessage {
                            variant: Some(wire::raw_bridge_message::Variant::Raw(m)),
                        } => {
                            trace!("bridge: incoming data");
                            match aead.decrypt(GenericArray::from_slice(&nonce), &m[..]) {
                                Ok(m) => {
                                    send.send(m).await;
                                    Ok(progress.send(()).await)
                                }
                                Err(e) => {
                                    error!("decrypt: {:?}", e);
                                    Ok(())
                                }
                            }
                        }
                        _ => Err(Status::aborted("malformed data")),
                    }
                }
            }))
            .fuse();
        let mut up = Box::new(Box::pin(up));
        let progress = self.progress.clone();
        let down = self
            .spawn
            .spawn(
                recv.map(move |m| {
                    let aead = Pin::clone(&aead);
                    let nonce = Pin::clone(&nonce);
                    let progress = progress.clone();
                    async move {
                        trace!("bridge: outgoing data");
                        let m = aead
                            .encrypt(GenericArray::from_slice(&nonce), &m[..])
                            .map_err(|e| {
                                error!("encrypt: {:?}", e);
                                Status::aborted("malformed data")
                            })?;
                        let m = wire::RawBridgeMessage {
                            variant: Some(wire::raw_bridge_message::Variant::Raw(m)),
                        };
                        progress.send(()).await;
                        Ok::<_, Status>(m)
                    }
                })
                .buffer_unordered(32)
                .map(Ok)
                .forward(response)
                .map_err(|e| {
                    error!("bridge: broken pipe: {}", e);
                    Status::aborted("hangup")
                }),
            )
            .fuse();
        let mut down = Box::new(Box::pin(down));
        select! {
            r = up => match r {
                Ok(Err(e)) => Err(e),
                Err(e) => {
                    error!("spawn: {:?}", e);
                    Ok(())
                },
                _ => Ok(()),
            },
            r = down => match r {
                Ok(Err(e)) => Err(e),
                Err(e) => {
                    error!("spawn: {:?}", e);
                    Ok(())
                },
                _ => Ok(()),
            },
        }
    }
}

#[tonic::async_trait]
impl<S> wire::bridge_server::Bridge for Pin<Arc<BridgeServer<S>>>
where
    S: Spawn + Send + Sync + 'static,
    S::Error: 'static,
{
    type ChannelStream =
        Pin<Box<dyn 'static + Send + Sync + Stream<Item = Result<wire::RawBridgeMessage, Status>>>>;
    async fn channel(
        &self,
        request: Request<Streaming<wire::RawBridgeMessage>>,
    ) -> Result<Response<Self::ChannelStream>, Status> {
        let request = request.into_inner();
        let request = Pin::from(Box::new(request)
            as Box<dyn Stream<Item = Result<wire::RawBridgeMessage, Status>> + Send + Sync>);
        let (response_tx, response) = std_channel(4096);
        let poll = self
            .spawn
            .spawn({
                let this = Pin::clone(self);
                async move { this.as_ref().process_stream(request, response_tx).await }
            })
            .unwrap_or_else(|e| {
                error!("bridge: {:?}", e);
                Ok(())
            });

        Ok(Response::new(Box::pin(TryFutureStream::new(
            Box::new(Box::pin(poll)),
            Box::new(Box::pin(response)),
            true,
        ))))
    }
}

pub struct GrpcBridgeConstruction {
    pub id: BridgeId,
    pub params: GrpcParams,
    pub kill_switch: oneshot::Sender<()>,
    pub driver: Box<dyn Future<Output = ()> + Send + Sync + Unpin>,
}

fn random_addr_from_cidr(net: &IpAddr, range: usize) -> Result<IpAddr, GenericError> {
    #[derive(Error, Debug)]
    enum RandomCidrError {
        #[error("invalid cidr spec")]
        InvalidCidr,
    }
    match net {
        IpAddr::V4(net) if range <= 32 => {
            let mut addr = net.octets();
            let mut rand = addr;
            let slice: &mut BitSlice<Msb0, _> = BitSlice::from_slice_mut(&mut addr);
            OsRng.fill_bytes(&mut rand);
            let rand_slice: &BitSlice<Msb0, _> = BitSlice::from_slice(&rand);
            slice[range..].copy_from_slice(&rand_slice[range..]);
            Ok(addr.into())
        }
        IpAddr::V6(net) if range <= 128 => {
            let mut addr = net.octets();
            let mut rand = addr;
            let slice: &mut BitSlice<Msb0, _> = BitSlice::from_slice_mut(&mut addr);
            OsRng.fill_bytes(&mut rand);
            let rand_slice: &BitSlice<Msb0, _> = BitSlice::from_slice(&rand);
            slice[range..].copy_from_slice(&rand_slice[range..]);
            Ok(addr.into())
        }
        _ => Err(Box::new(RandomCidrError::InvalidCidr)),
    }
}

/// Construct a TCP GRPC bridge server
pub async fn bridge<S>(
    spawn: S,
    params: &BridgeConstructorParams,
) -> Result<GrpcBridgeConstruction, GenericError>
where
    S: Spawn + Clone + Send + Sync + 'static,
    S::Error: 'static,
{
    trace!("bridge: engineering");
    let BridgeConstructorParams {
        ip_listener_mask,
        ip_listener_address,
        ..
    } = params;
    let addr = random_addr_from_cidr(ip_listener_address, *ip_listener_mask)?;
    let stream = TcpListener::bind(SocketAddr::new(addr, 0)).await?;
    let addr = stream.local_addr()?;
    let addr = vec![addr];

    let (server, mut progress) = BridgeServer::new(spawn.clone());
    let up_key = server.up.key;
    let down_key = server.down.key;
    let up = server.up_id.clone();
    let down = server.down_id.clone();
    let server = Arc::pin(server);
    let service = wire::bridge_server::BridgeServer::new(Pin::clone(&server));
    let (incoming_tx, incoming) = channel(4096);
    let accept = async move {
        let incoming = stream.incoming();
        incoming
            .for_each_concurrent(32, |stream| {
                let incoming = incoming_tx.clone();
                async move {
                    incoming.send(stream).await;
                }
            })
            .await
    };
    let accept = Box::pin(accept) as Pin<Box<dyn Future<Output = ()> + Send + Sync>>;
    let mut accept = accept.fuse();
    let service = Server::builder()
        .add_service(service)
        .serve_with_incoming(incoming.map_ok(TcpStreamCompat))
        .then(|r| async move {
            if let Err(e) = r {
                error!("unix bridge: {}", e)
            }
        });
    let service = spawn
        .spawn(service)
        .unwrap_or_else(|e| error!("bridge: service: {:?}", e));
    let service = Box::pin(service) as Pin<Box<dyn Future<Output = ()> + Send + Sync>>;
    let mut service = service.fuse();
    let id = BridgeId { up, down };
    let params = GrpcParams {
        addr,
        id: id.clone(),
        up: up_key,
        down: down_key,
    };
    let progress = async move {
        loop {
            select_biased! {
                r = progress.next().fuse() => if let None = r { break },
                _ = sleep(Duration::new(300, 0)).fuse() => break,
            }
        }
    };
    let progress = Box::pin(progress) as Pin<Box<dyn Future<Output = ()> + Send + Sync>>;
    let mut progress = progress.fuse();
    let (kill_switch, kill_signal) = oneshot::channel();
    let service = async move {
        select_biased! {
            _ = progress => (),
            _ = service => (),
            _ = accept => (),
            kill_signal = kill_signal.fuse() => {
                match kill_signal {
                    Ok(_) => info!("bridge server: killed"),
                    Err(_) => info!("bridge server: killed since kill switch dropped"),
                }
            }
        }
    };
    Ok(GrpcBridgeConstruction {
        id,
        params,
        kill_switch,
        driver: Box::new(Box::pin(service) as Pin<Box<dyn Future<Output = ()> + Send + Sync>>),
    })
}

#[cfg(target_family = "unix")]
pub async fn bridge_uds<S>(
    spawn: S,
) -> Result<
    (
        BridgeId,
        UnixParams,
        Box<dyn Future<Output = ()> + Send + Sync + Unpin>,
    ),
    GenericError,
>
where
    S: Spawn + Clone + Send + Sync + 'static,
    S::Error: 'static,
{
    let tempdir = tempfile::tempdir()?;
    let mut socket = PathBuf::from(tempdir.path());
    socket.push("socket");
    let stream = UnixListener::bind(&socket).await?;
    let (server, mut progress) = BridgeServer::new(spawn.clone());
    let up_key = server.up.key;
    let down_key = server.down.key;
    let up = server.up_id.clone();
    let down = server.down_id.clone();
    let server = Arc::pin(server);
    let service = wire::bridge_server::BridgeServer::new(Pin::clone(&server));
    let (incoming_tx, incoming) = channel(4096);
    let accept = async move {
        let incoming = stream.incoming();
        incoming
            .for_each_concurrent(32, |stream| {
                let incoming = incoming_tx.clone();
                async move {
                    incoming.send(stream).await;
                }
            })
            .await
    }
    .fuse();
    let service = Server::builder()
        .add_service(service)
        .serve_with_incoming(incoming.map_ok(UnixStreamCompat))
        .then(|r| async move {
            if let Err(e) = r {
                error!("unix bridge: {}", e)
            }
        });
    let service = spawn
        .spawn(service)
        .unwrap_or_else(|e| error!("bridge: service: {:?}", e))
        .fuse();
    let id = BridgeId { up, down };
    let params = UnixParams {
        addr: socket,
        id: id.clone(),
        up: up_key,
        down: down_key,
    };
    let progress = async move {
        loop {
            select_biased! {
                _ = progress.next().fuse() => (),
                _ = sleep(Duration::new(300, 0)).fuse() => break,
            }
        }
    }
    .fuse();
    let service = async move {
        let _tempdir = tempdir;
        pin_mut!(progress, service, accept);
        select_biased! {
            _ = progress => (),
            _ = service => (),
            _ = accept => (),
        }
    };
    Ok((
        id,
        params,
        Box::new(Box::pin(service) as Pin<Box<dyn Future<Output = ()> + Send + Sync>>),
    ))
}

struct UnixStreamCompat(UnixStream);

impl Connected for UnixStreamCompat {}

impl TokioAsyncRead for UnixStreamCompat {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl TokioAsyncWrite for UnixStreamCompat {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        AsyncStdWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        AsyncStdWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

struct TcpStreamCompat(TcpStream);

impl Connected for TcpStreamCompat {}

impl TokioAsyncRead for TcpStreamCompat {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl TokioAsyncWrite for TcpStreamCompat {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        AsyncStdWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        AsyncStdWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

pub struct GrpcBridge;

#[derive(Error, Debug)]
pub enum Error {
    #[error("transport: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("uri: {0}")]
    Uri(#[from] http::Error),
    #[error("net: {0}, backtrace: {1:?}")]
    Net(Status, Bt),
    #[error("codec: {0}, backtrace: {1:?}")]
    Codec(GenericError, Bt),
    #[error("broken pipe: {0:?}")]
    Pipe(Bt),
    #[error("malformed, backtrace: {0:?}")]
    Malformed(Bt),
    #[error("crypto: {0:?}, backtrace: {1:?}")]
    Crypto(aead::Error, Bt),
    #[error("io: {0}")]
    Io(std::io::Error),
    #[error("other: {0:?}")]
    Other(GenericError),
}

#[derive(Error, Debug)]
#[error("{0:?}")]
pub struct GrpcBridgeError(pub Vec<Error>);

async fn grpc_bridge_client<G, S>(
    mut message_sink: StdSender<wire::RawBridgeMessage>,
    message_stream: impl 'static
        + Send
        + Sync
        + Unpin
        + Stream<Item = Result<wire::RawBridgeMessage, Error>>,
    up: String,
    down: String,
    key: [u8; 32],
    spawn: &S,
) -> Result<Bridge<G>, Error>
where
    G: 'static + Guard<BridgeMessage, ()>,
    GenericError: From<G::Error>,
    S: Spawn + Send + Sync + 'static,
    S::Error: 'static,
{
    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut nonce);
    message_sink
        .send(wire::RawBridgeMessage {
            variant: Some(wire::raw_bridge_message::Variant::Id(wire::RawBridgeId {
                id: Some(wire::BridgeId { up, down }),
                nonce: nonce.to_vec(),
            })),
        })
        .await
        .map_err(|e| {
            error!("broken pipe: {}", e);
            Error::Pipe(<_>::default())
        })?;
    let aead = Arc::pin(ChaCha20Poly1305::new(GenericArray::from_slice(&key)));
    let nonce = Arc::pin(nonce);
    let (tx, message_sink_transform) = std_channel(4096);
    let poll = spawn
        .spawn(
            message_sink_transform
                .map({
                    let aead = Pin::clone(&aead);
                    let nonce = Pin::clone(&nonce);
                    move |m| {
                        trace!("bridge terminal: outgoing data");
                        let Pomerium { data, .. } = m;
                        let data = aead
                            .encrypt(GenericArray::from_slice(&nonce[..]), &data[..])
                            .map_err(|e| Error::Crypto(e, <_>::default()))?;
                        Ok(wire::RawBridgeMessage {
                            variant: Some(wire::raw_bridge_message::Variant::Raw(data)),
                        })
                    }
                })
                .try_for_each(move |m| {
                    let mut sink = message_sink.clone();
                    async move {
                        sink.send(m).await.map_err(|e| {
                            error!("broken pipe: {}", e);
                            Error::Pipe(<_>::default())
                        })
                    }
                })
                .unwrap_or_else(|e| error!("bridge: {}", e)),
        )
        .then(|r| async move {
            match r {
                Err(e) => {
                    error!("bridge: {:?}", e);
                }
                Ok(_) => (),
            }
        });
    let poll = Box::new(Box::pin(poll));
    let tx = Box::new(tx.sink_map_err(|e| Box::new(e) as GenericError));
    let rx = Box::new(Box::pin(
        message_stream
            .and_then(move |m| {
                let aead = Pin::clone(&aead);
                let nonce = Pin::clone(&nonce);
                async move {
                    match m {
                        wire::RawBridgeMessage {
                            variant: Some(wire::raw_bridge_message::Variant::Raw(data)),
                        } => {
                            trace!("bridge terminal: incoming data");
                            let data = aead
                                .decrypt(GenericArray::from_slice(&nonce[..]), &data[..])
                                .map_err(|e| Error::Crypto(e, <_>::default()))?;
                            Ok(Pomerium::from_raw(data))
                        }
                        _ => Err(Error::Malformed(<_>::default())),
                    }
                }
            })
            .map_err(|e| Box::new(e) as GenericError),
    ));
    Ok(Bridge { tx, rx, poll })
}

#[async_trait]
impl<G> ConstructibleBridge<G> for GrpcBridge
where
    G: 'static + Guard<BridgeMessage, ()>,
    GenericError: From<G::Error>,
{
    type Params = GrpcParams;
    type Error = Error;
    async fn build<S>(
        &self,
        id: &BridgeId,
        params: &Self::Params,
        half: BridgeHalf,
        spawn: S,
    ) -> Result<Bridge<G>, Self::Error>
    where
        S: Spawn + Send + Sync + 'static,
        S::Error: 'static,
    {
        let GrpcParams { addr, up, down, .. } = params;
        let mut errors = vec![];
        let try_bridge = |addr: SocketAddr| -> BoxFuture<Result<Bridge<G>, Error>> {
            let spawn = &spawn;
            async move {
                let uri = Uri::builder()
                    .scheme("http")
                    .authority(&addr.to_string() as &str)
                    .path_and_query("/")
                    .build()
                    .map_err(Error::Uri)?;
                let mut client = wire::bridge_client::BridgeClient::connect(uri)
                    .await
                    .map_err(Error::Transport)?;
                let (message_sink, bridge_in) = std_channel(4096);
                let bridge_out = client
                    .channel(Request::new(bridge_in.map(wire::RawBridgeMessage::from)))
                    .await
                    .map_err(|e| Error::Net(e, <_>::default()))?
                    .into_inner()
                    .map_err(|e| Error::Net(e, <_>::default()));
                match half {
                    BridgeHalf::Up => {
                        grpc_bridge_client(
                            message_sink,
                            bridge_out,
                            id.up.clone(),
                            id.down.clone(),
                            *up,
                            spawn,
                        )
                        .await
                    }
                    BridgeHalf::Down => {
                        grpc_bridge_client(
                            message_sink,
                            bridge_out,
                            id.down.clone(),
                            id.up.clone(),
                            *down,
                            spawn,
                        )
                        .await
                    }
                }
            }
            .boxed()
        };
        for addr in addr {
            match try_bridge(addr.clone()).await {
                Ok(bridge) => return Ok(bridge),
                Err(e) => errors.push(e),
            }
        }
        Err(Error::Other(Box::new(GrpcBridgeError(errors))))
    }
}

pub struct UnixBridge;

impl UnixBridge {
    async fn build_channel(params: &UnixParams) -> Result<Channel, Error> {
        let addr = params.addr.clone();
        let connector = tower::service_fn(move |_| {
            let addr = addr.clone();
            async move {
                UnixStream::connect(addr)
                    .await
                    .map_err(|e| Box::new(Error::Io(e)) as GenericError)
                    .map(UnixStreamCompat)
            }
        });
        Endpoint::try_from("uds://[::]:8888")
            .unwrap()
            .connect_with_connector(connector)
            .await
            .map_err(Error::Transport)
    }
}

#[async_trait]
impl<G> ConstructibleBridge<G> for UnixBridge
where
    G: 'static + Guard<BridgeMessage, ()>,
    GenericError: From<G::Error>,
{
    type Params = UnixParams;
    type Error = Error;
    async fn build<S>(
        &self,
        id: &BridgeId,
        params: &Self::Params,
        half: BridgeHalf,
        spawn: S,
    ) -> Result<Bridge<G>, Self::Error>
    where
        S: Spawn + Send + Sync + 'static,
        S::Error: 'static,
    {
        let UnixParams { up, down, .. } = params;
        let channel = Self::build_channel(params).await?;
        let mut client = wire::bridge_client::BridgeClient::new(channel);
        let (message_sink, bridge_in) = std_channel(4096);
        let bridge_out = client
            .channel(Request::new(bridge_in.map(wire::RawBridgeMessage::from)))
            .await
            .map_err(|e| Error::Net(e, <_>::default()))?
            .into_inner()
            .map_err(|e| Error::Net(e, <_>::default()));
        match half {
            BridgeHalf::Up => {
                grpc_bridge_client(
                    message_sink,
                    bridge_out,
                    id.up.clone(),
                    id.down.clone(),
                    *up,
                    &spawn,
                )
                .await
            }
            BridgeHalf::Down => {
                grpc_bridge_client(
                    message_sink,
                    bridge_out,
                    id.down.clone(),
                    id.up.clone(),
                    *down,
                    &spawn,
                )
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_cidr() {
        let addr = "192.168.11.1".parse().unwrap();
        let range = 23;
        let random = random_addr_from_cidr(&addr, range).unwrap();
        if let IpAddr::V4(addr) = random {
            println!("{}", addr);
            let addr = addr.octets();
            let actual: &BitSlice<Msb0, _> = BitSlice::from_slice(&addr);
            let expected: &BitSlice<Msb0, _> = BitSlice::from_slice(&[192u8, 168, 10, 0]);
            assert_eq!(actual[..range], expected[..range]);
        } else {
            panic!()
        }
    }
}
