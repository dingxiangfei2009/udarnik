use std::{
    convert::TryFrom,
    io::Result as IoResult,
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use aes_gcm_siv::{
    aead::{Aead, NewAead},
    Aes256GcmSiv,
};
use async_std::{
    io::{Read as AsyncStdRead, Write as AsyncStdWrite},
    net::{TcpListener, TcpStream},
    os::unix::net::{UnixListener, UnixStream},
    sync::{channel, Arc, Receiver, Sender},
    task::sleep,
};
use async_trait::async_trait;
use failure::{Backtrace, Fail};
use futures::{
    channel::mpsc::{channel as std_channel, Sender as StdSender},
    prelude::*,
    select,
};
use generic_array::GenericArray;
use http::Uri;
use log::error;
use prost::Message;
use rand::{rngs::OsRng, RngCore};
use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite};
use tonic::transport::{server::Connected, Endpoint, Server,Channel};
use tonic::{Request, Response, Status, Streaming};

use super::{BridgeHalf, ConstructibleBridge};

use crate::{
    state::{
        wire, Bridge, BridgeId, BridgeMessage, GrpcBridge as GrpcParams, Guard, Pomerium,
        UnixBridge as UnixParams,
    },
    utils::{SyncFuture, TryFutureStream},
    GenericError,
};

#[derive(Fail, Debug, From)]
pub enum BridgeServerError {
    #[fail(display = "broken pipe")]
    Pipe(Backtrace),
}

#[derive(Clone)]
pub struct BridgeChannel {
    key: [u8; 32],
    send: Sender<BridgeMessage>,
    recv: Receiver<BridgeMessage>,
}

impl BridgeChannel {
    pub fn new(key: [u8; 32]) -> Self {
        let (send, recv) = channel(65536);
        Self { key, send, recv }
    }
}

pub struct BridgeServer {
    up_id: String,
    down_id: String,
    up: BridgeChannel,
    down: BridgeChannel,
    progress: Sender<()>,
}

impl BridgeServer {
    fn new() -> (Self, Receiver<()>) {
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
            },
            progress,
        )
    }
}

#[tonic::async_trait]
impl wire::bridge_server::Bridge for Pin<Arc<BridgeServer>> {
    type ChannelStream =
        Pin<Box<dyn 'static + Send + Sync + Stream<Item = Result<wire::RawBridgeMessage, Status>>>>;
    async fn channel(
        &self,
        request: Request<Streaming<wire::RawBridgeMessage>>,
    ) -> Result<Response<Self::ChannelStream>, Status> {
        let request = request.into_inner();
        let mut request = Pin::from(Box::new(request)
            as Box<dyn Stream<Item = Result<wire::RawBridgeMessage, Status>> + Send + Sync>);
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
        let aead = Arc::pin(Aes256GcmSiv::new(*GenericArray::from_slice(&key)));
        let aead_ = Pin::clone(&aead);
        let nonce_ = Pin::clone(&nonce);
        let progress = self.progress.clone();
        let up = request.try_for_each_concurrent(32, move |m| {
            let aead = Pin::clone(&aead_);
            let nonce = Pin::clone(&nonce_);
            let send = send.clone();
            let progress = progress.clone();
            async move {
                match m {
                    wire::RawBridgeMessage {
                        variant: Some(wire::raw_bridge_message::Variant::Raw(m)),
                    } => {
                        let m = aead
                            .decrypt(GenericArray::from_slice(&nonce), &m[..])
                            .map_err(|e| {
                                error!("decrypt: {:?}", e);
                                Status::aborted("malformed data")
                            })?;
                        let m = wire::BridgeMessage::decode(&m[..]).map_err(|e| {
                            error!("decode: {}", e);
                            Status::aborted("malformed data")
                        })?;
                        let m = BridgeMessage::try_from(m).map_err(|e| {
                            error!("transform: {}", e);
                            Status::aborted("malformed data")
                        })?;
                        send.send(m).await;
                        Ok(progress.send(()).await)
                    }
                    _ => Err(Status::aborted("malformed data")),
                }
            }
        });
        let progress = self.progress.clone();
        let down = recv
            .map(move |m| {
                let aead = Pin::clone(&aead);
                let nonce = Pin::clone(&nonce);
                let progress = progress.clone();
                async move {
                    let m = wire::BridgeMessage::from(m);
                    let mut v = vec![];
                    m.encode(&mut v).map_err(|e| {
                        error!("encode: {}", e);
                        Status::aborted("malformed data")
                    })?;
                    let m = aead
                        .encrypt(GenericArray::from_slice(&nonce), &v[..])
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
            .buffer_unordered(32);

        Ok(Response::new(Box::pin(TryFutureStream {
            complete: Some(Box::new(Box::pin(up))),
            stream: Some(Box::new(down)),
        })))
    }
}

pub async fn bridge() -> Result<
    (
        BridgeId,
        GrpcParams,
        Box<dyn Future<Output = ()> + Send + Sync + Unpin>,
    ),
    GenericError,
> {
    let stream = TcpListener::bind("[::]:0").await?;
    let addr = stream.local_addr()?;
    let (server, mut progress) = BridgeServer::new();
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
        .then(|r| {
            async move {
                if let Err(e) = r {
                    error!("unix bridge: {}", e)
                }
            }
        });
    let service = SyncFuture::new(Box::pin(service) as Pin<Box<dyn Future<Output = ()> + Send>>);
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
            select! {
                _ = progress.next().fuse() => (),
                _ = sleep(Duration::new(300, 0)).fuse() => break,
            }
        }
    };
    let progress = Box::pin(progress) as Pin<Box<dyn Future<Output = ()> + Send + Sync>>;
    let mut progress = progress.fuse();
    let service = async move {
        select! {
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

#[cfg(target_family = "unix")]
pub async fn bridge_uds() -> Result<
    (
        BridgeId,
        UnixParams,
        Box<dyn Future<Output = ()> + Send + Sync + Unpin>,
    ),
    GenericError,
> {
    let tempdir = tempfile::tempdir()?;
    let mut socket = PathBuf::from(tempdir.path());
    socket.push("socket");
    let stream = UnixListener::bind(&socket).await?;
    let (server, mut progress) = BridgeServer::new();
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
        .serve_with_incoming(incoming.map_ok(UnixStreamCompat))
        .then(|r| {
            async move {
                if let Err(e) = r {
                    error!("unix bridge: {}", e)
                }
            }
        });
    let service = SyncFuture::new(Box::pin(service) as Pin<Box<dyn Future<Output = ()> + Send>>);
    let service = Box::pin(service) as Pin<Box<dyn Future<Output = ()> + Send + Sync>>;
    let mut service = service.fuse();
    let id = BridgeId { up, down };
    let params = UnixParams  {
        addr: socket,
        id: id.clone(),
        up: up_key,
        down: down_key,
    };
    let progress = async move {
        loop {
            select! {
                _ = progress.next().fuse() => (),
                _ = sleep(Duration::new(300, 0)).fuse() => break,
            }
        }
    };
    let progress = Box::pin(progress) as Pin<Box<dyn Future<Output = ()> + Send + Sync>>;
    let mut progress = progress.fuse();
    let service = async move {
        let _tempdir = tempdir;
        select! {
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

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "transport: {}", _0)]
    Transport(#[cause] tonic::transport::Error),
    #[fail(display = "uri: {}", _0)]
    Uri(#[cause] http::Error),
    #[fail(display = "net: {}", _0)]
    Net(Status, Backtrace),
    #[fail(display = "codec: {}", _0)]
    Codec(GenericError, Backtrace),
    #[fail(display = "broken pipe: {}", _0)]
    Pipe(Backtrace),
    #[fail(display = "malformed: {}", _0)]
    Malformed(Backtrace),
    #[fail(display = "crypto: {:?}", _0)]
    Crypto(aead::Error, Backtrace),
    #[fail(display = "io: {}", _0)]
    Io(std::io::Error),
}

impl From<Error> for GenericError {
    fn from(e: Error) -> Self {
        Box::new(e.compat())
    }
}

async fn grpc_bridge_client<G>(
    mut message_sink: StdSender<wire::RawBridgeMessage>,
    message_stream: impl 'static
        + Send
        + Sync
        + Unpin
        + Stream<Item = Result<wire::RawBridgeMessage, Error>>,
    up: String,
    down: String,
    key: [u8; 32],
) -> Result<Bridge<G>, Error>
where
    G: 'static + Guard<BridgeMessage, ()>,
    GenericError: From<G::Error>,
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
    let aead = Arc::pin(Aes256GcmSiv::new(*GenericArray::from_slice(&key)));
    let nonce = Arc::pin(nonce);
    let (tx, message_sink_transform) = std_channel(4096);
    let poll = Box::new(Box::pin(
        message_sink_transform
            .map({
                let aead = Pin::clone(&aead);
                let nonce = Pin::clone(&nonce);
                move |m| {
                    let Pomerium { data, .. } = m;
                    let data = aead
                        .encrypt(GenericArray::from_slice(&nonce[..]), &data[..])
                        .map_err(|e| Error::Crypto(e, <_>::default()))?;
                    Ok(wire::RawBridgeMessage {
                        variant: Some(wire::raw_bridge_message::Variant::Raw(data)),
                    })
                }
            })
            .try_for_each_concurrent(4096, move |m| {
                let mut sink = message_sink.clone();
                async move {
                    sink.send(m).await.map_err(|e| {
                        error!("broken pipe: {}", e);
                        Error::Pipe(<_>::default())
                    })
                }
            })
            .unwrap_or_else(|e| error!("bridge: {}", e)),
    ));
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
                            let data = aead
                                .decrypt(GenericArray::from_slice(&nonce[..]), &data[..])
                                .map_err(|e| Error::Crypto(e, <_>::default()))?;
                            Ok(Pomerium::from_raw(data))
                        }
                        _ => Err(Error::Malformed(<_>::default())),
                    }
                }
            })
            .map_err(|e| Box::new(e.compat()) as GenericError),
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
    async fn build(
        &self,
        id: &BridgeId,
        params: &Self::Params,
        half: BridgeHalf,
    ) -> Result<Bridge<G>, Self::Error> {
        let GrpcParams { addr, up, down, .. } = params;
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
                )
                .await
            }
        }
    }
}

pub struct UnixBridge;

impl UnixBridge {
    async fn build_channel(params: &UnixParams) -> Result<Channel, Error> {
        let addr = params.addr.clone();
        let connector = tower::service_fn(move |_| {
            let addr = addr.clone();
            async move {
                UnixStream::connect(addr).await.map_err(Error::Io).map(UnixStreamCompat)
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
    async fn build(
        &self,
        id: &BridgeId,
        params: &Self::Params,
        half: BridgeHalf,
    ) -> Result<Bridge<G>, Self::Error> {
        let UnixParams { addr, up, down, .. } = params;
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
                )
                .await
            }
        }
    }
}
