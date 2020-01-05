use std::{collections::HashMap, convert::TryFrom, net::SocketAddr, pin::Pin, time::Duration};

use aes_gcm_siv::{
    aead::{Aead, NewAead},
    Aes256GcmSiv,
};
use async_std::{
    sync::{channel, Arc, Receiver, RwLock, Sender, Weak},
    task::sleep,
};
use failure::{Backtrace, Fail};
use futures::{prelude::*, select};
use generic_array::GenericArray;
use log::{error, info};
use prost::Message;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use crate::{
    state::{wire, BridgeMessage},
    utils::TryFutureStream,
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

#[derive(Default)]
pub struct BridgeServer {
    channels: RwLock<HashMap<String, BridgeChannel>>,
}

impl BridgeServer {
    async fn register(self: Pin<&Self>, id: String, key: [u8; 32]) {
        let mut channels = self.channels.write().await;
        let (send, recv) = channel(65536);
        channels.insert(id, BridgeChannel { key, send, recv });
    }

    async fn cancel(self: Pin<&Self>, id: &str) {
        self.channels.write().await.remove(id);
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
        let (id, mut nonce) = match request
            .next()
            .await
            .ok_or_else(|| Status::aborted("broken pipe"))??
        {
            wire::RawBridgeMessage {
                variant:
                    Some(wire::raw_bridge_message::Variant::Id(wire::RawBridgeId { id, nonce })),
            } => (id, nonce),
            _ => return Err(Status::aborted("connection reset")),
        };
        nonce.resize(12, 0);
        let nonce = nonce;
        let (up, down) = match id.splitn(2, '#').collect::<Vec<_>>()[..] {
            [up, down] => (up, down),
            _ => return Err(Status::aborted("invalid id")),
        };
        let (key, send, recv) = {
            let channels = self.channels.read().await;
            let BridgeChannel { key, send, .. } = channels
                .get(up)
                .ok_or_else(|| Status::aborted("connection reset"))?
                .clone();
            let recv = channels
                .get(down)
                .ok_or_else(|| Status::aborted("connection reset"))?
                .recv
                .clone();
            (key, send, recv)
        };
        let aead = Aes256GcmSiv::new(*GenericArray::from_slice(&key));
        let aead_ = aead.clone();
        let nonce_ = nonce.clone();
        let up = request.try_for_each_concurrent(32, move |m| {
            let aead = aead_.clone();
            let nonce = nonce_.clone();
            let send = send.clone();
            async move {
                match m {
                    wire::RawBridgeMessage {
                        variant: Some(wire::raw_bridge_message::Variant::Raw(m)),
                    } => {
                        let m = aead
                            .decrypt(GenericArray::from_slice(&nonce), &m[..])
                            .map_err(|e| {
                                error!("decrypt: {:?}", e);
                                Status::aborted("malformed data")})?;
                        let m = wire::BridgeMessage::decode(&m[..]).map_err(|e| {
                            error!("decode: {}", e);
                            Status::aborted("malformed data")
                        })?;
                        let m = BridgeMessage::try_from(m).map_err(|e| {
                            error!("transform: {}", e);
                            Status::aborted("malformed data")
                        })?;
                        Ok(send.send(m).await)
                    }
                    _ => Err(Status::aborted("malformed data")),
                }
            }
        });
        let down = recv.map(move |m| {
            let aead = aead.clone();
            let nonce = nonce.clone();
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

pub async fn bridge(addr: SocketAddr) -> Result<(), GenericError> {
    let server = Arc::pin(BridgeServer::default());
    let service = wire::bridge_server::BridgeServer::new(Pin::clone(&server));
    let mut service = Server::builder()
        .add_service(service)
        .serve(addr)
        .boxed()
        .fuse();
    // let mut cleanup = async {
    //     loop {
    //         sleep(Duration::new(30, 0)).await;
    //         server.as_ref().cleanup().await;
    //     }
    // }
    // .boxed()
    // .fuse();
    select! {
        r = service => r?,
    }
    Ok(())
}
