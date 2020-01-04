use std::{
    collections::HashMap,
    convert::TryFrom,
    net::SocketAddr,
    pin::Pin,
    time::Duration,
};

use async_std::{
    sync::{channel, Arc, Receiver, RwLock, Sender, Weak},
    task::sleep,
};
use failure::{Backtrace, Fail};
use futures::{prelude::*, select};
use log::{error, info};
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

#[derive(Default)]
pub struct BridgeServer {
    channels: RwLock<HashMap<String, Weak<(Sender<BridgeMessage>, Receiver<BridgeMessage>)>>>,
}

impl BridgeServer {
    async fn register(
        self: Pin<&Self>,
        id: String,
    ) -> Arc<(Sender<BridgeMessage>, Receiver<BridgeMessage>)> {
        let mut channels = self.channels.write().await;
        if let Some(pair) = channels.get(&id).and_then(Weak::upgrade) {
            pair
        } else {
            let pair = Arc::new(channel(65536));
            channels.insert(id.clone(), Arc::downgrade(&pair));
            pair
        }
    }
    async fn cleanup(self: Pin<&Self>) {
        let mut channels = self.channels.write().await;
        let survivals = channels
            .drain()
            .filter_map(|(id, pair)| pair.upgrade().map(move |p| (id, Arc::downgrade(&p))))
            .collect();
        *channels = survivals;
    }
}

#[tonic::async_trait]
impl wire::bridge_server::Bridge for Pin<Arc<BridgeServer>> {
    type ChannelStream =
        Pin<Box<dyn 'static + Send + Sync + Stream<Item = Result<wire::BridgeMessage, Status>>>>;
    async fn channel(
        &self,
        request: Request<Streaming<wire::BridgeMessage>>,
    ) -> Result<Response<Self::ChannelStream>, Status> {
        let request = request.into_inner().and_then(|m| {
            async { BridgeMessage::try_from(m).map_err(|e| Status::aborted(format!("{}", e))) }
        });
        let mut request = Pin::from(Box::new(request)
            as Box<dyn Stream<Item = Result<BridgeMessage, Status>> + Send + Sync>);
        if let BridgeMessage::Id(id) = request
            .next()
            .await
            .ok_or_else(|| Status::aborted("broken pipe"))??
        {
            let (up, down) = match id.splitn(2, '#').collect::<Vec<_>>()[..] {
                [up, down] => (up, down),
                _ => return Err(Status::aborted("invalid id")),
            };
            let (up, _up_pair) =
                if let Some(up_pair) = self.channels.read().await.get(up).and_then(Weak::upgrade) {
                    (up_pair.0.clone(), up_pair)
                } else {
                    let up_pair = self.as_ref().register(up.to_string()).await;
                    (up_pair.0.clone(), up_pair)
                };
            let (down, _down_pair) = if let Some(down_pair) =
                self.channels.read().await.get(down).and_then(Weak::upgrade)
            {
                (down_pair.1.clone(), down_pair)
            } else {
                let down_pair = self.as_ref().register(down.to_string()).await;
                (down_pair.1.clone(), down_pair)
            };
            let down = Box::new(down.map(wire::BridgeMessage::from).map(Ok));
            let stream = TryFutureStream {
                complete: Some(Box::new(Box::pin(request.try_for_each_concurrent(
                    32,
                    move |m| {
                        let up = up.clone();
                        async move { Ok(up.clone().send(m).await) }
                    },
                )))),
                stream: Some(down),
            };
            Ok(Response::new(Box::pin(stream)))
        } else {
            Err(Status::aborted("malformed stream"))
        }
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
    let mut cleanup = async {
        loop {
            sleep(Duration::new(30, 0)).await;
            server.as_ref().cleanup().await;
        }
    }
    .boxed()
    .fuse();
    select! {
        r = service => r?,
        _ = cleanup => (),
    }
    Ok(())
}
