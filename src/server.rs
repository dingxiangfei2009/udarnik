use std::{pin::Pin, sync::Arc, net::SocketAddr};

use async_std::sync::RwLock;
use tonic::{Request, Response, Streaming};

use crate::state::{Session, SessionId, protocol::server_server::Server};

pub struct UdarnikServer<G> {
    sessions: Pin<Arc<RwLock<HashMap<SessionId, Session>>>>,
}

#[tonic::async_trait]
impl<G> Server for UdarnikServer<G> {
    async fn key_exchange(&self, request: Streaming<Message<G>>) -> Result<> {
        
    }
//     type KeyExchangeStream: BoxStream<'static, Item = Message>
}

pub async fn server(addr: SocketAddr) {}
