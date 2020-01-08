use async_trait::async_trait;

pub mod grpc;

use crate::{
    state::{Bridge, BridgeId},
    utils::Spawn,
};

#[derive(PartialEq, Eq, Clone, Copy, Hash)]
pub enum BridgeHalf {
    Up,
    Down,
}

#[async_trait]
pub trait ConstructibleBridge<G> {
    type Params;
    type Error;
    async fn build<S>(
        &self,
        id: &BridgeId,
        params: &Self::Params,
        half: BridgeHalf,
        spawn: S,
    ) -> Result<Bridge<G>, Self::Error>
    where
        S: Spawn + Send + Sync + 'static,
        S::Error: 'static;
}
