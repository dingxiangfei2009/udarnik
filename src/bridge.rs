use async_trait::async_trait;

pub mod grpc;

use crate::state::{Bridge, BridgeId};

#[derive(PartialEq, Eq, Clone, Copy, Hash)]
pub enum BridgeHalf {
    Up,
    Down,
}

#[async_trait]
pub trait ConstructibleBridge<G> {
    type Params;
    type Error;
    async fn build(
        &self,
        id: &BridgeId,
        params: &Self::Params,
        half: BridgeHalf,
    ) -> Result<Bridge<G>, Self::Error>;
}
