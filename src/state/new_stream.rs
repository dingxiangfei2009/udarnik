use super::*;

impl<G> Session<G>
where
    G: 'static
        + Send
        + Sync
        + for<'a> From<&'a [u8]>
        + Guard<ClientMessageVariant, (SessionId, u64), Error = GenericError>
        + Guard<BridgeMessage, (), Error = GenericError>,
{
    pub(super) async fn new_stream<T, S>(
        &self,
        stream: u8,
        window: usize,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
        spawn: S,
    ) -> Result<(), SessionError>
    where
        T: 'static + Send + Future<Output = ()>,
        S: Spawn + Clone + Send + Sync + 'static,
        S::Error: 'static,
    {
        let mut shard_state = ShardState::default();
        for chunk in sha3::Sha3_512::digest(&self.session_key).chunks(32) {
            for (s, c) in chunk.iter().zip(shard_state.key.iter_mut()) {
                *c ^= s
            }
        }
        for chunk in sha3::Sha3_512::new()
            .chain(&self.session_key)
            .chain(b", stream=")
            .chain(&[stream])
            .finalize()
            .chunks(32)
        {
            for (s, c) in chunk.iter().zip(shard_state.stream_key.iter_mut()) {
                *c ^= s
            }
        }
        self.stream_state
            .new_stream(stream, window, shard_state, timeout_generator, spawn)
            .await
    }
}
