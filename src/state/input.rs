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
    pub(super) async fn handle_input(&self, input: Receiver<Vec<u8>>) -> Result<(), SessionError> {
        let stream_state = Pin::clone(&self.stream_state);
        input
            .map(Ok)
            .try_for_each_concurrent(4096, {
                move |input| {
                    let ss = Pin::clone(&stream_state);
                    async move { ss.send(input).await }
                }
            })
            .await
    }
}
