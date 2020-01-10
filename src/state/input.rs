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
    pub(super) async fn handle_input<T: 'static + Send + Future<Output = ()>>(
        self: Pin<&Self>,
        input: Receiver<Vec<u8>>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
    ) -> Result<(), SessionError> {
        input
            .map(Ok)
            .try_for_each_concurrent(2, {
                |input| {
                    let timeout_generator = timeout_generator.clone();
                    async move {
                        let mut input_tx = loop {
                            trace!("{:?}: find usable stream", self.role);
                            let stream_polls = self.stream_polls.read().await;
                            if let Some((_, (session_stream, _))) =
                                stream_polls.iter().choose(&mut StdRng::from_entropy())
                            {
                                break session_stream.input_tx.clone();
                            } else {
                                // explicit drop
                                drop(stream_polls);
                                timeout_generator(Duration::new(1, 0)).await;
                            }
                        };
                        input_tx.send(input).await
                    }
                }
            })
            .await
            .map_err(|e| SessionError::BrokenPipe(Box::new(e), <_>::default()))
    }
}
