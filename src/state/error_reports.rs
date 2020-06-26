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
    pub(super) async fn handle_error_reports(
        self: Pin<&Self>,
        error_reports: Receiver<(u8, u64, HashSet<u8>)>,
        progress: Sender<()>,
    ) -> Result<(), SessionError> {
        error_reports
            .map(Ok)
            .try_for_each(|(stream, serial, errors)| {
                let mut progress = progress.clone();
                async move {
                    let recvs = {
                        if let Some(stream) = self.hall_of_fame.read().await.peek(&stream) {
                            if let Some(recvs) = stream.lock().await.pop(&serial) {
                                recvs
                            } else {
                                return Ok(());
                            }
                        } else {
                            return Ok(());
                        }
                    };
                    for bridge_id in recvs.into_iter().filter_map(|(id, bridge_id)| {
                        if errors.contains(&id) {
                            None
                        } else {
                            bridge_id
                        }
                    }) {
                        self.bridge_state.inc_recv_counter(bridge_id).await;
                    }
                    progress
                        .send(())
                        .await
                        .map_err(|e| SessionError::BrokenPipe(Box::new(e), <_>::default()))
                }
            })
            .await
    }
}
