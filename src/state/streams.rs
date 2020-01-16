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
    pub(super) async fn handle_streams<T>(
        self: Pin<&Self>,
        bridges_out_tx: Sender<BridgeMessage>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
        spawn: impl Spawn + Clone + Send + Sync + 'static,
    ) -> Result<(), SessionError>
    where
        T: 'static + Send + Future<Output = ()>,
    {
        let mut rng = StdRng::from_entropy();
        loop {
            let polls: Vec<_> = {
                self.stream_polls
                    .read()
                    .await
                    .iter()
                    .map(|(stream, (_, polls))| {
                        let stream: u8 = *stream;
                        info!("{:?}: stream {} is open", self.role, stream);
                        let polls = ClonableSendableFuture::clone_pin_box(&**polls);
                        polls.map(move |_| stream).boxed()
                    })
                    .collect()
            };
            if polls.is_empty() {
                let stream = rng.next_u32() as u8;
                info!(
                    "{:?}: reset stream {} since there is no stream",
                    self.role, stream
                );
                let (session_stream, poll) = self.as_ref().get_ref().new_stream(
                    stream,
                    self.params.window,
                    bridges_out_tx.clone(),
                    timeout_generator.clone(),
                    spawn.clone(),
                );
                {
                    self.stream_polls
                        .write()
                        .await
                        .insert(stream, (session_stream, Box::pin(poll.shared())));
                }
                info!(
                    "{:?}: notify remote that stream {} is reset",
                    self.role, stream
                );
                self.as_ref().reset_remote_stream(stream).await?;
                self.stream_polls_waker_queue.try_notify_all();
            } else {
                let (stream, _, _) = future::select_all(polls).await;
                info!("{:?}: stream {} terminated", self.role, stream);
                self.stream_polls.write().await.remove(&stream);
            }
        }
    }
}
