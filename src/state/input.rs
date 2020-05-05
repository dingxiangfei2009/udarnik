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
    pub(super) async fn handle_input(
        self: Pin<&Self>,
        input: Receiver<Vec<u8>>,
    ) -> Result<(), SessionError> {
        input
            .map(Ok)
            .try_for_each({
                |input| async move {
                    let mut input_tx = {
                        let stream_polls = StreamExists {
                            session: self.as_ref().get_ref(),
                            stream_polls: None,
                            key: None,
                        }
                        .await;
                        if let Some((_, (session_stream, _))) =
                            stream_polls.iter().choose(&mut StdRng::from_entropy())
                        {
                            session_stream.input_tx.clone()
                        } else {
                            trace!(
                                "{:?}: no usable stream, but this might not correct",
                                self.role
                            );
                            return Ok(());
                        }
                    };
                    input_tx
                        .send(input)
                        .await
                        .map_err(|e| SessionError::BrokenPipe(Box::new(e), <_>::default()))?;
                    Ok::<_, SessionError>(())
                }
            })
            .await
    }
}

struct StreamExists<'a, G> {
    session: &'a Session<G>,
    stream_polls: Option<BoxFuture<'a, RwLockReadGuard<'a, StreamPolls>>>,
    key: Option<usize>,
}

impl<'a, G> Future for StreamExists<'a, G> {
    type Output = RwLockReadGuard<'a, StreamPolls>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use Poll::*;
        if let None = self.stream_polls {
            self.stream_polls = Some(self.session.stream_polls.read().boxed());
        }
        if let Some(mut stream_polls) = self.stream_polls.take() {
            match Pin::new(&mut stream_polls).poll(cx) {
                Ready(stream_polls) => {
                    if !stream_polls.is_empty() {
                        self.session
                            .stream_polls_waker_queue
                            .deregister_poll_waker(self.key);
                        return Ready(stream_polls);
                    } else {
                        self.stream_polls = Some(self.session.stream_polls.read().boxed());
                    }
                }
                Pending => {
                    self.stream_polls = Some(stream_polls);
                }
            }
        } else {
            unreachable!()
        }
        self.key = self
            .session
            .stream_polls_waker_queue
            .register_poll_waker(self.key, cx.waker().clone());
        Pending
    }
}
