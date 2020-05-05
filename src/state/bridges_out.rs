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
    pub(super) async fn handle_bridges_out(
        self: Pin<&Self>,
        bridges_out_rx: Receiver<BridgeMessage>,
    ) -> Result<(), String> {
        bridges_out_rx
            .map(Ok::<_, String>)
            .try_for_each({
                move |outbound| async move {
                    let mut rng = StdRng::from_entropy();
                    let (bridge_id, mut tx) = {
                        trace!("{:?}: bridges_out: find usable bridge", self.role);
                        let bridge_polls = BridgeExists {
                            session: self.as_ref().get_ref(),
                            bridge_polls: None,
                            key: None,
                        }
                        .await;
                        if let Some((bridge_id, (bridge, _))) = bridge_polls.iter().choose(&mut rng)
                        {
                            debug!(
                                "{:?}: bridges_out: choose bridge {:?}",
                                self.role, bridge_id
                            );
                            (bridge_id.clone(), ClonableSink::clone_pin_box(&**bridge))
                        } else {
                            trace!(
                                "{:?}: no usable bridge, but this might not correct",
                                self.role
                            );
                            return Ok(());
                        }
                    };
                    match tx.send(outbound).await {
                        Err(e) => error!("{:?}: bridges_out: {}", self.role, e),
                        _ => debug!("{:?}: bridges_out: sent to {:?}", self.role, bridge_id),
                    }
                    if let Some(counter) = self.send_counter.counters.read().await.get(&bridge_id) {
                        counter.fetch_add(1, Ordering::Relaxed);
                        debug!(
                            "{:?}: bridges_out: {:?} send counter updated",
                            self.role, bridge_id
                        );
                        return Ok(());
                    }
                    self.send_counter
                        .counters
                        .write()
                        .await
                        .entry(bridge_id.clone())
                        .or_default()
                        .fetch_add(1, Ordering::Relaxed);
                    debug!(
                        "{:?}: bridges_out: {:?} send counter initialized",
                        self.role, bridge_id
                    );
                    Ok(())
                }
            })
            .await
    }
}

struct BridgeExists<'a, G> {
    session: &'a Session<G>,
    bridge_polls: Option<BoxFuture<'a, RwLockReadGuard<'a, BridgePolls>>>,
    key: Option<usize>,
}

impl<'a, G> Future for BridgeExists<'a, G> {
    type Output = RwLockReadGuard<'a, BridgePolls>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use Poll::*;
        let mut bridge_polls = self
            .bridge_polls
            .take()
            .unwrap_or_else(|| self.session.bridge_polls.read().boxed());
        match Pin::new(&mut bridge_polls).poll(cx) {
            Ready(bridge_polls) => {
                if !bridge_polls.is_empty() {
                    self.session
                        .bridge_polls_waker_queue
                        .deregister_poll_waker(self.key);
                    Ready(bridge_polls)
                } else {
                    self.key = self
                        .session
                        .bridge_polls_waker_queue
                        .register_poll_waker(self.key, cx.waker().clone());
                    Pending
                }
            }
            Pending => {
                self.bridge_polls = Some(bridge_polls);
                Pending
            }
        }
    }
}
