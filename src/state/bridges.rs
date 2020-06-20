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
    pub(super) async fn handle_bridges<T>(
        self: Pin<Arc<Self>>,
        invite_cooldown: Duration,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
    ) -> Result<(), SessionError>
    where
        T: 'static + Send + Future<Output = ()>,
    {
        let mut last_invite = Instant::now() - Duration::new(10, 0);
        loop {
            trace!("{:?}: poll_bridges", self.role);
            let polls: Vec<_> = {
                self.bridge_polls
                    .read()
                    .await
                    .values()
                    .map(|(_, poll)| ClonableSendableFuture::clone_pin_box(&**poll))
                    .collect()
            };
            if polls.is_empty() {
                drop(polls);
                if let KeyExchangeRole::Boris = self.role {
                    // I am server. I don't ask clients to build bridges for me.
                    timeout_generator(Duration::new(1, 0)).await;
                    continue;
                }
                trace!("{:?}: poll_bridges: no bridges, inviting", self.role);
                let now = Instant::now();
                let duration_since = now.duration_since(last_invite);
                if duration_since > invite_cooldown {
                    self.as_ref().invite_bridge_proposal().await?;
                    last_invite = Instant::now();
                } else {
                    trace!(
                        "{:?}: poll_bridges: last invitation too recent, elapsed={:?}",
                        self.role,
                        duration_since
                    );
                    timeout_generator(Duration::new(1, 0)).await;
                    continue;
                }
            } else {
                let (bridge, _, _) = future::select_all(polls).await;
                trace!("{:?}: bridge: {:?} terminated", self.role, bridge);
                if let Some(kill_switch) = self.bridge_kill_switches.lock().await.remove(&bridge) {
                    let _ = kill_switch.send(());
                }
                self.bridge_polls.write().await.remove(&bridge);
                self.send_counter.counters.write().await.remove(&bridge);
                self.send_success_counter
                    .counters
                    .write()
                    .await
                    .remove(&bridge);
                self.receive_counter.counters.write().await.remove(&bridge);
            }
        }
    }
}
