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
    pub(super) async fn handle_bridges_out<T: 'static + Send + Future<Output = ()>>(
        self: Pin<&Self>,
        bridges_out_rx: Receiver<BridgeMessage>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
    ) -> Result<(), String> {
        bridges_out_rx
            .map(Ok::<_, String>)
            .try_for_each_concurrent(4096, {
                let timeout_generator = timeout_generator.clone();
                move |outbound| {
                    let timeout_generator = timeout_generator.clone();
                    async move {
                        let mut rng = StdRng::from_entropy();
                        let (bridge_id, mut tx) = loop {
                            trace!("{:?}: bridges_out: find usable bridge", self.role);
                            let bridges_out = self.bridges_out.read().await;
                            if let Some((bridge_id, bridge)) = bridges_out.iter().choose(&mut rng) {
                                debug!(
                                    "{:?}: bridges_out: choose bridge {:?}",
                                    self.role, bridge_id
                                );
                                break (bridge_id.clone(), ClonableSink::clone_pin_box(&**bridge));
                            } else {
                                drop(bridges_out);
                                timeout_generator(Duration::new(1, 0)).await;
                            }
                        };
                        match tx.send(outbound).await {
                            Err(e) => error!("{:?}: bridges_out: {}", self.role, e),
                            _ => debug!("{:?}: bridges_out: sent to {:?}", self.role, bridge_id),
                        }
                        if let Some(counter) =
                            self.send_counter.counters.read().await.get(&bridge_id)
                        {
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
                }
            })
            .await
    }
}
