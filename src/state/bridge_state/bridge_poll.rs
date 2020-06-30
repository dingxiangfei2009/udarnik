use super::*;

impl BridgeState {
    pub(super) async fn bridge_poll<T>(
        self: Pin<Arc<Self>>,
        invite_cooldown: Duration,
        mut bridge_invitation_trigger: Sender<()>,
        mut poll_rx: Receiver<Box<dyn Send + Sync + ClonableSendableFuture<BridgeId> + Unpin>>,
        timeout_generator: impl 'static + Send + Sync + Fn(Duration) -> T,
    ) -> Result<(), SessionError>
    where
        T: 'static + Send + Future<Output = ()>,
    {
        let mut polls = FuturesUnordered::new();
        loop {
            info!("poll_bridges: polling");
            select_biased! {
                id = polls.next() => {
                    if let Some(id) = id {
                        info!("bridge_poll: {:?} dies", id);
                        self.bridge_sinks.write().await.remove(&id);
                        if let Some(kill_switch) = self.kill_switches.lock().await.remove(&id) {
                            let _ = kill_switch.send(());
                        }
                        self.send_counter.counters.write().await.remove(&id);
                        self.send_success_counter
                            .counters
                            .write()
                            .await
                            .remove(&id);
                        self.receive_counter.counters.write().await.remove(&id);
                        continue;
                    }
                    select_biased! {
                        poll = poll_rx.next() => {
                            info!("poll_bridges: new bridge");
                            if let Some(poll) = poll {
                                polls.push(poll);
                            } else {
                                break
                            }
                        }
                        _ = timeout_generator(invite_cooldown).fuse() => {
                            info!("poll_bridges: no bridges, inviting");
                            bridge_invitation_trigger
                                .send(())
                                .await
                                .map_err(|e| {
                                    SessionError::BrokenPipe(Box::new(e) as GenericError, Bt::new())
                                })?;
                        },
                    }
                }
                poll = poll_rx.next() => {
                    info!("poll_bridges: new bridge");
                    if let Some(poll) = poll {
                        polls.push(poll);
                    } else {
                        break;
                    }
                }
            }
        }
        Ok(())
    }
}
