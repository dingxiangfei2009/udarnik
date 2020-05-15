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
    pub(super) async fn handle_master_messages<T>(
        self: Pin<Arc<Self>>,
        mut master_messages: Receiver<Message<G>>,
        bridges_in_tx: Sender<(BridgeId, BridgeMessage)>,
        bridges_out_tx: Sender<BridgeMessage>,
        mut progress: Sender<()>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
        spawn: impl Spawn + Clone + Send + Sync + 'static,
    ) -> Result<(), SessionError>
    where
        T: 'static + Send + Future<Output = ()>,
    {
        while let Some(message) = master_messages.next().await {
            let ClientMessage {
                serial,
                session,
                variant,
            } = match message {
                Message::Client(m) => m,
                _ => {
                    info!("unknown message, ignored");
                    continue;
                }
            };
            trace!("{:?}: incoming client message", self.role);

            let tag = (session.clone(), serial);
            let variant = match variant.decode_with_tag(&self.inbound_guard, &tag) {
                Ok(v) => v,
                Err(e) => {
                    error!("decode error: {}", e);
                    continue;
                }
            };

            // Message can be valid but old.
            if let Err(local_serial) = self.assert_valid_serial(serial) {
                info!(
                    "{:?}: outdated serial, should be at least {}",
                    self.role, local_serial
                );
                self.as_ref().notify_serial(local_serial, true).await?;
                continue;
            }

            match variant {
                ClientMessageVariant::BridgeNegotiate(negotiation) => {
                    trace!("{:?}: incoming bridge negotiation message", self.role);
                    match negotiation {
                        BridgeNegotiationMessage::ProposeAsk => {
                            info!("{:?}: peer wants new bridges", self.role);
                            self.as_ref().answer_ask_proposal(spawn.clone()).await?
                        }
                        BridgeNegotiationMessage::Ask(proposals) => {
                            info!("{:?}: peer wants new bridge rendevous", self.role);
                            Pin::clone(&self)
                                .apply_proposal(proposals, bridges_in_tx.clone(), spawn.clone())
                                .await;
                        }
                        BridgeNegotiationMessage::Retract(bridges_) => {
                            info!("{:?}: peer wants to tear down bridges", self.role);
                            {
                                let mut bridge_polls = self.bridge_polls.write().await;
                                for BridgeRetract(id) in &bridges_ {
                                    bridge_polls.remove(id);
                                }
                            }
                            for BridgeRetract(id) in bridges_ {
                                self.bridge_builder.kill(&id).await;
                            }
                        }
                        BridgeNegotiationMessage::AskProposal(proposals) => {
                            info!("{:?}: peer sends some bridge proposals", self.role);
                            let asks = Pin::clone(&self)
                                .apply_proposal(proposals, bridges_in_tx.clone(), spawn.clone())
                                .await;
                            self.as_ref().ask_bridge(asks).await?
                        }
                        BridgeNegotiationMessage::QueryHealth => {
                            info!("{:?}: peer queries bridge health", self.role);
                            self.as_ref().answer_bridge_health_query().await?
                        }
                        BridgeNegotiationMessage::Health(health) => {
                            info!("{:?}: peer answers bridge health", self.role);
                            let mut counters = self.send_success_counter.counters.write().await;
                            for (id, count) in health {
                                counters
                                    .entry(id)
                                    .or_default()
                                    .fetch_add(count, Ordering::Relaxed);
                            }
                        }
                    }
                }
                ClientMessageVariant::Stream(request) => match request {
                    StreamRequest::Reset { stream, window } => {
                        info!("{:?}: peer resets stream {}", self.role, stream,);
                        let (session_stream, poll) = self.new_stream(
                            stream,
                            window,
                            bridges_out_tx.clone(),
                            progress.clone(),
                            timeout_generator.clone(),
                            spawn.clone(),
                        );
                        {
                            self.stream_polls
                                .write()
                                .await
                                .insert(stream, (session_stream, Box::pin(poll.shared())));
                        }
                        info!("{:?}: stream {}: reset", self.role, stream);
                        self.stream_polls_waker_queue.try_notify_all();
                    }
                },
                ClientMessageVariant::Ok | ClientMessageVariant::Err => {
                    trace!("{:?}: peer answers", self.role);
                    self.update_remote_serial(serial);
                    progress
                        .send(())
                        .await
                        .map_err(|e| SessionError::BrokenPipe(Box::new(e), <_>::default()))?;
                }
            }
            self.as_ref()
                .notify_serial(self.update_local_serial(serial), false)
                .await?;
            progress
                .send(())
                .await
                .map_err(|e| SessionError::BrokenPipe(Box::new(e), <_>::default()))?;
        }
        Ok(())
    }
}
