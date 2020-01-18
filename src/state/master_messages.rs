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
        master_messages: Receiver<Message<G>>,
        bridges_in_tx: Sender<(BridgeId, BridgeMessage)>,
        bridges_out_tx: Sender<BridgeMessage>,
        progress: Sender<()>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
        spawn: impl Spawn + Clone + Send + Sync + 'static,
    ) -> Result<(), SessionError>
    where
        T: 'static + Send + Future<Output = ()>,
    {
        master_messages
            .map(Ok)
            .try_for_each({
                move |request| {
                    let this = Pin::clone(&self);
                    let bridges_in_tx = bridges_in_tx.clone();
                    let bridges_out_tx = bridges_out_tx.clone();
                    let timeout_generator = timeout_generator.clone();
                    let mut progress = progress.clone();
                    let spawn = spawn.clone();
                    async move {
                        match request {
                            Message::Client(ClientMessage {
                                serial,
                                session,
                                variant: Redact(variant),
                            }) => {
                                trace!("{:?}: incoming client message", this.role);
                                let tag = (session.clone(), serial);
                                match variant.decode_with_tag(&this.inbound_guard, &tag) {
                                    Ok(variant) => {
                                        // prevent replay
                                        if let Err(local_serial) = this.assert_valid_serial(serial)
                                        {
                                            info!(
                                                "{:?}: outdated serial, should be at least {}",
                                                this.role, local_serial
                                            );
                                            return this
                                                .as_ref()
                                                .notify_serial(local_serial, true)
                                                .await;
                                        }
                                        match variant {
                                            ClientMessageVariant::BridgeNegotiate(negotiation) => {
                                                trace!(
                                                    "{:?}: incoming bridge negotiation message",
                                                    this.role
                                                );
                                                match negotiation {
                                                    BridgeNegotiationMessage::ProposeAsk => {
                                                        info!(
                                                            "{:?}: peer wants new bridges",
                                                            this.role
                                                        );
                                                        this.as_ref()
                                                            .answer_ask_proposal(spawn.clone())
                                                            .await?
                                                    }
                                                    BridgeNegotiationMessage::Ask(proposals) => {
                                                        info!(
                                                            "{:?}: peer wants new bridge rendevous",
                                                            this.role
                                                        );
                                                        Pin::clone(&this)
                                                            .apply_proposal(
                                                                proposals,
                                                                bridges_in_tx.clone(),
                                                                spawn.clone(),
                                                            )
                                                            .await;
                                                    }
                                                    BridgeNegotiationMessage::Retract(bridges_) => {
                                                        info!(
                                                            "{:?}: peer wants to tear down bridges",
                                                            this.role
                                                        );
                                                        let mut bridge_polls =
                                                            this.bridge_polls.write().await;
                                                        for BridgeRetract(id) in bridges_ {
                                                            bridge_polls.remove(&id);
                                                        }
                                                    }
                                                    BridgeNegotiationMessage::AskProposal(
                                                        proposals,
                                                    ) => {
                                                        info!(
                                                        "{:?}: peer sends some bridge proposals",
                                                        this.role
                                                    );
                                                        let asks = Pin::clone(&this)
                                                            .apply_proposal(
                                                                proposals,
                                                                bridges_in_tx.clone(),
                                                                spawn.clone(),
                                                            )
                                                            .await;
                                                        this.as_ref().ask_bridge(asks).await?
                                                    }
                                                    BridgeNegotiationMessage::QueryHealth => {
                                                        info!(
                                                            "{:?}: peer queries bridge health",
                                                            this.role
                                                        );
                                                        this.as_ref()
                                                            .answer_bridge_health_query()
                                                            .await?
                                                    }
                                                    BridgeNegotiationMessage::Health(health) => {
                                                        info!(
                                                            "{:?}: peer answers bridge health",
                                                            this.role
                                                        );
                                                        let mut counters = this
                                                            .send_success_counter
                                                            .counters
                                                            .write()
                                                            .await;
                                                        for (id, count) in health {
                                                            counters
                                                                .entry(id)
                                                                .or_default()
                                                                .fetch_add(
                                                                    count,
                                                                    Ordering::Relaxed,
                                                                );
                                                        }
                                                    }
                                                }
                                            }
                                            ClientMessageVariant::Stream(request) => {
                                                match request {
                                                    StreamRequest::Reset { stream, window } => {
                                                        info!(
                                                            "{:?}: peer resets stream {}",
                                                            this.role, stream,
                                                        );
                                                        let (session_stream, poll) = this
                                                            .new_stream(
                                                                stream,
                                                                window,
                                                                bridges_out_tx.clone(),
                                                                progress.clone(),
                                                                timeout_generator.clone(),
                                                                spawn.clone(),
                                                            );
                                                        {
                                                            this.stream_polls.write().await.insert(
                                                                stream,
                                                                (
                                                                    session_stream,
                                                                    Box::pin(poll.shared()),
                                                                ),
                                                            );
                                                        }
                                                        info!(
                                                            "{:?}: stream {}: reset",
                                                            this.role, stream
                                                        );
                                                        this.stream_polls_waker_queue
                                                            .try_notify_all();
                                                    }
                                                }
                                            }
                                            ClientMessageVariant::Ok
                                            | ClientMessageVariant::Err => {
                                                trace!("{:?}: peer answers", this.role);
                                                this.update_remote_serial(serial);
                                                return progress.send(()).await.map_err(|e| {
                                                    SessionError::BrokenPipe(
                                                        Box::new(e),
                                                        <_>::default(),
                                                    )
                                                });
                                            }
                                        }
                                        this.as_ref()
                                            .notify_serial(this.update_local_serial(serial), false)
                                            .await?;
                                        progress.send(()).await.map_err(|e| {
                                            SessionError::BrokenPipe(Box::new(e), <_>::default())
                                        })
                                    }
                                    Err(e) => {
                                        error!("decode error: {}", e);
                                        Ok(())
                                    }
                                }
                            }
                            _ => {
                                info!("unknown message, ignored");
                                Ok(())
                            }
                        }
                    }
                }
            })
            .await
    }
}
