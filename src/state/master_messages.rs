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

            match variant {
                ClientMessageVariant::Ok | ClientMessageVariant::Err => {
                    trace!("{:?}: peer answers", self.role);
                    self.update_remote_serial(serial);
                    progress
                        .send(())
                        .await
                        .map_err(|e| SessionError::BrokenPipe(Box::new(e), <_>::default()))?;
                    continue;
                }
                _ => {}
            }

            // Message can be valid but old.
            if let Err(local_serial) = self.assert_valid_serial(serial) {
                info!(
                    "{:?}: outdated serial {}, should be at least {}, message: {:?}",
                    self.role, serial, local_serial, variant
                );
                self.as_ref().notify_serial(local_serial, true).await?;
                continue;
            }

            match variant {
                ClientMessageVariant::BridgeNegotiate(negotiation) => {
                    Pin::clone(&self)
                        .handle_bridge_negotiation(negotiation, spawn.clone())
                        .await?
                }
                ClientMessageVariant::Stream(request) => match request {
                    StreamRequest::Reset { stream, window } => {
                        info!("{:?}: peer resets stream {}", self.role, stream,);
                        self.new_stream(stream, window, timeout_generator.clone(), spawn.clone())
                            .await?;
                        info!("{:?}: stream {}: reset", self.role, stream);
                    }
                },
                _ => {}
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

    async fn handle_bridge_negotiation(
        self: Pin<Arc<Self>>,
        negotiation: BridgeNegotiationMessage,
        spawn: impl Spawn + Clone + Send + Sync + 'static,
    ) -> Result<(), SessionError> {
        trace!("{:?}: incoming bridge negotiation message", self.role);
        match negotiation {
            BridgeNegotiationMessage::ProposeAsk => {
                info!("{:?}: peer wants new bridges", self.role);
                self.new_tasks
                    .clone()
                    .send(Box::new(Box::pin(async move {
                        if let Err(e) = self.answer_ask_proposal(spawn).await {
                            error!("answer_ask_proposal: {:?}", e);
                        }
                    })) as Box<_>)
                    .await
                    .map_err(|e| SessionError::BrokenPipe(Box::new(e), <_>::default()))?;
            }
            BridgeNegotiationMessage::Ask(proposals) => {
                info!("{:?}: peer wants new bridge rendevous", self.role);
                Pin::clone(&self).apply_proposal(proposals, spawn).await?;
            }
            BridgeNegotiationMessage::Retract(bridges_) => {
                info!("{:?}: peer wants to tear down bridges", self.role);
                for BridgeRetract(id) in bridges_ {
                    self.bridge_state.remove_bridge(&id).await
                }
            }
            BridgeNegotiationMessage::AskProposal(proposals) => {
                info!("{:?}: peer sends some bridge proposals", self.role);
                let asks = Pin::clone(&self).apply_proposal(proposals, spawn).await?;
                self.as_ref().ask_bridge(asks).await?
            }
            BridgeNegotiationMessage::QueryHealth => {
                info!("{:?}: peer queries bridge health", self.role);
                self.as_ref().answer_bridge_health_query().await?
            }
            BridgeNegotiationMessage::Health(health) => {
                info!("{:?}: peer answers bridge health", self.role);
                self.bridge_state.update_bridge_health(health).await;
            }
        }
        Ok(())
    }
}
