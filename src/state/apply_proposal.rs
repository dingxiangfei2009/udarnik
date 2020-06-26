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
    pub(super) async fn apply_proposal<S>(
        self: Pin<Arc<Self>>,
        proposals: Vec<BridgeAsk>,
        spawn: S,
    ) -> Result<Vec<BridgeAsk>, SessionError>
    where
        S: Spawn + Clone + Send + Sync + 'static,
        S::Error: 'static,
    {
        let half = match self.role {
            KeyExchangeRole::Anke => BridgeHalf::Down,
            KeyExchangeRole::Boris => BridgeHalf::Up,
        };
        let this = Pin::clone(&self);
        let results: Vec<_> = iter(proposals)
            .map(move |BridgeAsk { r#type, id }| {
                let this = Pin::clone(&this);
                let spawn_ = spawn.clone();
                let id = id.clone();
                let work = async move {
                    info!("{:?}: bridge: id={:?}, building", this.role, id);
                    match this
                        .as_ref()
                        .bridge_builder
                        .build(&r#type, &id, half, spawn_.clone())
                        .await
                    {
                        Ok(Bridge { tx, rx, poll }) => {
                            info!("{:?}: bridge: id={:?}, captured", this.role, id);
                            let (mapping_tx, mapping_rx) = channel(4096);
                            let inbound_guard = Arc::clone(&this.inbound_guard);
                            let outbound_guard = Arc::clone(&this.outbound_guard);
                            let sink =
                                Box::new(mapping_tx.sink_map_err(|e| Box::new(e) as GenericError));
                            let mut poll_outbound = spawn_
                                .spawn(
                                    mapping_rx
                                        .map(move |m| Ok(Pomerium::encode(&*outbound_guard, m)))
                                        .forward(tx)
                                        .unwrap_or_else({
                                            move |e| {
                                                error!("poll_outbound: {}", e);
                                            }
                                        }),
                                )
                                .fuse();
                            let source = rx.and_then(move |p| {
                                let inbound_guard = Arc::clone(&inbound_guard);
                                async move { p.decode(&inbound_guard) }.boxed()
                                    as BoxFuture<'static, Result<BridgeMessage, GenericError>>
                            });
                            let source: Box<
                                dyn 'static
                                    + Stream<Item = Result<BridgeMessage, GenericError>>
                                    + Unpin
                                    + Send,
                            > = Box::new(source);
                            let mut poll = poll.fuse();
                            let poll = async move {
                                select_biased! {
                                    r = poll_outbound => {
                                        if let Err(e) = r {
                                            error!("bridge: poll_outbound: {:?}", e)
                                        }
                                    },
                                    _ = poll => (),
                                }
                            }
                            .shared();
                            this.bridge_state
                                .as_ref()
                                .add_bridge(id.clone(), poll, source, sink, spawn_)
                                .await?;
                            Ok(Some(BridgeAsk {
                                r#type: r#type.clone(),
                                id: id.clone(),
                            }))
                        }

                        Err(e) => {
                            error!("bridge id={:?} error={}", id, e);
                            Ok(None)
                        }
                    }
                };
                let work: BoxFuture<'static, Result<_, SessionError>> = work.boxed();
                let task = spawn.spawn(work);
                async move {
                    if let Ok(r) = task.await {
                        r
                    } else {
                        Err(SessionError::Spawn)
                    }
                }
            })
            .buffer_unordered(256)
            .try_filter_map(|r| async move { Ok(r) })
            .collect()
            .await;
        results.into_iter().collect()
    }
}
