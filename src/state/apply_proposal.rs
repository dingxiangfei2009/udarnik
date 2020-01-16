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
        bridges_in_tx: Sender<(BridgeId, BridgeMessage)>,
        spawn: S,
    ) -> Vec<BridgeAsk>
    where
        S: Spawn + Clone + Send + Sync + 'static,
        S::Error: 'static,
    {
        let half = match self.role {
            KeyExchangeRole::Anke => BridgeHalf::Down,
            KeyExchangeRole::Boris => BridgeHalf::Up,
        };
        let this = Pin::clone(&self);
        let success = iter(proposals)
            .map(move |BridgeAsk { r#type, id }| {
                let this = Pin::clone(&this);
                let bridges_in_tx = bridges_in_tx.clone();
                let spawn = spawn.clone();
                async move {
                    let spawn_ = spawn.clone();
                    spawn
                        .spawn(async move {
                            let spawn = spawn_;
                            info!("{:?}: bridge: id={:?}, building", this.role, id);
                            match this
                                .as_ref()
                                .bridge_builder
                                .build(&r#type, &id, half, spawn.clone())
                                .await
                            {
                                Ok(Bridge { tx, rx, poll }) => {
                                    info!("{:?}: bridge: id={:?}, captured", this.role, id);
                                    let (mapping_tx, mapping_rx) = channel(4096);
                                    let inbound_guard = Arc::clone(&this.inbound_guard);
                                    let outbound_guard = Arc::clone(&this.outbound_guard);
                                    let sink = Box::new(
                                        mapping_tx.sink_map_err(|e| Box::new(e) as GenericError),
                                    );
                                    let mut poll_outbound = spawn.spawn(mapping_rx
                                        .map(move |m| Ok(Pomerium::encode(&*outbound_guard, m)))
                                        .forward(tx)
                                        .unwrap_or_else({
                                            move |e| {
                                                error!("poll_outbound: {}", e);
                                            }
                                        }))
                                        .boxed()
                                        .fuse();
                                    let mut poll_inbound = spawn.spawn(rx
                                        .and_then(move |p| {
                                            let inbound_guard = Arc::clone(&inbound_guard);
                                            async move { p.decode(&inbound_guard) }
                                        })
                                        .map_ok({
                                            let id = id.clone();
                                            move |p| (id.clone(), p)
                                        })
                                        .forward(bridges_in_tx.sink_err_into())
                                        .unwrap_or_else({
                                            move |e| {
                                                error!("bridges_in_tx: {}", e);
                                            }
                                        }))
                                        .boxed()
                                        .fuse();
                                    let mut poll = poll.fuse();
                                    {
                                        this.bridge_polls.write().await.insert(id.clone(), {
                                            let id = id.clone();
                                            (
                                                sink,
                                                Box::new(
                                                    async move {
                                                        select! {
                                                            r = poll_inbound => {
                                                                match r {
                                                                    Err(e) => error!("bridge: poll_inbound: {:?}", e),
                                                                    _ => (),
                                                                }
                                                                id
                                                            },
                                                            r = poll_outbound => {
                                                                match r {
                                                                    Err(e) => error!("bridge: poll_inbound: {:?}", e),
                                                                    _ => (),
                                                                }
                                                                id
                                                            },
                                                            r = poll => id,
                                                        }
                                                    }
                                                    .boxed()
                                                    .shared(),
                                                ),
                                            )
                                        });
                                    }
                                    this.bridge_polls_waker_queue.try_notify_all();
                                    Some(BridgeAsk {
                                        r#type: r#type.clone(),
                                        id: id.clone(),
                                    })
                                }
                                Err(e) => {
                                    error!("bridge id={:?} error={}", id, e);
                                    None
                                }
                            }
                        })
                        .await
                }
            })
            .buffer_unordered(256)
            .filter_map(|r| {
                async move {
                    r.unwrap_or_else(|e| {
                        error!("spawn: {:?}", e);
                        None
                    })
                }
            })
            .collect()
            .await;
        success
    }
}
