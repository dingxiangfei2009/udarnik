use super::*;

impl BridgeState {
    pub fn new<T>(
        invite_cooldown: Duration,
        bridge_inward: Sender<(BridgeId, BridgeMessage)>,
        bridge_outward: Receiver<BridgeMessage>,
        bridge_invitation_trigger: Sender<()>,
        timeout_generator: impl 'static + Send + Sync + Fn(Duration) -> T,
    ) -> (Pin<Arc<Self>>, impl Future<Output = ()>)
    where
        T: 'static + Send + Future<Output = ()>,
    {
        let (new_bridge_poll, bridge_poll_rx) = channel(4096);
        let this = Arc::pin(Self {
            new_bridge_poll,
            kill_switches: <_>::default(),
            send_counter: <_>::default(),
            send_success_counter: <_>::default(),
            receive_counter: <_>::default(),
            bridge_sinks: <_>::default(),
            bridge_avail_mutex: <_>::default(),
            bridge_avail_cv: <_>::default(),
            bridge_inward,
        });
        let mut handle_bridge_polls = Pin::clone(&this)
            .bridge_poll(
                invite_cooldown,
                bridge_invitation_trigger,
                bridge_poll_rx,
                timeout_generator,
            )
            .boxed()
            .fuse();
        let mut handle_bridge_outward = bridge_outward
            .for_each({
                let this = Pin::clone(&this);
                move |m| Pin::clone(&this).bridge_outward(m)
            })
            .boxed()
            .fuse();
        let poll = async move {
            select_biased! {
                r = handle_bridge_polls => {
                    if let Err(e) = r {
                        error!("all_bridge_poll: {:?}", e)
                    }
                },
                _ = handle_bridge_outward => (),
            }
        };
        (this, poll)
    }

    pub async fn inc_recv_counter(&self, bridge_id: BridgeId) {
        if let Some(counter) = self.receive_counter.counters.read().await.get(&bridge_id) {
            counter.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.receive_counter
            .counters
            .write()
            .await
            .entry(bridge_id)
            .or_default()
            .fetch_add(1, Ordering::Relaxed);
    }

    async fn bridge_poll<T>(
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
                        _ = timeout_generator(invite_cooldown).fuse() => {
                            trace!("poll_bridges: no bridges, inviting");
                            bridge_invitation_trigger
                                .send(())
                                .await
                                .map_err(|e| {
                                    SessionError::BrokenPipe(Box::new(e) as GenericError, Bt::new())
                                })?;
                        },
                        poll = poll_rx.next() => {
                            if let Some(poll) = poll {
                                polls.push(poll);
                            } else {
                                break
                            }
                        }
                    }
                }
                poll = poll_rx.next() => {
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

    async fn bridge_outward(self: Pin<Arc<Self>>, outbound: BridgeMessage) {
        let mut rng = StdRng::from_entropy();
        let (id, mut sink) = loop {
            let bridge_sinks = self.bridge_sinks.read().await;
            if let Some((id, (sink, _))) = bridge_sinks.iter().choose(&mut rng) {
                debug!("bridges_out: choose bridge {:?}", id);
                break (id.clone(), ClonableSink::clone_pin_box(&**sink));
            } else {
                // NOTE: this order matters!
                let mutex = self.bridge_avail_mutex.lock().await;
                drop(bridge_sinks);
                self.bridge_avail_cv.wait(mutex).await;
            }
        };
        match sink.send(outbound).await {
            Err(e) => error!("bridges_out: {}", e),
            _ => debug!("bridges_out: sent to {:?}", id),
        }
        if let Some(counter) = self.send_counter.counters.read().await.get(&id) {
            counter.fetch_add(1, Ordering::Relaxed);
            debug!("bridges_out: {:?} send counter updated", id);
            return;
        }
        self.send_counter
            .counters
            .write()
            .await
            .entry(id.clone())
            .or_default()
            .fetch_add(1, Ordering::Relaxed);
        debug!("bridges_out: {:?} send counter initialized", id);
    }

    pub async fn add_kill_switch(&self, id: BridgeId, switch: OneshotSender<()>) {
        if let Some(switch) = self.kill_switches.lock().await.insert(id, switch) {
            let _ = switch.send(());
        }
    }

    pub async fn add_bridge<S>(
        self: Pin<&Self>,
        id: BridgeId,
        poll: impl 'static + Future<Output = ()> + Unpin + Send,
        source: impl 'static + Stream<Item = Result<BridgeMessage, GenericError>> + Unpin + Send,
        sink: BridgeSink,
        spawn: S,
    ) -> Result<(), SessionError>
    where
        S: Spawn + Clone + Send + Sync + 'static,
        S::Error: 'static,
    {
        let (cancel_bridge, bridge_cancelled) = AbortHandle::new_pair();
        let bridge_inward = self
            .bridge_inward
            .clone()
            .sink_map_err(|e| Box::new(e) as GenericError);
        let source = spawn
            .spawn(
                source
                    .map_ok({
                        let id = id.clone();
                        move |p| (id.clone(), p)
                    })
                    .forward(bridge_inward),
            )
            .unwrap_or_else(|_| Err(Box::new(SessionError::Spawn)));
        let id_ = id.clone();
        let poll = async move {
            select_biased! {
                r = source.fuse() => {
                    if let Err(e) = r {
                        error!("bridge: poll_inbound: {:?}", e)
                    }
                },
                _ = poll.fuse() => (),
            }
        };
        let poll = async move {
            let _ = Abortable::new(poll, bridge_cancelled).await;
            id_
        };
        self.new_bridge_poll
            .clone()
            .send(Box::new(poll.shared()))
            .await
            .map_err(|e| SessionError::BrokenPipe(Box::new(e), Bt::new()))?;
        // NOTE: order matters
        let mut bridge_sinks = self.bridge_sinks.write().await;
        let _mutex = self.bridge_avail_mutex.lock().await;
        bridge_sinks.insert(id, (sink, cancel_bridge));
        self.bridge_avail_cv.notify_all();
        Ok(())
    }

    pub async fn remove_bridge(&self, id: &BridgeId) {
        if let Some((_, abort)) = self.bridge_sinks.read().await.get(id) {
            abort.abort();
        }
    }

    pub async fn update_bridge_health(&self, health: impl IntoIterator<Item = (BridgeId, u64)>) {
        let mut counters = self.send_success_counter.counters.write().await;
        for (id, count) in health {
            counters
                .entry(id)
                .or_default()
                .fetch_add(count, Ordering::Relaxed);
        }
    }
}
