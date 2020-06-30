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
    pub fn new<T, S>(
        session_bootstrap: SessionBootstrap,
        timeout_params: TimeoutParams,
        bridge_constructor_params: BridgeConstructorParams,
        master_messages: Receiver<Message<G>>,
        master_sink: Box<dyn Send + Sync + ClonableSink<Message<G>, GenericError>>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
        spawn: S,
    ) -> Result<SessionHandle<G>, SessionError>
    where
        S: Spawn + Clone + Send + Sync + 'static,
        T: 'static + Send + Future<Output = ()>,
    {
        let SessionBootstrap {
            role,
            params,
            session_key,
            session_id,
        } = session_bootstrap;
        let TimeoutParams {
            stream_timeout,
            send_cooldown,
            stream_reset_timeout,
            recv_timeout,
            invite_cooldown,
        } = timeout_params;
        let (input_tx, input) = channel(4096);
        let (output, output_rx) = channel(4096);
        let (error_reports, error_reports_rx) = channel(4096);
        let (progress, progress_rx) = channel(4096);
        let (bridge_outward_tx, bridge_outward) = channel(4096);
        let (bridge_invitation_trigger, bridge_invitation_rx) = channel(4096);
        let (bridges_in_tx, bridges_in_rx) = channel(4096);
        let bridge_drivers = FuturesUnordered::new();
        let (new_tasks, new_tasks_rx) = channel(4096);
        let (stream_reset_trigger, stream_reset_rx) = channel(4096);
        let (bridge_state, bridge_state_poll) = BridgeState::new(
            invite_cooldown,
            bridges_in_tx,
            bridge_outward,
            bridge_invitation_trigger,
            timeout_generator.clone(),
        );
        let codec = Arc::new(RSCodec::new(params.correction).map_err(SessionError::Codec)?);
        let (stream_state, stream_state_poll) = StreamState::new(
            StreamTimeouts {
                stream_timeout,
                send_cooldown,
                stream_reset_timeout,
                recv_timeout,
            },
            stream_reset_trigger,
            progress.clone(),
            bridge_outward_tx,
            Arc::clone(&codec),
            error_reports.clone(),
            output.clone(),
            timeout_generator.clone(),
        );
        let session = Arc::pin(Self {
            role,
            local_serial: <_>::default(),
            remote_serial: <_>::default(),
            inbound_guard: Arc::new(G::from(&session_key)),
            outbound_guard: Arc::new(G::from(&session_key)),
            session_key: session_key.to_vec(),

            master_sink,
            bridge_builder: BridgeBuilder::new(),
            bridge_drivers: Arc::pin(RwLock::new(bridge_drivers)),
            bridge_state,
            stream_state,
            hall_of_fame: Arc::new(RwLock::new(LruCache::new(256))),

            new_tasks,

            session_id: session_id.clone(),
            params,
            bridge_constructor_params,
        });
        let poll = Pin::clone(&session)
            .process_session(
                input,
                error_reports_rx,
                master_messages,
                bridges_in_rx,
                progress,
                new_tasks_rx,
                bridge_invitation_rx,
                stream_reset_rx,
                timeout_generator.clone(),
                spawn,
            )
            .fuse();
        let poll = async move {
            pin_mut!(bridge_state_poll, stream_state_poll, poll);
            select_biased! {
                _ = bridge_state_poll.fuse() => (),
                _ = stream_state_poll.fuse() => (),
                _ = poll => (),
            }
            Ok(())
        }
        .boxed();
        Ok(SessionHandle {
            session,
            poll,
            input: input_tx,
            output: output_rx,
            progress: progress_rx,
        })
    }

    // processes
    async fn handle_bridge_drivers<T>(
        self: Pin<&Self>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
    ) where
        T: 'static + Send + Future<Output = ()>,
    {
        loop {
            trace!("{:?}: poll_bridge_drivers", self.role);
            let mut bridge_drivers = self.bridge_drivers.write().await;
            if bridge_drivers.len() > 0 {
                bridge_drivers.next().await;
            } else {
                drop(bridge_drivers);
                timeout_generator(Duration::new(1, 0)).await;
            }
        }
    }

    async fn send_raw_master_message(&self, message: Message<G>) -> Result<(), SessionError> {
        ClonableSink::clone_pin_box(&*self.master_sink)
            .send(message)
            .await
            .map_err(|e| SessionError::BrokenPipe(e, <_>::default()))
    }

    async fn send_master_message(&self, message: ClientMessageVariant) -> Result<(), SessionError> {
        let serial = self.remote_serial.fetch_add(1, Ordering::Relaxed);
        let message = Message::Client(ClientMessage {
            serial,
            session: self.session_id.clone(),
            variant: Pomerium::encode_with_tag(
                &*self.outbound_guard,
                message,
                &(self.session_id.clone(), serial),
            ),
        });
        self.send_raw_master_message(message).await
    }

    async fn invite_bridge_proposal(self: Pin<&Self>) -> Result<(), SessionError> {
        trace!("{:?}: invite bridge proposals", self.role);
        self.send_master_message(ClientMessageVariant::BridgeNegotiate(
            BridgeNegotiationMessage::ProposeAsk,
        ))
        .await
    }

    async fn reset_stream<T, S>(
        self: Pin<&Self>,
        stream: u8,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
        spawn: S,
    ) -> Result<(), SessionError>
    where
        T: 'static + Send + Future<Output = ()>,
        S: Spawn + Clone + Send + Sync + 'static,
        S::Error: 'static,
    {
        self.new_stream(stream, self.params.window, timeout_generator, spawn)
            .await?;
        self.send_master_message(ClientMessageVariant::Stream(StreamRequest::Reset {
            window: self.params.window,
            stream,
        }))
        .await
    }

    async fn construct_bridge_proposals<S>(self: Pin<&Self>, spawn: S) -> Vec<BridgeAsk>
    where
        S: Spawn + Clone + Send + Sync + 'static,
    {
        // TODO: provide other bridge types
        let mut asks = vec![];
        for _ in 0..3 {
            debug!("{:?}: building bridge", self.role);
            let grpc::GrpcBridgeConstruction {
                id,
                params,
                driver,
                kill_switch,
            } = match grpc::bridge(spawn.clone(), &self.bridge_constructor_params).await {
                Ok(r) => r,
                Err(e) => {
                    error!("{:?}: bridge engineer: {}", self.role, e);
                    continue;
                }
            };
            self.bridge_state
                .add_kill_switch(id.clone(), kill_switch)
                .await;
            self.bridge_drivers.read().await.push(driver.fuse());
            debug!("{:?}: bridge constructed", self.role);
            asks.push(BridgeAsk {
                r#type: BridgeType::Grpc(params),
                id,
            })
        }
        debug!("{:?}: constructed bridge proposals", self.role);
        asks
    }

    pub(super) async fn answer_ask_proposal<S>(
        self: Pin<Arc<Self>>,
        spawn: S,
    ) -> Result<(), SessionError>
    where
        S: Spawn + Clone + Send + Sync + 'static,
    {
        // TODO: proposal
        if let KeyExchangeRole::Anke = self.role {
            warn!("{:?}: I cannot build a bridge %)", self.role);
            return Ok(());
        }
        let proposals = self.as_ref().construct_bridge_proposals(spawn).await;
        self.send_master_message(ClientMessageVariant::BridgeNegotiate(
            BridgeNegotiationMessage::AskProposal(proposals),
        ))
        .await
    }

    pub(super) fn update_local_serial(&self, serial: u64) -> u64 {
        let serial = serial + 1;
        loop {
            let local_serial = self.local_serial.load(Ordering::Relaxed);
            if Wrapping(local_serial) - Wrapping(serial) < Wrapping(1 << 63) {
                break local_serial;
            } else if self
                .local_serial
                .compare_exchange(local_serial, serial, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break serial;
            }
        }
    }

    pub(super) fn update_remote_serial(&self, serial: u64) -> u64 {
        let serial = serial + 1;
        loop {
            let remote_serial = self.remote_serial.load(Ordering::Relaxed);
            if Wrapping(serial) - Wrapping(serial) < Wrapping(1 << 63) {
                break remote_serial;
            } else if self
                .remote_serial
                .compare_exchange(remote_serial, serial, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break serial;
            }
        }
    }

    pub(super) async fn notify_serial(
        self: Pin<&Self>,
        serial: u64,
        failure: bool,
    ) -> Result<(), SessionError> {
        trace!("{:?}: notify peer the serial", self.role);
        let tag = (self.session_id.clone(), serial);
        let message = Message::Client(ClientMessage {
            serial,
            session: self.session_id.clone(),
            variant: Pomerium::encode_with_tag(
                &*self.outbound_guard,
                if failure {
                    ClientMessageVariant::Err
                } else {
                    ClientMessageVariant::Ok
                },
                &tag,
            ),
        });
        self.send_raw_master_message(message).await
    }

    pub(super) async fn ask_bridge(
        self: Pin<&Self>,
        proposals: Vec<BridgeAsk>,
    ) -> Result<(), SessionError> {
        self.send_master_message(ClientMessageVariant::BridgeNegotiate(
            BridgeNegotiationMessage::Ask(proposals),
        ))
        .await
    }

    pub(super) fn assert_valid_serial(&self, serial: u64) -> Result<u64, u64> {
        let local_serial = self.local_serial.load(Ordering::Relaxed);
        let diff = Wrapping(serial) - Wrapping(local_serial);
        if diff > Wrapping(1 << 63) {
            Err(local_serial)
        } else {
            Ok(serial)
        }
    }

    pub(super) async fn answer_bridge_health_query(self: Pin<&Self>) -> Result<(), SessionError> {
        let health = self
            .bridge_state
            .receive_counter
            .counters
            .read()
            .await
            .iter()
            .map(|(id, recvs)| (id.clone(), recvs.load(Ordering::Relaxed)))
            .collect();
        self.send_master_message(ClientMessageVariant::BridgeNegotiate(
            BridgeNegotiationMessage::Health(health),
        ))
        .await
    }

    async fn process_session<T>(
        self: Pin<Arc<Self>>,
        input: Receiver<Vec<u8>>,
        error_reports: Receiver<(u8, u64, HashSet<u8>)>,
        master_messages: Receiver<Message<G>>,
        bridge_inward: Receiver<(BridgeId, BridgeMessage)>,
        progress: Sender<()>,
        mut new_tasks: Receiver<Box<dyn 'static + Send + Sync + Unpin + Future<Output = ()>>>,
        mut bridge_invitation_trigger: Receiver<()>,
        mut stream_reset_trigger: Receiver<u8>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
        spawn: impl Spawn + Clone + Send + Sync + 'static,
    ) -> Result<(), SessionError>
    where
        T: 'static + Send + Future<Output = ()>,
    {
        let error_reports = {
            let this = Pin::clone(&self);
            let progress = progress.clone();
            async move {
                this.as_ref()
                    .handle_error_reports(error_reports, progress)
                    .await
            }
            .fuse()
        };
        let input = spawn
            .spawn({
                let this = Pin::clone(&self);
                async move {
                    info!("input start");
                    this.as_ref().handle_input(input).await
                }
            })
            .fuse();
        let invite_bridges = {
            let this = Pin::clone(&self);
            async move {
                while let Some(_) = bridge_invitation_trigger.next().await {
                    if let Err(e) = this.as_ref().invite_bridge_proposal().await {
                        error!("invite_bridges: master message failed, {:?}", e)
                    }
                }
            }
            .fuse()
        };
        let reset_streams = {
            let this = Pin::clone(&self);
            let timeout = timeout_generator.clone();
            let spawn = spawn.clone();
            async move {
                while let Some(stream) = stream_reset_trigger.next().await {
                    this.as_ref()
                        .reset_stream(stream, timeout.clone(), spawn.clone())
                        .await?;
                }
                Ok::<_, SessionError>(())
            }
            .fuse()
        };
        let poll_bridges_in = spawn
            .spawn({
                let this = Pin::clone(&self);
                async move { this.as_ref().handle_bridges_in(bridge_inward).await }
            })
            .fuse();
        let poll_master_messages = spawn
            .spawn({
                let this = Pin::clone(&self);
                this.handle_master_messages(
                    master_messages,
                    progress.clone(),
                    timeout_generator.clone(),
                    spawn.clone(),
                )
            })
            .fuse();
        let poll_bridge_drivers = {
            let this = Pin::clone(&self);
            async move { this.as_ref().handle_bridge_drivers(timeout_generator).await }.fuse()
        };

        let poll_tasks = spawn
            .spawn(async move {
                let mut tasks = FuturesUnordered::new();
                loop {
                    select_biased! {
                        r = tasks.next() => {
                            if let None = r {
                                if let Some(task) = new_tasks.next().await {
                                    tasks.push(task);
                                } else {
                                    break;
                                }
                            }
                        }
                        task = new_tasks.next() => {
                            if let Some(task) = task {
                                tasks.push(task);
                            } else {
                                break;
                            }
                        }
                    }
                }
            })
            .unwrap_or_else(|_| ())
            .fuse();
        pin_mut!(
            poll_master_messages,
            poll_bridges_in,
            poll_bridge_drivers,
            error_reports,
            invite_bridges,
            reset_streams,
            input,
            poll_tasks,
        );
        select! {
            _ = poll_master_messages => Ok(()),
            _ = poll_bridges_in => Ok(()),
            _ = poll_bridge_drivers => Ok(()),
            result = error_reports => match result {
                Err(e) => {
                    error!("{:?}: error_reports: {:?}", self.role, e);
                    Ok(())
                },
                _ => Ok(()),
            },
            _ = invite_bridges => Ok(()),
            r = reset_streams => {
                if let Err(e) = r {
                    error!("reset_streams: {:?}", e)
                }
                Ok(())
            },
            result = input => match result {
                Ok(Err(e)) => {
                    error!("{:?}: input: {:?}", self.role, e);
                    Err(e)
                },
                Err(e) => {
                    error!("{:?}: input: {:?}", self.role, e);
                    Ok(())
                }
                _ => Ok(()),
            },
            _ = poll_tasks => Ok(()),
        }
    }
}
