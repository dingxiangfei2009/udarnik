use super::*;
use futures::channel::oneshot::channel as oneshot_channel;

impl StreamState {
    pub fn new<T>(
        stream_timeout: Duration,
        stream_reset_trigger: Sender<u8>,
        session_progress: Sender<()>,
        bridge_outward: Sender<BridgeMessage>,
        send_cooldown: Duration,
        codec: Arc<RSCodec>,
        error_reports: Sender<(u8, u64, HashSet<u8>)>,
        output: Sender<Vec<u8>>,
        timeout_generator: impl 'static + Send + Sync + Fn(Duration) -> T,
    ) -> (Pin<Arc<Self>>, impl Future<Output = ()>)
    where
        T: 'static + Send + Future<Output = ()>,
    {
        let (new_stream_poll, stream_poll_rx) = channel(4096);
        let this = Arc::pin(Self {
            streams: <_>::default(),
            new_stream_poll,
            stream_avail_mutex: <_>::default(),
            stream_avail_cv: <_>::default(),
            stream_timeout,
            session_progress,
            bridge_outward,
            send_cooldown,
            codec,
            error_reports,
            output,
        });
        let mut handle_stream_poll =
            Self::stream_poll(stream_reset_trigger, stream_poll_rx, timeout_generator)
                .boxed()
                .fuse();
        let poll = async move {
            select_biased! {
                _ = handle_stream_poll => (),
            }
        };
        (this, poll)
    }

    async fn stream_poll<T>(
        mut reset_trigger: Sender<u8>,
        mut new_poll: Receiver<StreamPoll>,
        timeout_generator: impl 'static + Send + Sync + Fn(Duration) -> T,
    ) where
        T: 'static + Send + Future<Output = ()>,
    {
        let mut rng = StdRng::from_entropy();
        let mut polls = FuturesUnordered::new();
        loop {
            if polls.is_empty() {
                // try to get a new stream
                if let Err(_) = reset_trigger.send(rng.next_u32() as u8).await {
                    break;
                }
                select_biased! {
                    poll = new_poll.next() => {
                        if let Some(poll) = poll {
                            polls.push(poll);
                        } else {
                            break;
                        }
                    }
                    _ = timeout_generator(Duration::new(5, 0)).fuse() => {
                        // TODO: adjust timeout
                    }
                }
            } else {
                select_biased! {
                    id = polls.next().fuse() => (),
                    poll = new_poll.next().fuse() => {
                        if let Some(poll) = poll {
                            polls.push(poll);
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    pub async fn new_stream<T, S>(
        &self,
        stream: u8,
        window: usize,
        shard_state: ShardState,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
        spawn: S,
    ) -> Result<(), SessionError>
    where
        T: 'static + Send + Future<Output = ()>,
        S: Spawn + Clone + Send + Sync + 'static,
    {
        let shard_state = Arc::new(shard_state);
        let (terminate_tx, terminate) = oneshot_channel();
        let terminate = terminate.unwrap_or_else(|_| ()).shared();
        let (progress_tx, progress) = channel(4096);
        let (task_notifiers_tx, task_notifiers_rx) = channel(window);
        let task_notifiers_tx = task_notifiers_tx.sink_map_err(|e| Box::new(e) as GenericError);

        let send_queue = Arc::new(SendQueue::new(
            stream,
            window,
            Box::new(task_notifiers_tx) as _,
        ));

        let mut send_out_process = spawn
            .spawn(
                SendOutProcess {
                    send_queue: Arc::clone(&send_queue),
                    terminate: Box::new(terminate.clone()) as _,
                    bridge_outward: self.bridge_outward.clone(),
                    progress: progress_tx.clone(),
                    session_progress: self.session_progress.clone(),
                }
                .send_all_out(),
            )
            .unwrap_or_else(|_| Err(SessionError::Spawn))
            .boxed()
            .fuse();

        let receive_queue = Arc::new(ReceiveQueue::new());

        let (inbound, inbound_rx) = channel(4096);
        let (send_enqueue, send_enqueue_rx) = channel(4096);
        let session_stream = SessionStream {
            inbound,
            send_enqueue,
            terminate: terminate_tx,
        };

        let admit_process = AdmitProcess {
            stream,
            recv_queue: Arc::clone(&receive_queue),
            shard_state: Arc::clone(&shard_state),
            bridge_outward: self.bridge_outward.clone(),
        };

        let task_notifiers = <_>::default();

        let feedback_process = FeedbackProcess {
            task_notifiers: Arc::clone(&task_notifiers),
            progress: progress_tx.clone(),
            session_progress: self.session_progress.clone(),
            send_queue: Arc::clone(&send_queue),
            window,
            send_cooldown: self.send_cooldown,
            timeout_generator: timeout_generator.clone(),
        };

        let mut sort_inbound = spawn
            .spawn(Self::sort_inbound(
                stream,
                inbound_rx,
                admit_process,
                feedback_process,
            ))
            .unwrap_or_else(|_| Err(SessionError::Spawn))
            .boxed()
            .fuse();

        let mut recv_process = spawn
            .spawn(
                RecvProcess {
                    stream,
                    error_reports: self.error_reports.clone(),
                    recv_queue: Arc::clone(&receive_queue),
                    codec: Arc::clone(&self.codec),
                    bridge_outward: self.bridge_outward.clone(),
                    progress: progress_tx,
                    session_progress: self.session_progress.clone(),
                    output: self.output.clone(),
                    recv_timeout: Duration::new(30, 0),
                    timeout: timeout_generator.clone(),
                    terminate: Box::new(terminate.clone()) as _,
                }
                .process_recv(),
            )
            .unwrap_or_else(|_| Err(SessionError::Spawn))
            .boxed()
            .fuse();

        let mut process_task_notifiers = spawn
            .spawn(Self::process_task_notifiers(
                task_notifiers_rx,
                task_notifiers,
            ))
            .unwrap_or_else(|_| ())
            .boxed()
            .fuse();

        let mut send_enqueue_process = spawn
            .spawn(
                Arc::new(SendEnqueueProcess {
                    send_queue: Arc::clone(&send_queue),
                    shard_state: Arc::clone(&shard_state),
                    codec: Arc::clone(&self.codec),
                    send_cooldown: self.send_cooldown,
                    timeout_generator: timeout_generator.clone(),
                })
                .process_send_enqueue(send_enqueue_rx),
            )
            .unwrap_or_else(|_| Err(SessionError::Spawn))
            .boxed()
            .fuse();

        let mut timeout = spawn
            .spawn(Self::timeout(
                self.stream_timeout,
                progress,
                timeout_generator,
            ))
            .unwrap_or_else(|_| error!("new_stream: timeout: cannot spawn"))
            .boxed()
            .fuse();

        let poll = async move {
            select_biased! {
                r = send_enqueue_process => r?,
                r = sort_inbound => r?,
                r = process_task_notifiers => r,
                r = send_out_process => r?,
                r = recv_process => r?,
                _ = timeout => (),
            }
            Ok::<_, SessionError>(())
        };

        let mut streams = self.streams.write().await;
        self.stream_avail_mutex.lock().await;
        self.new_stream_poll
            .clone()
            .send(Box::new(
                async move {
                    if let Err(r) = poll.await {
                        error!("stream_poll: {:?}", r)
                    }
                }
                .shared(),
            ))
            .await
            .map_err(|e| SessionError::BrokenPipe(Box::new(e), Bt::new()))?;
        streams.insert(stream, session_stream);
        Ok(self.stream_avail_cv.notify_all())
    }

    pub async fn send(&self, data: Vec<u8>) -> Result<(), SessionError> {
        let mut rng = StdRng::from_entropy();
        loop {
            let streams = self.streams.read().await;
            if let Some((_, stream)) = streams.iter().choose(&mut rng) {
                break stream
                    .send_enqueue
                    .clone()
                    .send(data)
                    .await
                    .map_err(|e| SessionError::BrokenPipe(Box::new(e), Bt::new()));
            } else {
                debug!("StreamState::send: waiting available stream");
                let guard = self.stream_avail_mutex.lock().await;
                drop(streams);
                self.stream_avail_cv.wait(guard).await;
            }
        }
    }

    pub async fn recv(&self, message: BridgeMessage) -> Result<bool, SessionError> {
        let streams = self.streams.read().await;
        let stream = match &message {
            BridgeMessage::PayloadFeedback { stream, .. } => *stream,
            BridgeMessage::Payload { raw_shard_id, .. } => raw_shard_id.stream,
        };
        if let Some(stream) = streams.get(&stream) {
            stream
                .inbound
                .clone()
                .send(message)
                .await
                .map_err(|e| SessionError::BrokenPipe(Box::new(e), Bt::new()))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn process_task_notifiers(
        task_notifiers: Receiver<(u64, TaskProgressNotifier)>,
        store: TaskProgressNotifierStore,
    ) {
        task_notifiers
            .for_each_concurrent(4096, |(serial, notifier)| {
                let store = Arc::clone(&store);
                async move {
                    store.write().await.insert(serial, notifier);
                }
            })
            .await
    }

    async fn sort_inbound<Timeout, T>(
        stream: u8,
        inbound: Receiver<BridgeMessage>,
        admit_process: AdmitProcess,
        feedback_process: FeedbackProcess<Timeout>,
    ) -> Result<(), SessionError>
    where
        T: 'static + Send + Future<Output = ()>,
        Timeout: 'static + Send + Sync + Fn(Duration) -> T,
    {
        let feedback_process = Arc::new(feedback_process);
        let admit_process = Arc::new(admit_process);
        inbound
            .map(Ok)
            .try_for_each_concurrent(4096, move |message| {
                let feedback_process = Arc::clone(&feedback_process);
                let admit_process = Arc::clone(&admit_process);
                async move {
                    match message {
                        BridgeMessage::Payload {
                            raw_shard,
                            raw_shard_id,
                        } => admit_process.admit_shard(raw_shard, raw_shard_id).await?,
                        BridgeMessage::PayloadFeedback {
                            feedback,
                            stream: stream_,
                        } if stream == stream_ => {
                            feedback_process.process_feedback(feedback).await?
                        }
                        _ => error!("poll_bridges_in: unknown message"),
                    }
                    Ok(())
                }
            })
            .await
    }

    async fn timeout<T>(
        stream_timeout: Duration,
        mut progress: Receiver<()>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
    ) where
        T: 'static + Send + Future<Output = ()>,
    {
        loop {
            select_biased! {
                r = progress.next().fuse() => {
                    if let None = r {
                        break
                    }
                },
                _ = timeout_generator(stream_timeout).fuse() => break,
            }
        }
        warn!("stream: killing progress");
    }
}

type TaskProgressNotifierStore = Arc<RwLock<BTreeMap<u64, TaskProgressNotifier>>>;

struct FeedbackProcess<Timeout> {
    task_notifiers: TaskProgressNotifierStore,
    // stream progress indicator
    progress: Sender<()>,
    // session progress indicator
    session_progress: Sender<()>,
    // send queue in order to enable blocking
    send_queue: Arc<SendQueue>,
    send_cooldown: Duration,
    window: usize,
    timeout_generator: Timeout,
}

impl<Timeout, T> FeedbackProcess<Timeout>
where
    T: 'static + Send + Future<Output = ()>,
    Timeout: 'static + Send + Sync + Fn(Duration) -> T,
{
    async fn process_feedback(&self, feedback: PayloadFeedback) -> Result<(), SessionError> {
        {
            let task_notifiers = self.task_notifiers.read().await;
            if task_notifiers.len() > self.window {
                debug!("task notifier overflow, cleaning");
                drop(task_notifiers);
                let mut task_notifiers = self.task_notifiers.write().await;
                let serials: HashSet<_> = task_notifiers.keys().copied().collect();
                if task_notifiers.len() > self.window {
                    for serial in serials {
                        if let None = task_notifiers.get(&serial).and_then(|n| n.upgrade()) {
                            task_notifiers.remove(&serial);
                        }
                    }
                }
            }
        }
        let task_notifiers = self.task_notifiers.read().await;
        match feedback {
            PayloadFeedback::Ok { serial, id, quorum } => {
                if let Some(mut notifier) = task_notifiers
                    .get(&serial)
                    .and_then(|n| n.upgrade())
                    .map(|n| ClonableSink::clone_pin_box(&**n))
                {
                    if let Err(e) = notifier.send(Ok((id, quorum))).await {
                        debug!("notifer pipe: {}", e);
                    }
                }
                if let Err(e) = self.progress.clone().send(()).await {
                    debug!("progress pipe: {}", e);
                    return Err(SessionError::BrokenPipe(Box::new(e), Bt::new()));
                }
                if let Err(e) = self.session_progress.clone().send(()).await {
                    debug!("session_progress pipe: {}", e);
                    return Err(SessionError::BrokenPipe(Box::new(e), Bt::new()));
                }
            }
            PayloadFeedback::Duplicate { serial, id, quorum } => {
                if let Some(mut notifier) = task_notifiers
                    .get(&serial)
                    .and_then(|n| n.upgrade())
                    .map(|n| ClonableSink::clone_pin_box(&**n))
                {
                    if let Err(e) = notifier.send(Ok((id, quorum))).await {
                        debug!("notifier pipe: {}", e);
                    }
                }
            }
            PayloadFeedback::Full { serial, queue_len } => {
                warn!("backpressure, serial={}, queue={}", serial, queue_len);
                self.send_queue
                    .block_sending((self.timeout_generator)(self.send_cooldown))
                    .await;
                debug!("feedback: full, serial={}, queue={}", serial, queue_len);
            }
            PayloadFeedback::OutOfBound {
                serial,
                start,
                queue_len,
            } => {
                debug!(
                    "out of bound: serial={}, start={}, queue={}",
                    serial, start, queue_len
                );
                if let Some(mut notifier) = task_notifiers
                    .get(&serial)
                    .and_then(|n| n.upgrade())
                    .map(|n| ClonableSink::clone_pin_box(&**n))
                {
                    if let Err(e) = notifier.send(Err(RemoteRecvError::Complete)).await {
                        debug!("notifier pipe: {}", e);
                    }
                }
            }
            PayloadFeedback::Malformed { serial } => {
                if let Some(mut notifier) = task_notifiers
                    .get(&serial)
                    .and_then(|n| n.upgrade())
                    .map(|n| ClonableSink::clone_pin_box(&**n))
                {
                    if let Err(e) = notifier.send(Err(RemoteRecvError::Malformed)).await {
                        debug!("notifier pipe: {}", e);
                    }
                }
            }
            PayloadFeedback::Complete { serial } => {
                if let Some(mut notifier) = task_notifiers
                    .get(&serial)
                    .and_then(|n| n.upgrade())
                    .map(|n| ClonableSink::clone_pin_box(&**n))
                {
                    if let Err(e) = notifier.send(Err(RemoteRecvError::Complete)).await {
                        debug!("notifier pipe: {}", e);
                    }
                }
                if let Err(e) = self.progress.clone().send(()).await {
                    debug!("progress pipe: {}", e);
                    return Err(SessionError::BrokenPipe(Box::new(e), Bt::new()));
                }
                if let Err(e) = self.session_progress.clone().send(()).await {
                    debug!("session_progress pipe: {}", e);
                    return Err(SessionError::BrokenPipe(Box::new(e), Bt::new()));
                }
            }
        }
        Ok(())
    }
}

struct SendEnqueueProcess<Timeout> {
    send_queue: Arc<SendQueue>,
    shard_state: Arc<ShardState>,
    codec: Arc<RSCodec>,
    send_cooldown: Duration,
    timeout_generator: Timeout,
}

impl<Timeout, T> SendEnqueueProcess<Timeout>
where
    T: 'static + Send + Future<Output = ()>,
    Timeout: 'static + Send + Sync + Fn(Duration) -> T,
{
    async fn enqueue_one(self: Arc<Self>, data: Vec<u8>) -> Result<(), SessionError> {
        let send_task = self.send_queue.send(
            &data,
            &self.shard_state,
            &self.codec,
            &self.timeout_generator,
            self.send_cooldown,
        );
        match send_task.await {
            Ok(_) => {}
            Err(SendError::Exhausted) => {
                info!("send: has tried its best");
            }
            Err(SendError::BrokenPipe) => {
                return Err(SessionError::BrokenPipe(
                    Box::new(SendError::BrokenPipe),
                    Bt::new(),
                ));
            }
            Err(e) => {
                error!("send: {}", e);
            }
        }
        Ok(())
    }
    async fn process_send_enqueue(
        self: Arc<Self>,
        send_enqueue: impl 'static + Stream<Item = Vec<u8>>,
    ) -> Result<(), SessionError> {
        send_enqueue
            .map(Ok)
            .try_for_each_concurrent(4096, move |data| Arc::clone(&self).enqueue_one(data))
            .await
    }
}

struct SendOutProcess {
    send_queue: Arc<SendQueue>,
    terminate: Box<dyn Sync + ClonableSendableFuture<()> + Unpin>,
    // bridge outward send entry point
    bridge_outward: Sender<BridgeMessage>,
    // progress indicator
    progress: Sender<()>,
    // session progress indicator
    session_progress: Sender<()>,
}

impl SendOutProcess {
    async fn send_all_out(mut self) -> Result<(), SessionError> {
        loop {
            let (raw_shard, raw_shard_id) = select_biased! {
                message = self.send_queue.pop().fuse() => message,
                _ = ClonableSendableFuture::clone_pin_box(&*self.terminate).fuse() => return Ok(()),
            };
            self.bridge_outward
                .send(BridgeMessage::Payload {
                    raw_shard,
                    raw_shard_id,
                })
                .await
                .map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()))?;
            self.progress
                .send(())
                .await
                .map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()))?;
            self.session_progress
                .send(())
                .await
                .map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()))?;
        }
    }
}

struct RecvProcess<Timeout> {
    stream: u8,
    error_reports: Sender<(u8, u64, HashSet<u8>)>,
    recv_queue: Arc<ReceiveQueue>,
    codec: Arc<RSCodec>,
    // bridge outward send entry point
    bridge_outward: Sender<BridgeMessage>,
    // progress indicator
    progress: Sender<()>,
    // session progress indicator
    session_progress: Sender<()>,
    // final output
    output: Sender<Vec<u8>>,
    timeout: Timeout,
    recv_timeout: Duration,
    terminate: Box<dyn Sync + ClonableSendableFuture<()> + Unpin>,
}

impl<Timeout, T> RecvProcess<Timeout>
where
    T: 'static + Send + Future<Output = ()>,
    Timeout: 'static + Send + Sync + Fn(Duration) -> T,
{
    async fn process_recv(mut self) -> Result<(), SessionError> {
        loop {
            let result = select_biased! {
                front = self.recv_queue.poll(&self.codec).fuse() => {
                    trace!("poll_recv: next is available");
                    Ok(front)
                },
                _ = ClonableSendableFuture::clone_pin_box(&*self.terminate).fuse() => return Ok(()),
                _ = (self.timeout)(self.recv_timeout).fuse() => {
                    // timeout
                    debug!("poll_recv: next is timeout");
                    if let Some(front) = self.recv_queue.pop_front().await {
                        debug!("poll_recv: stale next");
                        front.poll(&self.codec)
                    } else {
                        continue
                    }
                }
            };
            match result {
                Ok((serial, data, errors)) => {
                    // hall of shame
                    info!(
                        "stream {}: poll_recv: good packet {}: {:?}",
                        self.stream, serial, data
                    ); // TODO: REMOVE
                    let (data, errors) = join!(
                        self.output.send(data),
                        self.error_reports.send((self.stream, serial, errors))
                    );
                    data.map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()))?;
                    errors
                        .map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()))?;
                    self.bridge_outward
                        .send(BridgeMessage::PayloadFeedback {
                            stream: self.stream,
                            feedback: PayloadFeedback::Complete { serial },
                        })
                        .await
                        .map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()))?;
                    self.progress
                        .send(())
                        .await
                        .map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()))?;
                    self.session_progress
                        .send(())
                        .await
                        .map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()))?;
                }
                Err(e) => {
                    // TODO: fine grained error reporting
                    error!("poll_recv: pop front: {}", e)
                }
            }
        }
    }
}

struct AdmitProcess {
    stream: u8,
    recv_queue: Arc<ReceiveQueue>,
    shard_state: Arc<ShardState>,
    bridge_outward: Sender<BridgeMessage>,
}

impl AdmitProcess {
    async fn admit_shard(
        &self,
        raw_shard: RawShard,
        raw_shard_id: RawShardId,
    ) -> Result<(), SessionError> {
        let serial = raw_shard_id.serial;
        let feedback = match self
            .recv_queue
            .admit(raw_shard, raw_shard_id, &self.shard_state)
            .await
        {
            Ok((id, quorum_size)) => {
                trace!(
                    "poll_admit: admitted, serial={}, id={}, quorum_size={}",
                    serial,
                    id,
                    quorum_size
                );
                PayloadFeedback::Ok {
                    serial,
                    id,
                    quorum: quorum_size,
                }
            }
            Err(ReceiveError::Full(queue_len)) => {
                debug!("poll_admit: full");
                PayloadFeedback::Full { queue_len, serial }
            }
            Err(ReceiveError::OutOfBound(start, queue_len)) => {
                debug!(
                    "poll_admit: out of bound, serial={}, start={}, queue={}",
                    serial, start, queue_len
                );
                PayloadFeedback::OutOfBound {
                    start,
                    queue_len,
                    serial,
                }
            }
            Err(ReceiveError::Quorum(QuorumError::Duplicate(id, quorum))) => {
                debug!("poll_admit: duplicate");
                PayloadFeedback::Duplicate { serial, id, quorum }
            }
            Err(ReceiveError::Quorum(QuorumError::Malformed { .. }))
            | Err(ReceiveError::Quorum(QuorumError::MismatchContent(..))) => {
                debug!("poll_admit: data {} malformed/mismatch", serial);
                PayloadFeedback::Malformed { serial }
            }
            Err(e) => {
                error!("admission: {}", e);
                return Ok(());
            }
        };
        self.bridge_outward
            .clone()
            .send(BridgeMessage::PayloadFeedback {
                stream: self.stream,
                feedback,
            })
            .await
            .map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()))
    }
}
