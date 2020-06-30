use super::*;
use futures::channel::oneshot::channel as oneshot_channel;

mod admit;
mod feedback;
mod recv;
mod send_enqueue;

use self::{
    admit::AdmitProcess, feedback::FeedbackProcess, recv::RecvProcess,
    send_enqueue::SendEnqueueProcess,
};

impl StreamState {
    pub fn new<T>(
        StreamTimeouts {
            stream_timeout,
            send_cooldown,
            stream_reset_timeout,
            recv_timeout,
        }: StreamTimeouts,
        stream_reset_trigger: Sender<u8>,
        session_progress: Sender<()>,
        bridge_outward: Sender<BridgeMessage>,
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
            session_progress,
            bridge_outward,
            codec,
            error_reports,
            output,

            stream_timeout,
            send_cooldown,
            recv_timeout,
        });
        let poll = Self::stream_poll(
            stream_reset_timeout,
            stream_reset_trigger,
            stream_poll_rx,
            timeout_generator,
        );
        (this, poll)
    }

    async fn stream_poll<T>(
        stream_reset_timeout: Duration,
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
                let timeout = timeout_generator(stream_reset_timeout);
                select! {
                    poll = new_poll.next() => {
                        if let Some(poll) = poll {
                            polls.push(poll);
                        } else {
                            break;
                        }
                    }
                    _ = timeout.fuse() => {
                        // TODO: adjust timeout
                    }
                }
            } else {
                select! {
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

        let send_out_process = SendOutProcess {
            send_queue: Arc::clone(&send_queue),
            terminate: Box::new(terminate.clone()) as _,
            bridge_outward: self.bridge_outward.clone(),
            progress: progress_tx.clone(),
            session_progress: self.session_progress.clone(),
        }
        .send_all_out()
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

        let sort_inbound =
            Self::sort_inbound(stream, inbound_rx, admit_process, feedback_process).fuse();

        let recv_process = RecvProcess {
            stream,
            error_reports: self.error_reports.clone(),
            recv_queue: Arc::clone(&receive_queue),
            codec: Arc::clone(&self.codec),
            bridge_outward: self.bridge_outward.clone(),
            progress: progress_tx,
            session_progress: self.session_progress.clone(),
            output: self.output.clone(),
            recv_timeout: self.recv_timeout,
            timeout: timeout_generator.clone(),
            terminate: Box::new(terminate.clone()) as _,
        }
        .process_recv()
        .fuse();

        let process_task_notifiers =
            Self::process_task_notifiers(task_notifiers_rx, task_notifiers).fuse();

        let send_enqueue_process = Arc::new(SendEnqueueProcess {
            send_queue: Arc::clone(&send_queue),
            shard_state: Arc::clone(&shard_state),
            codec: Arc::clone(&self.codec),
            send_cooldown: self.send_cooldown,
            timeout_generator: timeout_generator.clone(),
        })
        .process_send_enqueue(send_enqueue_rx)
        .fuse();

        let timeout = Self::timeout(self.stream_timeout, progress, timeout_generator).fuse();

        let poll = async move {
            pin_mut!(
                sort_inbound,
                recv_process,
                send_enqueue_process,
                send_out_process,
                timeout,
                process_task_notifiers,
            );
            select_biased! {
                _ = timeout => (),
                r = sort_inbound => r?,
                r = recv_process => r?,
                r = send_enqueue_process => r?,
                r = process_task_notifiers => r,
                r = send_out_process => r?,
            }
            Ok::<_, SessionError>(())
        };

        warn!("stream state: new stream poll: sending");
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

        let mut streams = self.streams.write().await;
        streams.insert(stream, Arc::new(session_stream));
        self.stream_avail_mutex.lock().await;
        drop(streams);
        Ok(self.stream_avail_cv.notify_all())
    }

    pub async fn send(&self, data: Vec<u8>) -> Result<(), SessionError> {
        let mut rng = StdRng::from_entropy();
        loop {
            let streams = self.streams.read().await;
            if let Some((_, stream)) = streams.iter().choose(&mut rng) {
                let stream = Arc::clone(stream);
                drop(streams);
                trace!("stream_state: found a stream for sending");
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
            let stream = Arc::clone(&stream);
            drop(streams);
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
            .for_each_concurrent(32, |(serial, notifier)| {
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
            .try_for_each_concurrent(32, move |message| {
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
            let (raw_shard, raw_shard_id) = select! {
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
