use super::*;

pub struct SendQueue {
    q_send: MPMCSender<(RawShard, RawShardId)>,
    q_recv: MPMCReceiver<(RawShard, RawShardId)>,
    stream: u8,
    serial: AtomicU64,
    task_notifiers: TaskProgressNotifierSink,
    block_sending_tx: MPMCSender<BoxFuture<'static, ()>>,
    block_sending_rx: MPMCReceiver<BoxFuture<'static, ()>>,
}

impl SendQueue {
    pub fn new(stream: u8, window: usize, task_notifiers: TaskProgressNotifierSink) -> Self {
        let (q_send, q_recv) = mpmc_channel(window);
        let (block_sending_tx, block_sending_rx) = mpmc_channel(window);
        Self {
            stream,
            task_notifiers,
            serial: AtomicU64::default(),
            q_send,
            q_recv,
            block_sending_tx,
            block_sending_rx,
        }
    }

    pub fn block_sending(&self, condition: impl 'static + Future<Output = ()> + Send) {
        let _ = self.block_sending_tx.try_send(condition.boxed());
    }

    pub async fn enqueue(&self, data: (RawShard, RawShardId)) {
        if let Ok(block_sending) = self.block_sending_rx.try_recv() {
            debug!("send queue: back pressure");
            block_sending.await
        }
        self.q_send.send(data).await;
    }

    pub async fn pop(&self) -> (RawShard, RawShardId) {
        self.q_recv.recv().await.expect("senders should never drop")
    }

    pub async fn send<Timeout>(
        &self,
        data: impl AsRef<[u8]>,
        shard_state: &ShardState,
        codec: &RSCodec,
        timeout_generator: impl Fn(Duration) -> Timeout,
        timeout: Duration,
    ) -> Result<(), SendError>
    where
        Timeout: Future,
    {
        let shards = Shard::from_codes(codec.encode(data.as_ref()).map_err(SendError::Codec)?);
        let serial = self.serial.fetch_add(1, Ordering::Relaxed);
        let mut shards: Vec<_> = shards
            .iter()
            .map(|shard| shard.encode_shard(self.stream, serial, &shard_state))
            .collect();
        let stream = self.stream;
        debug!("send queue: stream {} serial {}", stream, serial);

        let (tx, mut status) = channel(256);
        let tx = Arc::new(Box::new(tx.sink_map_err(|e| Box::new(e) as GenericError))
            as Box<
                dyn Send + Sync + ClonableSink<Result<(u8, u8), RemoteRecvError>, GenericError>,
            >);
        ClonableSink::clone_pin_box(&*self.task_notifiers)
            .send((serial, Arc::downgrade(&tx) as _))
            .await
            .map_err(|_| SendError::BrokenPipe)?;

        let threshold = codec.threshold();
        for (shard, shard_id) in shards.drain(..threshold) {
            self.enqueue((shard, shard_id)).await;
        }

        // hear from the peer about how the reception goes
        let remote_report = async move {
            while let Some(status) = status.next().await {
                match status {
                    Ok((id, quorum_size)) => {
                        trace!(
                            "send queue: feedback: stream {} serial {} id {} quorum_size {}",
                            stream,
                            serial,
                            id,
                            quorum_size,
                        );
                    }
                    Err(RemoteRecvError::Complete) => {
                        trace!(
                            "send queue: feedback: complete stream {} serial {}",
                            stream,
                            serial,
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("send queue: feedback: {}", e);
                        return Err(SendError::Remote(e));
                    }
                }
            }
            Err(SendError::RemoteLost(<_>::default()))
        }
        .fuse();
        let keep_sending = async move {
            for (shard, shard_id) in shards {
                self.enqueue((shard, shard_id)).await;
                timeout_generator(timeout).await;
            }
            trace!("exhausted");
            // okay, maybe we have to drop it
            Err(SendError::Exhausted)
        }
        .fuse();
        pin_mut!(remote_report, keep_sending);
        let result = select_biased! {
            r = remote_report => r,
            r = keep_sending => r,
        };
        debug!("send queue: stream {} serial {} over", stream, serial);
        result
    }
}
