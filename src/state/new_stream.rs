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
    pub(super) fn new_stream<T, S>(
        &self,
        stream: u8,
        window: usize,
        bridges_out_tx: Sender<BridgeMessage>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
        spawn: S,
    ) -> (SessionStream, impl 'static + Future<Output = ()> + Send)
    where
        T: 'static + Send + Future<Output = ()>,
        S: Spawn + Clone + Send + Sync + 'static,
        S::Error: 'static,
    {
        let (input_tx, input_rx) = channel(window);
        let (task_notifiers_tx, task_notifiers_rx) = channel(window);
        let (bridges_in_tx, bridges_in_rx) = channel(4096);
        let bridges_in_tx = Box::new(
            bridges_in_tx
                .sink_map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default())),
        ) as _;
        let task_notifiers_tx = task_notifiers_tx.sink_map_err(|e| Box::new(e) as GenericError);
        let (payload_tx, payload_rx) = channel(4096);
        let (feedback_tx, feedback_rx) = channel(4096);
        let poll_bridges_in = bridges_in_rx.map(Ok::<_, GenericError>).try_fold(
            (payload_tx, feedback_tx),
            move |(mut payload_tx, mut feedback_tx), message| {
                async move {
                    match message {
                        BridgeMessage::Payload {
                            raw_shard,
                            raw_shard_id,
                        } => {
                            payload_tx.send((raw_shard, raw_shard_id)).await?;
                        }
                        BridgeMessage::PayloadFeedback {
                            feedback,
                            stream: stream_,
                        } if stream == stream_ => {
                            feedback_tx.send(feedback).await?;
                        }
                        _ => error!("poll_bridges_in: unknown message"),
                    }
                    Ok((payload_tx, feedback_tx))
                }
            },
        );
        let poll_bridges_in = spawn.spawn(poll_bridges_in);
        let task_notifiers: Arc<RwLock<BTreeMap<u64, TaskProgressNotifier>>> = <_>::default();
        let poll_task_notifiers = task_notifiers_rx.for_each({
            let task_notifiers = Arc::clone(&task_notifiers);
            move |(serial, task_notifier)| {
                let task_notifiers = Arc::clone(&task_notifiers);
                async move {
                    task_notifiers.write().await.insert(serial, task_notifier);
                }
            }
        });
        let poll_task_notifiers = spawn.spawn(poll_task_notifiers);

        let send_queue = Arc::new(SendQueue::new(
            stream,
            window,
            Box::new(task_notifiers_tx) as _,
        ));
        let receive_queue = Arc::new(ReceiveQueue::new());

        let poll_feedback = {
            let task_notifiers_ptr = Arc::clone(&task_notifiers);
            let send_queue = Arc::clone(&send_queue);
            let timeout_generator = timeout_generator.clone();
            let send_cooldown = self.send_cooldown;
            let mut feedback_rx = feedback_rx.fuse();
            async move {
                loop {
                    let task_notifiers = task_notifiers_ptr.read().await;
                    if task_notifiers.len() > window {
                        drop(task_notifiers);
                        let mut task_notifiers = task_notifiers_ptr.write().await;
                        let serials: HashSet<_> = task_notifiers.keys().copied().collect();
                        if task_notifiers.len() > window {
                            for serial in serials {
                                if let None = task_notifiers.get(&serial).and_then(|n| n.upgrade())
                                {
                                    task_notifiers.remove(&serial);
                                }
                            }
                        }
                    } else if let Some(feedback) = feedback_rx.next().await {
                        match feedback {
                            PayloadFeedback::Ok { serial, id, quorum } => {
                                if let Some(notifier) =
                                    task_notifiers.get(&serial).and_then(|n| n.upgrade())
                                {
                                    if let Err(e) =
                                        notifier.lock().await.send(Ok((id, quorum))).await
                                    {
                                        error!("pipe: {}", e);
                                    }
                                }
                            }
                            PayloadFeedback::Duplicate { serial, id, quorum } => {
                                if let Some(notifier) =
                                    task_notifiers.get(&serial).and_then(|n| n.upgrade())
                                {
                                    if let Err(e) =
                                        notifier.lock().await.send(Ok((id, quorum))).await
                                    {
                                        error!("pipe: {}", e);
                                    }
                                }
                            }
                            PayloadFeedback::Full { serial, queue_len } => {
                                error!("backpressure, serial={}, queue={}", serial, queue_len);
                                send_queue.block_sending(timeout_generator(send_cooldown))
                            }
                            PayloadFeedback::OutOfBound {
                                serial,
                                start,
                                queue_len,
                            } => error!(
                                "out of bound: serial={}, start={}, queue={}",
                                serial, start, queue_len
                            ),
                            PayloadFeedback::Malformed { serial } => {
                                if let Some(notifier) =
                                    task_notifiers.get(&serial).and_then(|n| n.upgrade())
                                {
                                    if let Err(e) = notifier
                                        .lock()
                                        .await
                                        .send(Err(RemoteRecvError::Malformed))
                                        .await
                                    {
                                        error!("pipe: {}", e);
                                    }
                                }
                            }
                            PayloadFeedback::Complete { serial } => {
                                if let Some(notifier) =
                                    task_notifiers.get(&serial).and_then(|n| n.upgrade())
                                {
                                    if let Err(e) = notifier
                                        .lock()
                                        .await
                                        .send(Err(RemoteRecvError::Complete))
                                        .await
                                    {
                                        error!("pipe: {}", e);
                                    }
                                }
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
        };
        let poll_feedback = spawn.spawn(poll_feedback);

        let poll_send_pending = {
            unfold(
                (Arc::clone(&send_queue), timeout_generator.clone()),
                move |(send_queue, timeout_generator)| {
                    async move {
                        // TODO: BAD LOOP
                        loop {
                            select! {
                                send = send_queue.pop().fuse() => break Some((send, (send_queue, timeout_generator))),
                                _ = timeout_generator(Duration::new(0, 1000000)).fuse() => (),
                            }
                        }
                    }
                },
            )
            .map(|(raw_shard, raw_shard_id)| {
                Ok(BridgeMessage::Payload {
                    raw_shard,
                    raw_shard_id,
                })
            })
            .forward(bridges_out_tx.clone())
            .map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()))
        };
        let poll_send_pending = spawn.spawn(poll_send_pending);

        let poll_recv = {
            unfold(
                (
                    Arc::clone(&receive_queue),
                    Arc::clone(&self.codec),
                    timeout_generator.clone(),
                    self.role,
                ),
                |(receive_queue, codec, timeout_generator, role)| {
                    async move {
                        // TODO: BAD LOOP
                        loop {
                            select! {
                                recv = receive_queue.poll(&codec).fuse() => {
                                    trace!("{:?}: poll_recv: incoming data", role);
                                    break Some((
                                        Ok(recv),
                                        (receive_queue, codec, timeout_generator, role),
                                    ));
                                }
                                _ = timeout_generator(Duration::new(0, 1000000)).fuse() => ()
                            }
                        }
                    }
                },
            )
        };
        let poll_recv = {
            let receive_queue = Arc::clone(&receive_queue);
            let codec = Arc::clone(&self.codec);
            let timeout = Duration::new(30, 0)/* self.receive_timeout */;
            let timeout_generator = timeout_generator.clone();
            let mut bridges_out_tx = bridges_out_tx.clone();
            let mut error_reports = self.error_reports.clone();
            let mut output = self.output.clone();
            let role = self.role;
            async move {
                let mut poll_recv = Box::pin(poll_recv.fuse());
                loop {
                    trace!("{:?}: poll_recv, timeout={:?}", role, timeout);
                    let front = select! {
                        front = poll_recv.next() => {
                            if let Some(front) = front {
                                debug!("{:?}: poll_recv: next", role);
                                front
                            } else {
                                debug!("{:?}: poll_recv: terminated", role);
                                break
                            }
                        },
                        _ = timeout_generator(timeout).fuse() => {
                            debug!("{:?}: poll_recv: timed out", role);
                            if let Some(front) = receive_queue.pop_front() {
                                front.poll(&codec)
                            } else {
                                continue
                            }
                        }
                    };
                    match front {
                        Ok((serial, data, errors)) => {
                            // hall of shame
                            let (data, errors) = join!(
                                output.send(data),
                                error_reports.send((stream, serial, errors))
                            );
                            data?;
                            errors?;
                            bridges_out_tx
                                .send(BridgeMessage::PayloadFeedback {
                                    stream,
                                    feedback: PayloadFeedback::Complete { serial },
                                })
                                .await?;
                        }
                        Err(e) => {
                            // TODO: fine grained error reporting
                            error!("{:?}: poll_recv: pop front: {}", role, e)
                        }
                    }
                }
                Ok::<_, GenericError>(())
            }
        };
        let poll_recv = spawn.spawn(poll_recv);

        let mut shard_state = ShardState::default();
        for chunk in sha3::Sha3_512::digest(&self.session_key).chunks(32) {
            for (s, c) in chunk.iter().zip(shard_state.key.iter_mut()) {
                *c ^= s
            }
        }
        for chunk in sha3::Sha3_512::new()
            .chain(&self.session_key)
            .chain(b", stream=")
            .chain(&[stream])
            .result()
            .chunks(32)
        {
            for (s, c) in chunk.iter().zip(shard_state.stream_key.iter_mut()) {
                *c ^= s
            }
        }

        let poll_admit = {
            let receive_queue = Arc::clone(&receive_queue);
            let shard_state = shard_state;
            let role = self.role;
            payload_rx
                .fuse()
                .filter_map(move |(raw_shard, raw_shard_id)| {
                    trace!("{:?}: poll_admit", role);
                    let receive_queue = Arc::clone(&receive_queue);
                    let serial = raw_shard_id.serial;
                    async move {
                        match receive_queue.admit(raw_shard, raw_shard_id, &shard_state) {
                            Ok((id, quorum_size)) => {
                                trace!(
                                    "{:?}: poll_admit: admitted, serial={}, id={}, quorum_size={}",
                                    role,
                                    serial,
                                    id,
                                    quorum_size
                                );
                                Some(PayloadFeedback::Ok {
                                    serial,
                                    id,
                                    quorum: quorum_size,
                                })
                            }
                            Err(ReceiveError::Full(queue_len)) => {
                                trace!("{:?}: poll_admit: full", role);
                                Some(PayloadFeedback::Full { queue_len, serial })
                            }
                            Err(ReceiveError::OutOfBound(start, queue_len)) => {
                                trace!("{:?}: poll_admit: out of bound", role);
                                Some(PayloadFeedback::OutOfBound {
                                    start,
                                    queue_len,
                                    serial,
                                })
                            }
                            Err(ReceiveError::Quorum(QuorumError::Duplicate(id, quorum))) => {
                                trace!("{:?}: poll_admit: duplicate", role);
                                Some(PayloadFeedback::Duplicate { serial, id, quorum })
                            }
                            Err(ReceiveError::Quorum(QuorumError::Malformed { .. }))
                            | Err(ReceiveError::Quorum(QuorumError::MismatchContent(..))) => {
                                trace!("{:?}: poll_admit: malformed/mismatch", role);
                                Some(PayloadFeedback::Malformed { serial })
                            }
                            Err(e) => {
                                error!("admission: {}", e);
                                None
                            }
                        }
                    }
                })
                .map(move |feedback| Ok(BridgeMessage::PayloadFeedback { stream, feedback }))
                .forward(bridges_out_tx.clone())
        };
        let poll_admit = spawn.spawn(poll_admit);

        let poll_send = input_rx.map(Ok).try_for_each_concurrent(2, {
            let send_queue = Arc::clone(&send_queue);
            let shard_state = shard_state;
            let codec = Arc::clone(&self.codec);
            let timeout_generator = timeout_generator.clone();
            let timeout = self.send_cooldown;
            move |input| {
                let send_queue = Arc::clone(&send_queue);
                let codec = Arc::clone(&codec);
                let timeout_generator = timeout_generator.clone();
                async move {
                    match send_queue
                        .send(&input, &shard_state, &codec, timeout_generator, timeout)
                        .await
                    {
                        Ok(_) => (),
                        Err(SendError::BrokenPipe) => {
                            return Err(SessionError::BrokenPipe(
                                Box::new(SendError::BrokenPipe.compat()),
                                <_>::default(),
                            ))
                        }
                        Err(e) => error!("send: {}", e),
                    }
                    Ok(())
                }
            }
        });
        let poll_send = spawn.spawn(poll_send);

        let poll_all = async move {
            select! {
                r = poll_bridges_in.boxed().fuse() => match r {
                    Ok(Err(e)) => {
                        error!("stream: poll_bridges_in: {}", e);
                    }
                    Err(e) => {
                        error!("stream: poll_bridges_in: spawn: {:?}", e);
                    }
                    _ => {
                        error!("stream: poll_bridges_in: terminated");
                    },
                },
                r = poll_task_notifiers.boxed().fuse() => match r {
                    Ok(()) => {
                        error!("stream: poll_task_notifiers: terminated");
                    }
                    Err(e) => {
                        error!("stream: poll_task_notifiers: spawn: {:?}", e);
                    }
                },
                r = poll_feedback.boxed().fuse() => match r {
                    Ok(()) => {
                        error!("stream: poll_feedback: terminated");
                    }
                    Err(e) => {
                        error!("stream: poll_feedback: spawn: {:?}", e);
                    }
                },
                r = poll_send_pending.boxed().fuse() => match r {
                    Ok(Err(e)) => {
                        error!("stream: poll_send_pending: {}", e);
                    }
                    Err(e) => {
                        error!("stream: poll_send_pending: spawn: {:?}", e);
                    }
                    _ => error!("stream: poll_send_pending: terminated"),
                },
                r = poll_recv.fuse() => match r {
                    Ok(Err(e)) => {
                        error!("stream: poll_recv: {}", e);
                    }
                    Err(e) => {
                        error!("stream: poll_recv: spawn: {:?}", e);
                    }
                    _ => error!("stream: poll_recv: terminated"),
                },
                r = poll_admit.boxed().fuse() => match r {
                    Ok(Err(e)) => {
                        error!("stream: poll_admit: {}", e);
                    }
                    Err(e) => {
                        error!("stream: poll_admit: spawn: {:?}", e);
                    }
                    _ => error!("stream: poll_admit: terminated"),
                },
                r = poll_send.boxed().fuse() => match r {
                    Ok(Err(e)) => {
                        error!("stream: poll_send: {}", e);
                    }
                    Err(e) => {
                        error!("stream: poll_send: spawn: {:?}", e);
                    }
                    _ => error!("stream: poll_send: terminated"),
                },
            }
        };

        (
            SessionStream {
                send_queue,
                receive_queue,
                bridges_in_tx,
                input_tx,
            },
            poll_all,
        )
    }
}
