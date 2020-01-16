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
    pub(super) async fn handle_bridges_in<T: 'static + Send + Future<Output = ()>>(
        self: Pin<&Self>,
        bridges_in_rx: Receiver<(BridgeId, BridgeMessage)>,
        timeout_generator: impl 'static + Clone + Send + Sync + Fn(Duration) -> T,
    ) {
        bridges_in_rx
            .for_each_concurrent(4096, {
                let timeout_generator = timeout_generator.clone();
                move |(bridge_id, inbound)| {
                    let timeout_generator = timeout_generator.clone();
                    async move {
                        let stream = match &inbound {
                            BridgeMessage::PayloadFeedback { stream, .. } => *stream,
                            BridgeMessage::Payload { raw_shard_id, .. } => raw_shard_id.stream,
                        };
                        let report = if let BridgeMessage::Payload {
                            raw_shard_id: RawShardId { stream, serial, id },
                            ..
                        } = &inbound
                        {
                            trace!(
                                "bridge: id={:?}, inbound, stream={}, serial={}, id={}",
                                bridge_id,
                                stream,
                                serial,
                                id
                            );
                            Some((*stream, *serial, *id, bridge_id))
                        } else {
                            None
                        };
                        let mut stream = {
                            trace!("{:?}: handle_bridges_in: find stream", self.role);
                            let stream_polls = self.stream_polls.read().await;
                            if let Some((session_stream, _)) = stream_polls.get(&stream) {
                                trace!(
                                    "{:?}: handle_bridges_in: found stream {}",
                                    self.role,
                                    stream
                                );
                                ClonableSink::clone_pin_box(&*session_stream.bridges_in_tx)
                            } else {
                                drop(stream_polls);
                                let mut stream_exists = StreamExists {
                                    key: None,
                                    session: self.as_ref().get_ref(),
                                    stream_polls: None,
                                    stream,
                                }
                                .fuse();
                                select! {
                                    stream = stream_exists => {
                                        stream
                                    },
                                    _ = timeout_generator(Duration::new(1, 0)).fuse() => {
                                        trace!(
                                            "{:?}, handle_bridges_in: no receiving stream, dropped",
                                            self.role
                                        );
                                        return
                                    },
                                }
                            }
                        };
                        match stream.send(inbound).await {
                            Ok(_) => {
                                trace!("{:?}: handle_bridges_in: checked in", self.role);
                                if let Some((stream, serial, id, bridge_id)) = report {
                                    let fame = self.hall_of_fame.read().await;
                                    if let Some(stream) = fame.peek(&stream) {
                                        let mut stream = stream.lock().await;
                                        if let Some(serial) = stream.peek_mut(&serial) {
                                            let id = serial.entry(id).or_default();
                                            if id.is_some() {
                                                id.take();
                                            }
                                        } else {
                                            let mut map = HashMap::new();
                                            map.insert(id, Some(bridge_id));
                                            stream.put(serial, map);
                                        }
                                    } else {
                                        drop(fame);
                                        let mut fame = self.hall_of_fame.write().await;
                                        if let Some(stream) = fame.peek(&stream) {
                                            let mut stream = stream.lock().await;
                                            if let Some(serial) = stream.peek_mut(&serial) {
                                                let id = serial.entry(id).or_default();
                                                if let Some(bridge_id_) = id {
                                                    if *bridge_id_ != bridge_id {
                                                        id.take();
                                                    }
                                                }
                                            } else {
                                                let mut map = HashMap::new();
                                                map.insert(id, Some(bridge_id));
                                                stream.put(serial, map);
                                            }
                                        } else {
                                            let mut table = LruCache::new(255);
                                            let mut map = HashMap::new();
                                            map.insert(id, Some(bridge_id));
                                            table.put(serial, map);
                                            fame.put(stream, Mutex::new(table));
                                        }
                                    }
                                }
                                trace!("{:?}: handle_bridges_in: hall_of_fame", self.role);
                            }
                            Err(e) => error!("poll_bridges_in: {}", e),
                        }
                    }
                }
            })
            .await
    }
}

struct StreamExists<'a, G> {
    session: &'a Session<G>,
    stream_polls: Option<BoxFuture<'a, RwLockReadGuard<'a, StreamPolls>>>,
    stream: u8,
    key: Option<usize>,
}

impl<'a, G> Future for StreamExists<'a, G> {
    type Output = Pin<Box<dyn ClonableSink<BridgeMessage, SessionError> + Send + Sync>>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use Poll::*;
        if let None = self.stream_polls {
            self.stream_polls = Some(self.session.stream_polls.read().boxed());
        }
        if let Some(mut stream_polls) = self.stream_polls.take() {
            match Pin::new(&mut stream_polls).poll(cx) {
                Ready(stream_polls) => {
                    if let Some((session_stream, _)) = stream_polls.get(&self.stream) {
                        self.session
                            .stream_polls_waker_queue
                            .deregister_poll_waker(self.key);
                        return Ready(ClonableSink::clone_pin_box(&*session_stream.bridges_in_tx));
                    } else {
                        self.key = self
                            .session
                            .stream_polls_waker_queue
                            .register_poll_waker(self.key, cx.waker().clone());
                    }
                }
                Pending => {
                    self.stream_polls = Some(stream_polls);
                }
            }
        } else {
            unreachable!()
        }
        Pending
    }
}
