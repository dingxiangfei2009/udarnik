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
    pub(super) async fn handle_bridges_in(
        self: Pin<&Self>,
        bridges_inward: Receiver<(BridgeId, BridgeMessage)>,
    ) {
        bridges_inward
            .for_each_concurrent(4096, {
                move |(bridge_id, inbound)| async move {
                    let report = match &inbound {
                        BridgeMessage::PayloadFeedback { .. } => None,
                        BridgeMessage::Payload {
                            raw_shard_id: RawShardId { stream, serial, id },
                            ..
                        } => {
                            debug!(
                                "bridge: id={:?}, inbound, stream={}, serial={}, id={}",
                                bridge_id, stream, serial, id
                            );
                            Some((*stream, *serial, *id, bridge_id))
                        }
                    };
                    match self.stream_state.recv(inbound).await {
                        Ok(true) => {
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
                        Ok(false) => trace!(
                            "{:?}, handle_bridges_in: no receiving stream, dropped",
                            self.role
                        ),
                        Err(e) => error!("poll_bridges_in: {}", e),
                    }
                }
            })
            .await
    }
}
