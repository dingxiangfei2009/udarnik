use super::*;

impl BridgeState {
    pub(super) async fn bridge_outward(self: Pin<Arc<Self>>, outbound: BridgeMessage) {
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
        if let BridgeMessage::Payload {
            raw_shard_id: RawShardId { id, serial, stream },
            ..
        } = &outbound
        {
            info!(
                "bridge out: payload: stream {} serial {} id {}",
                stream, serial, id
            )
        }
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
}
