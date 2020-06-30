use super::*;

#[derive(Default)]
struct ReceiveQueueState {
    queue: VecDeque<AsyncMutex<Quorum>>,
    start: Wrapping<u64>,
}

#[derive(Default)]
pub struct ReceiveQueue {
    state: AsyncRwLock<ReceiveQueueState>,
    window: Option<u32>,

    avail_mutex: AsyncMutex<()>,
    avail_cv: Condvar,
}

impl ReceiveQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn admit(
        &self,
        raw_shard: RawShard,
        raw_shard_id: RawShardId,
        shard_state: &ShardState,
    ) -> Result<(u8, u8), ReceiveError> {
        let serial = raw_shard_id.serial;
        let shard_id = (raw_shard_id, shard_state)
            .verify_proof(())
            .map_err(ReceiveError::Shard)?;
        let shard = raw_shard
            .clone()
            .verify_proof(shard_id.into_inner())
            .map_err(ReceiveError::Shard)?;

        let window = self.window.unwrap_or(256) as usize;
        let state = self.state.read().await;
        let Wrapping(idx) = Wrapping(serial) - state.start;
        let idx = idx as usize;
        if idx < 4 * window {
            let (result, queue_len) = if idx < state.queue.len() {
                let q_len = state.queue.len();
                let result = state.queue[idx]
                    .lock()
                    .await
                    .insert(serial, shard)
                    .map_err(ReceiveError::Quorum)?;
                if idx == 0 {
                    self.signal_one(state).await;
                }
                (result, q_len)
            } else {
                drop(state);
                let mut state = self.state.write().await;
                let len = state.queue.len();
                state
                    .queue
                    .resize_with(std::cmp::max(len, idx + 1), <_>::default);
                let q_len = state.queue.len();
                let result = state.queue[idx]
                    .lock()
                    .await
                    .insert(serial, shard)
                    .map_err(ReceiveError::Quorum)?;
                if idx == 0 {
                    self.signal_one(state).await;
                }
                (result, q_len)
            };
            if idx > window {
                Err(ReceiveError::Full(queue_len))
            } else {
                Ok(result)
            }
        } else {
            Err(ReceiveError::OutOfBound(state.start.0, state.queue.len()))
        }
    }

    pub async fn pop_front(&self) -> Option<Quorum> {
        let mut state = self.state.write().await;
        if let Some(q) = state.queue.pop_front() {
            state.start += Wrapping(1);
            self.signal_all(state).await;
            Some(q.into_inner())
        } else {
            None
        }
    }

    async fn wait_for_update<T>(&self, write_guard: T) {
        let guard = self.avail_mutex.lock().await;
        drop(write_guard);
        self.avail_cv.wait(guard).await;
    }

    async fn signal_one<T>(&self, write_guard: T) {
        let _guard = self.avail_mutex.lock().await;
        drop(write_guard);
        self.avail_cv.notify_one();
    }

    async fn signal_all<T>(&self, write_guard: T) {
        let _guard = self.avail_mutex.lock().await;
        drop(write_guard);
        self.avail_cv.notify_all();
    }

    pub async fn poll(&self, codec: &RSCodec) -> (u64, Vec<u8>, HashSet<u8>) {
        loop {
            let mut state = self.state.write().await;
            if let Some(front) = state.queue.front() {
                let result = front.lock().await.poll(&codec);
                drop(front);
                if let Ok(result) = result {
                    state.start += Wrapping(1);
                    state.queue.pop_front();
                    self.signal_one(state).await;
                    return result;
                } else {
                    self.wait_for_update(state).await;
                }
            } else {
                self.wait_for_update(state).await;
            }
        }
    }

    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        state.start = Wrapping(0);
        state.queue.clear();
    }
}
