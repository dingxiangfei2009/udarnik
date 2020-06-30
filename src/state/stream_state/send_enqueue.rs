use super::*;

pub struct SendEnqueueProcess<Timeout> {
    pub send_queue: Arc<SendQueue>,
    pub shard_state: Arc<ShardState>,
    pub codec: Arc<RSCodec>,
    pub send_cooldown: Duration,
    pub timeout_generator: Timeout,
}

impl<Timeout, T> SendEnqueueProcess<Timeout>
where
    T: 'static + Send + Future<Output = ()>,
    Timeout: 'static + Send + Sync + Fn(Duration) -> T,
{
    pub async fn enqueue_one(self: Arc<Self>, data: Vec<u8>) -> Result<(), SessionError> {
        trace!("send process: sending one");
        let send_task = self.send_queue.send(
            &data,
            &self.shard_state,
            &self.codec,
            &self.timeout_generator,
            self.send_cooldown,
        );
        match send_task.await {
            Ok(_) => trace!("send process: sent one"),
            Err(SendError::Exhausted) => {
                trace!("send: has tried its best");
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
    pub async fn process_send_enqueue(
        self: Arc<Self>,
        send_enqueue: impl 'static + Stream<Item = Vec<u8>>,
    ) -> Result<(), SessionError> {
        send_enqueue
            .map(Ok)
            .try_for_each(move |data| Arc::clone(&self).enqueue_one(data))
            .await
    }
}
