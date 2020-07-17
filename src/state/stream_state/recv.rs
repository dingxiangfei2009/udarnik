use super::*;

use crate::protocol::QuorumResolve;

pub(super) struct RecvProcess<Timeout> {
    pub stream: u8,
    pub error_reports: Sender<StreamErrorReport>,
    pub recv_queue: Arc<ReceiveQueue>,
    pub codec: Arc<RSCodec>,
    // bridge outward send entry point
    pub bridge_outward: Sender<BridgeMessage>,
    // progress indicator
    pub progress: Arc<AtomicBool>,
    // session progress indicator
    pub session_progress: Arc<AtomicBool>,
    // final output
    pub output: Sender<Vec<u8>>,
    pub timeout: Timeout,
    pub recv_timeout: Duration,
    pub terminate: Box<dyn Sync + ClonableSendableFuture<()> + Unpin>,
}

impl<Timeout, T> RecvProcess<Timeout>
where
    T: 'static + Send + Future<Output = ()>,
    Timeout: 'static + Send + Sync + Fn(Duration) -> T,
{
    pub async fn process_recv(mut self) -> Result<(), SessionError> {
        loop {
            trace!("stream {}: poll_recv: polling", self.stream);
            let QuorumResolve {
                serial,
                data,
                errors,
            } = select! {
                front = self.recv_queue.poll().fuse() => {
                    trace!("poll_recv: next is available");
                    front
                },
                _ = ClonableSendableFuture::clone_pin_box(&*self.terminate).fuse() => return Ok(()),
                _ = (self.timeout)(self.recv_timeout).fuse() => {
                    // timeout
                    warn!("stream {}: poll_recv: next is timeout", self.stream);
                    continue
                }
            };
            // hall of shame
            info!("stream {}: poll_recv: good packet {}", self.stream, serial); // TODO: REMOVE
            let (err, out, bridge_out) = join!(
                self.error_reports.send(StreamErrorReport {
                    stream: self.stream,
                    serial,
                    errors
                }),
                self.output.send(data),
                self.bridge_outward.send(BridgeMessage::PayloadFeedback {
                    stream: self.stream,
                    feedback: PayloadFeedback::Complete { serial },
                }),
            );
            err.map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()))?;
            out.map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()))?;
            bridge_out.map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()))?;
            self.progress.store(true, Ordering::Relaxed);
            self.session_progress.store(true, Ordering::Relaxed);
        }
    }
}
