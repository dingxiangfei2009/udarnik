use super::*;

pub struct FeedbackProcess<Timeout> {
    pub task_notifiers: TaskProgressNotifierStore,
    // stream progress indicator
    pub progress: Arc<AtomicBool>,
    // session progress indicator
    pub session_progress: Arc<AtomicBool>,
    // send queue in order to enable blocking
    pub send_queue: Arc<SendQueue>,
    pub send_cooldown: Duration,
    pub window: usize,
    pub timeout_generator: Timeout,
}

impl<Timeout, T> FeedbackProcess<Timeout>
where
    T: 'static + Send + Future<Output = ()>,
    Timeout: 'static + Send + Sync + Fn(Duration) -> T,
{
    pub async fn process_feedback(&self, feedback: PayloadFeedback) -> Result<(), SessionError> {
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
                trace!("feedback: ok");
                if let Some(mut notifier) = task_notifiers
                    .get(&serial)
                    .and_then(|n| n.upgrade())
                    .map(|n| ClonableSink::clone_pin_box(&**n))
                {
                    if let Err(e) = notifier.send(Ok((id, quorum))).await {
                        debug!("notifer pipe: {}", e);
                    }
                }
                self.progress.store(true, Ordering::Relaxed);
                self.session_progress.store(true, Ordering::Relaxed);
            }
            PayloadFeedback::Duplicate { serial, id, quorum } => {
                trace!("feedback: duplicate");
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
                trace!("feedback: full");
                self.send_queue
                    .block_sending((self.timeout_generator)(self.send_cooldown));
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
                trace!("feedback: malform");
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
                trace!("feedback: complete");
                if let Some(mut notifier) = task_notifiers
                    .get(&serial)
                    .and_then(|n| n.upgrade())
                    .map(|n| ClonableSink::clone_pin_box(&**n))
                {
                    if let Err(e) = notifier.send(Err(RemoteRecvError::Complete)).await {
                        debug!("notifier pipe: {}", e);
                    }
                }
                self.progress.store(true, Ordering::Relaxed);
                self.session_progress.store(true, Ordering::Relaxed);
            }
        }
        Ok(())
    }
}
