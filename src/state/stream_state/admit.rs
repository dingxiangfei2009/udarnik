use super::*;

pub struct AdmitProcess {
    pub stream: u8,
    pub recv_queue: Arc<ReceiveQueue>,
    pub shard_state: Arc<ShardState>,
    pub bridge_outward: Sender<BridgeMessage>,
}

impl AdmitProcess {
    pub async fn admit_shard(
        &self,
        raw_shard: RawShard,
        raw_shard_id: RawShardId,
    ) -> Result<(), SessionError> {
        let serial = raw_shard_id.serial;
        let feedback = match self
            .recv_queue
            .admit(raw_shard, raw_shard_id, &self.shard_state)
            .await
        {
            Ok((id, quorum_size)) => {
                debug!(
                    "poll_admit: admitted, stream {} serial {} id {} quorum_size {}",
                    self.stream, serial, id, quorum_size
                );
                PayloadFeedback::Ok {
                    serial,
                    id,
                    quorum: quorum_size,
                }
            }
            Err(ReceiveError::Full(queue_len)) => {
                debug!("poll_admit: full");
                PayloadFeedback::Full { queue_len, serial }
            }
            Err(ReceiveError::OutOfBound(start, queue_len)) => {
                debug!(
                    "poll_admit: out of bound, serial={}, start={}, queue={}",
                    serial, start, queue_len
                );
                PayloadFeedback::OutOfBound {
                    start,
                    queue_len,
                    serial,
                }
            }
            Err(ReceiveError::Quorum(QuorumError::Duplicate(id, quorum))) => {
                debug!("poll_admit: duplicate");
                PayloadFeedback::Duplicate { serial, id, quorum }
            }
            Err(ReceiveError::Quorum(QuorumError::Malformed { .. }))
            | Err(ReceiveError::Quorum(QuorumError::MismatchContent(..))) => {
                debug!("poll_admit: data {} malformed/mismatch", serial);
                PayloadFeedback::Malformed { serial }
            }
            Err(e) => {
                error!("admission: {}", e);
                return Ok(());
            }
        };
        self.bridge_outward
            .clone()
            .send(BridgeMessage::PayloadFeedback {
                stream: self.stream,
                feedback,
            })
            .await
            .map_err(|e| SessionError::BrokenPipe(Box::new(e) as _, <_>::default()))
    }
}
