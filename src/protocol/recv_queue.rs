use super::*;

use core::{
    cmp::min,
    num::Wrapping,
    ptr::null_mut,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering::*},
};

use crossbeam::utils::CachePadded;

use crate::utils::make_arc_clone;

pub struct ReceiveQueue {
    q: Box<[CachePadded<AtomicPtr<QuorumState>>]>,
    readiness: Box<[CachePadded<Readiness>]>,
    dead: Box<[Arc<CachePadded<AtomicBool>>]>,
    window_mask: u64,
    window_size: usize,
    head: AtomicU64,
    deq_head: AtomicU64,

    vacant_ready: Readiness,
}

impl Drop for ReceiveQueue {
    fn drop(&mut self) {
        for q in &self.q[..] {
            let p = q.load(Relaxed);
            if p.is_null() {
                continue;
            }
            unsafe {
                Arc::from_raw(p);
            }
        }
    }
}

#[derive(Default)]
struct Readiness {
    m: AsyncMutex<()>,
    cv: Condvar,
}

impl Readiness {
    async fn signal_one<T>(&self, guard: T) {
        let _guard = self.m.lock().await;
        drop(guard);
        self.cv.notify_one();
    }
    async fn signal_all<T>(&self, guard: T) {
        let _guard = self.m.lock().await;
        drop(guard);
        self.cv.notify_all();
    }
}

struct Alive {
    dead_flag: Arc<CachePadded<AtomicBool>>,
}

impl Alive {
    fn birth(dead_flag: &Arc<CachePadded<AtomicBool>>) -> Self {
        Self {
            dead_flag: Arc::clone(dead_flag),
        }
    }
}

impl Drop for Alive {
    fn drop(&mut self) {
        self.dead_flag.store(true, Release);
    }
}

impl ReceiveQueue {
    /// window_pow: log2 of the window size, so window is always a power of 2
    pub fn new(window_pow: Option<u8>) -> Self {
        let window_pow = min(16, window_pow.unwrap_or(16));
        let window_size = 1 << window_pow;
        let window_mask = (window_size - 1) as u64;
        let window_size = window_size as usize;
        let q: Vec<_> = (0..window_size).map(|_| <_>::default()).collect();
        let readiness: Vec<_> = (0..window_size).map(|_| <_>::default()).collect();
        let dead: Vec<_> = (0..window_size).map(|_| <_>::default()).collect();
        Self {
            q: q.into_boxed_slice(),
            readiness: readiness.into_boxed_slice(),
            dead: dead.into_boxed_slice(),
            window_mask,
            window_size,
            head: <_>::default(),
            deq_head: <_>::default(),
            vacant_ready: <_>::default(),
        }
    }

    fn reset_slot(&self, slot: usize) {
        let new = Arc::new(QuorumState::default());
        let ptr = self.q[slot].load(Relaxed);
        let new_ptr = Arc::into_raw(Arc::clone(&new)) as _;
        if let Ok(_) = self.q[slot].compare_exchange(ptr, new_ptr, Release, Relaxed) {
            if !ptr.is_null() {
                unsafe {
                    Arc::from_raw(ptr);
                }
            }
        } else {
            unsafe {
                Arc::from_raw(new_ptr);
            }
        }
    }

    async fn clean_up_dead_from_head(&self) {
        loop {
            let head = self.head.load(Relaxed);
            let Wrapping(next_head) = Wrapping(head) + Wrapping(1);
            let slot = (head & self.window_mask) as usize;
            if self.dead[slot].load(SeqCst) {
                if let Err(_) = self
                    .head
                    .compare_exchange_weak(head, next_head, SeqCst, Relaxed)
                {
                    continue;
                }
                self.reset_slot(slot);
                self.dead[slot].store(false, SeqCst);
                self.vacant_ready.signal_one(()).await;
            } else {
                break;
            }
        }
    }

    fn ensure_init_slab(&self, slot: usize) -> Arc<QuorumState> {
        let slab = Arc::new(QuorumState::default());
        loop {
            if let Some(slab) = make_arc_clone(self.q[slot].load(Acquire)) {
                break slab;
            } else {
                let slab_ptr = Arc::into_raw(Arc::clone(&slab)) as _;
                if let Ok(_) =
                    self.q[slot].compare_exchange_weak(null_mut(), slab_ptr, Release, Relaxed)
                {
                    break slab;
                } else {
                    unsafe {
                        Arc::from_raw(slab_ptr);
                    }
                }
            }
        }
    }

    pub async fn admit(
        &self,
        raw_shard: RawShard,
        raw_shard_id: RawShardId,
        shard_state: &ShardState,
        codec: &RSCodec,
    ) -> Result<(), ReceiveError> {
        self.clean_up_dead_from_head().await;
        let serial = raw_shard_id.serial;
        let shard_id = (raw_shard_id, shard_state)
            .verify_proof(())
            .map_err(ReceiveError::Shard)?;
        let shard = raw_shard
            .clone()
            .verify_proof(shard_id.into_inner())
            .map_err(ReceiveError::Shard)?;

        let slot = (serial & self.window_mask) as usize;

        if self.dead[slot].load(SeqCst) {
            trace!(
                "out of bound, head {} serial {} window {}",
                self.head.load(Relaxed),
                serial,
                self.window_size
            );
            return Err(ReceiveError::OutOfBound(serial, self.window_size as usize));
        }

        if let Err(head) = self.is_serial_out_of_bound(serial) {
            trace!(
                "out of bound, head {} serial {} window {}",
                head,
                serial,
                self.window_size
            );
            return Err(ReceiveError::OutOfBound(serial, self.window_size as usize));
        }
        while self.dead[slot].load(SeqCst) {}
        let slab = self.ensure_init_slab(slot);
        if let Err(head) = self.is_serial_out_of_bound(serial) {
            trace!(
                "oob, head {} serial {} window {}",
                head,
                serial,
                self.window_size
            );
            return Err(ReceiveError::OutOfBound(serial, self.window_size as usize));
        }
        trace!("admitting");
        slab.insert(serial, shard, codec)
            .map_err(ReceiveError::Quorum)?;
        trace!("threshold reached");
        Ok(self.readiness[slot].signal_all(()).await)
    }

    fn is_serial_out_of_bound(&self, serial: u64) -> Result<(), u64> {
        let head = self.head.load(SeqCst);
        let Wrapping(diff) = Wrapping(serial) - Wrapping(head);
        if diff >= self.window_size as u64 {
            Err(head)
        } else {
            Ok(())
        }
    }

    fn try_claim_poll_head(&self) -> Option<u64> {
        let slot = self.deq_head.load(Relaxed);
        let Wrapping(next_slot) = Wrapping(slot) + Wrapping(1);
        let head = self.head.load(SeqCst);
        let Wrapping(diff) = Wrapping(slot) - Wrapping(head);
        if diff < self.window_size as u64 {
            if let Ok(_) = self
                .deq_head
                .compare_exchange_weak(slot, next_slot, SeqCst, Relaxed)
            {
                return Some(slot);
            }
        }
        None
    }

    async fn claim_poll_head(&self) -> u64 {
        loop {
            for _ in 0..1000 {
                if let Some(slot) = self.try_claim_poll_head() {
                    return slot;
                }
            }
            let guard = self.vacant_ready.m.lock().await;
            if let Some(slot) = self.try_claim_poll_head() {
                return slot;
            } else {
                self.vacant_ready.cv.wait(guard).await;
            }
        }
    }

    pub async fn poll(&self) -> QuorumResolve {
        self.clean_up_dead_from_head().await;
        let deq_head = self.claim_poll_head().await;
        let slot = (deq_head & self.window_mask) as usize;
        while self.dead[slot].load(Acquire) {}
        let _alive = Alive::birth(&self.dead[slot]);
        let state = self.ensure_init_slab(slot);
        let mut count = 1000;
        loop {
            if let Some(result) = state.try_resolve() {
                assert_eq!(result.serial, deq_head);
                return result;
            }
            count -= 1;
            if count == 0 {
                let guard = self.readiness[slot].m.lock().await;
                if let Some(result) = state.try_resolve() {
                    assert_eq!(result.serial, deq_head);
                    return result;
                } else {
                    self.readiness[slot].cv.wait(guard).await;
                    count = 1000;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::stream::iter;
    use rand::rngs::OsRng;

    #[test]
    fn it_works() {
        let codec = RSCodec::new(16).unwrap();
        let input_data = &[33, 55, 23, 251];
        let send = codec.encode(input_data).unwrap();
        let mut recvs = vec![];
        for send in send.iter() {
            let mut recv = PartialCode::new();
            for (recv, send) in recv.iter_mut().zip(send.iter()) {
                *recv = Some(*send)
            }
            recvs.push(recv)
        }
        recvs[0][0] = None;
        for recv in codec.decode(&recvs).unwrap() {
            match recv {
                DecodeReport::Decode { data, errors } => {
                    assert_eq!(data, input_data);
                    assert_eq!(&[0], &*errors)
                }
                _ => panic!(),
            }
        }
    }

    #[tokio::test]
    async fn send_receive() -> Result<(), ReceiveError> {
        let _guard = slog_envlogger::init();
        let codec = RSCodec::new(31).unwrap();
        let recv_q = Arc::new(ReceiveQueue::new(Some(4)));
        let mut input_data = [0u8; 1500];
        OsRng.fill_bytes(&mut input_data);
        let shards = Shard::from_codes(codec.encode(&input_data).unwrap());
        let mut key = [0; 32];
        let mut stream_key = [0; 32];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut stream_key);
        let state = ShardState { key, stream_key };
        let stream = 0u8;
        let handle = async_std::task::spawn({
            let recv_q = Arc::clone(&recv_q);
            async move {
                loop {
                    let QuorumResolve { serial, data, .. } = recv_q.poll().await;
                    println!("serial {} data_len {}", serial, data.len());
                    assert_eq!(&data[..], &input_data[..], "data mismatch, {}", serial);
                }
            }
        });
        iter(0u64..)
            .map(|serial| {
                let recv_q = &recv_q;
                let codec = &codec;
                iter(shards.iter().take(193).cloned()).for_each_concurrent(
                    8,
                    move |shard| async move {
                        let (raw_shard, raw_shard_id) = shard.encode_shard(stream, serial, &state);
                        let _ = recv_q.admit(raw_shard, raw_shard_id, &state, codec).await;
                    },
                )
            })
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        handle.await;
        Ok(())
    }
}
