use std::{
    collections::{HashSet, VecDeque},
    mem::{transmute, MaybeUninit},
    num::Wrapping,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use aead::{Aead, NewAead, Payload};
use aes_gcm_siv::Aes256GcmSiv;
use async_std::sync::{Arc, Mutex, RwLock, Weak};
use crossbeam::queue::ArrayQueue;
use failure::{Backtrace, Fail};
use futures::{channel::mpsc::unbounded, future::BoxFuture, prelude::*, select};
use generic_array::GenericArray;
use lazy_static::lazy_static;
use log::trace;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use rayon::prelude::*;
use sha3::{Digest, Sha3_512};
use sss::{
    field::GF2561D,
    fourier::{GF2561DG2_255_FFT, GF2561DG2_UNITY_ROOT},
    reed_solomon::{DecodeError, ReedSolomon},
};

use crate::{
    common::{Verifiable, Verified},
    GenericError,
};

lazy_static! {
    static ref RS_255_223: ReedSolomon<GF2561D> =
        ReedSolomon::new(16, GF2561DG2_UNITY_ROOT.clone(), GF2561DG2_255_FFT.clone());
}

#[derive(Clone)]
pub struct RSCodec {
    data: u8,
    codec: ReedSolomon<GF2561D>,
}

#[derive(Fail, Debug)]
pub enum CodecError {
    #[fail(display = "invalid codec config")]
    RSCodec,
    #[fail(display = "reed solomon: {}", _0)]
    RS(#[cause] DecodeError, Backtrace),
}

#[derive(Clone, Copy, From)]
pub struct Code([u8; 255]);

impl Code {
    fn from_vec(v: Vec<u8>) -> Self {
        assert_eq!(v.len(), 255);
        let mut code = [0u8; 255];
        for (c, v) in code.iter_mut().zip(v) {
            *c = v;
        }
        Self(code)
    }
}

impl Deref for Code {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for Code {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub enum DecodeReport {
    TooManyError,
    Decode { data: Vec<u8>, errors: Vec<u8> },
    Malformed { data: Vec<u8>, errors: Vec<u8> },
}

#[derive(Clone, Copy)]
pub struct PartialCode([Option<u8>; 255]);

impl Default for PartialCode {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialCode {
    pub fn new() -> Self {
        Self([None; 255])
    }
}

impl Deref for PartialCode {
    type Target = [Option<u8>];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[Option<u8>]> for PartialCode {
    fn as_ref(&self) -> &[Option<u8>] {
        &self.0
    }
}

impl DerefMut for PartialCode {
    fn deref_mut(&mut self) -> &mut [Option<u8>] {
        &mut self.0
    }
}

impl RSCodec {
    pub fn new(correction: u8) -> Result<Self, CodecError> {
        if correction as u16 * 2 > 255 {
            Err(CodecError::RSCodec)
        } else {
            Ok(Self {
                data: 255 - ((correction as u16 * 2) as u8),
                codec: ReedSolomon::new(
                    correction as usize,
                    GF2561DG2_UNITY_ROOT.clone(),
                    GF2561DG2_255_FFT.clone(),
                ),
            })
        }
    }

    pub fn threshold(&self) -> usize {
        self.data as usize
    }

    pub fn encode(&self, input: &[u8]) -> Result<Vec<Code>, CodecError> {
        let codes = input
            .par_iter()
            .chunks(self.data as usize - 1)
            .map(|input| {
                let len = input.len() as u8;
                let input: Vec<_> = input
                    .iter()
                    .map(|&&c| c)
                    .chain((0..self.data - len).map(|_| len))
                    .map(|c| GF2561D(c))
                    .collect();
                let code = self
                    .codec
                    .encode(&input)
                    .map_err(|e| CodecError::RS(e, Backtrace::new()))?;
                let code = code.into_iter().map(|GF2561D(c)| c).collect();
                Ok(Code::from_vec(code))
            })
            .collect::<Result<_, _>>()?;
        Ok(codes)
    }

    pub fn decode(&self, input: &[PartialCode]) -> Result<Vec<DecodeReport>, CodecError> {
        let reports = input
            .into_par_iter()
            .map(|input| {
                let mut word = [GF2561D(0); 255];
                let mut erasures = vec![];
                for (i, c) in input.iter().enumerate() {
                    match c {
                        Some(c) => word[i] = GF2561D(*c),
                        None => {
                            erasures.push(i);
                        }
                    }
                }
                match self.codec.decode(word.to_vec(), erasures) {
                    Ok(result) => {
                        let GF2561D(orig_len) = result[self.data as usize - 1];
                        let errors = result.error_positions().iter().map(|&c| c as u8).collect();
                        if orig_len > self.data {
                            Ok(DecodeReport::Malformed {
                                data: result[..].iter().map(|&GF2561D(c)| c).collect(),
                                errors,
                            })
                        } else {
                            if result[orig_len as usize..]
                                .iter()
                                .all(|&GF2561D(c)| c == orig_len)
                            {
                                Ok(DecodeReport::Decode {
                                    data: result[..orig_len as usize]
                                        .iter()
                                        .map(|&GF2561D(c)| c)
                                        .collect(),
                                    errors,
                                })
                            } else {
                                Ok(DecodeReport::Malformed {
                                    data: result[..].iter().map(|&GF2561D(c)| c).collect(),
                                    errors,
                                })
                            }
                        }
                    }
                    Err(DecodeError::TooManyError(..)) => Ok(DecodeReport::TooManyError),
                    Err(e) => Err(CodecError::RS(e, Backtrace::new())),
                }
            })
            .collect::<Result<_, _>>()?;
        Ok(reports)
    }
}

#[derive(Clone, Debug)]
pub struct Shard {
    id: u8,
    data: Vec<u8>,
}

impl Deref for Shard {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl Shard {
    pub fn from_codes(codes: Vec<Code>) -> [Shard; 255] {
        let mut result: [MaybeUninit<Self>; 255] = unsafe { MaybeUninit::uninit().assume_init() };
        result.par_iter_mut().enumerate().for_each(|(i, result)| {
            let shard = Shard {
                id: i as u8,
                data: codes.iter().map(|c| c[i]).collect(),
            };
            unsafe {
                result.as_mut_ptr().write(shard);
            }
        });
        unsafe { transmute(result) }
    }
}

#[derive(Default)]
pub struct Quorum {
    serial: Option<u64>,
    quorum: HashSet<u8>,
    data: Option<Vec<PartialCode>>,
}

#[derive(Fail, Debug)]
pub enum QuorumError {
    #[fail(display = "duplicate shard")]
    Duplicate(u8, u8),
    #[fail(display = "mismatch shard")]
    Mismatch(u8),
    #[fail(display = "mismatch shard content")]
    MismatchContent(u8),
    #[fail(display = "threshold not met")]
    Absent(Option<usize>),
    #[fail(display = "malformed input")]
    Malformed { data: Vec<u8>, errors: Vec<u8> },
    #[fail(display = "reed solomon: {}", _0)]
    RS(#[cause] CodecError),
    #[fail(display = "completely lost")]
    Lost,
}

impl Quorum {
    /// ###Panic###
    /// Panics if `id` is out of range, ie. `id > 254`
    pub fn insert(&mut self, serial: u64, shard: Verified<Shard>) -> Result<(u8, u8), QuorumError> {
        let Shard { id, data } = shard.into_inner();
        if let Some(serial_) = &self.serial {
            if *serial_ != serial {
                return Err(QuorumError::Mismatch(id));
            }
        } else {
            self.serial = Some(serial)
        }
        if self.quorum.insert(id) {
            for (code, data) in self
                .data
                .get_or_insert_with(|| vec![<_>::default(); data.len()])
                .iter_mut()
                .zip(data)
            {
                code[id as usize] = Some(data)
            }
            Ok((id, self.quorum.len() as u8))
        } else {
            let quorum_data = self.data.as_ref().expect("to be initialized");
            if data.len() != quorum_data.len() {
                return Err(QuorumError::Mismatch(id));
            }
            for (code, data) in quorum_data.iter().zip(data) {
                if code[id as usize].expect("to be filled at this moment") != data {
                    return Err(QuorumError::MismatchContent(id));
                }
            }
            Err(QuorumError::Duplicate(id, quorum_data.len() as u8))
        }
    }

    pub fn poll(&self, codec: &RSCodec) -> Result<(u64, Vec<u8>, HashSet<u8>), QuorumError> {
        if self.quorum.len() < codec.data as usize {
            return Err(QuorumError::Absent(Some(codec.data as usize)));
        }
        let data = self
            .data
            .as_ref()
            .ok_or_else(|| QuorumError::Absent(None))?;
        let mut all_errors: HashSet<_> = <_>::default();
        let mut result = vec![];
        for (block, report) in codec
            .decode(&data)
            .map_err(QuorumError::RS)?
            .into_iter()
            .enumerate()
        {
            match report {
                DecodeReport::Malformed { data, errors } => {
                    return Err(QuorumError::Malformed { data, errors })
                }
                DecodeReport::Decode { data, errors } => {
                    result.extend(data);
                    all_errors.extend(errors);
                }
                DecodeReport::TooManyError => {
                    if self.quorum.len() == 255 {
                        return Err(QuorumError::Lost);
                    } else {
                        return Err(QuorumError::Absent(Some(block)));
                    }
                }
            }
        }
        Ok((self.serial.expect("should be set"), result, all_errors))
    }
}

#[derive(Fail, Debug)]
pub enum ShardError {
    #[fail(display = "mismatching id")]
    Mismatch(Backtrace),
    #[fail(display = "decrypt: {}", _0)]
    Decrypt(String),
}

pub struct ShardId {
    id: u8,
    serial: u64,
    key: [u8; 32],
    nonce: [u8; 12],
}

impl ShardId {
    pub fn to_aad(&self) -> Vec<u8> {
        let mut aad = vec![];
        aad.extend(b"id=");
        aad.extend(&self.id.to_le_bytes());
        aad.extend(b",serial=");
        aad.extend(&self.serial.to_le_bytes());
        aad.extend(b";;");
        aad
    }
}

#[derive(Clone)]
pub struct RawShard {
    pub raw_data: Vec<u8>,
}

impl Verifiable for RawShard {
    type Error = ShardError;
    type Proof = ShardId;
    type Output = Shard;
    fn verify(self, proof: Self::Proof) -> Result<Self::Output, Self::Error> {
        let RawShard { raw_data } = self;

        let aead = Aes256GcmSiv::new(GenericArray::clone_from_slice(&proof.key));
        let aad = proof.to_aad();
        let data = aead
            .decrypt(
                &GenericArray::clone_from_slice(&proof.nonce),
                Payload {
                    msg: raw_data.as_slice(),
                    aad: aad.as_slice(),
                },
            )
            .map_err(|e| ShardError::Decrypt(format!("{:?}", e)))?;

        if data[0] == proof.id && data[1..][..8] == proof.serial.to_le_bytes() {
            Ok(Shard {
                id: proof.id,
                data: data[9..].to_vec(),
            })
        } else {
            Err(ShardError::Mismatch(<_>::default()))
        }
    }
}

#[derive(Copy, Clone)]
pub struct RawShardId {
    pub id: u8,
    pub serial: u64,
    pub stream: u8,
}

#[derive(Default, Copy, Clone)]
pub struct ShardState {
    pub key: [u8; 32],
    pub stream_key: [u8; 32],
}

#[derive(Clone, Debug, Copy, Hash, PartialEq)]
struct ShardNonce([u8; 12]);

impl ShardNonce {
    fn new(state: &ShardState, id: u8, serial: u64) -> Self {
        let seed = state.seed(id, serial);
        let mut rng = ChaChaRng::from_seed(seed);
        rng.set_stream(serial);
        rng.set_word_pos(id as u128 * 2);
        let mut nonce = [0; 12];
        rng.fill_bytes(&mut nonce);
        Self(nonce)
    }
}

impl ShardState {
    fn seed(&self, id: u8, serial: u64) -> [u8; 32] {
        let mut rng = ChaChaRng::from_seed(self.key);
        rng.set_stream(serial);
        let mut word_pos = serial as u128;
        word_pos ^= (id as u128) << 64;
        word_pos += id as u128;
        rng.set_word_pos(word_pos);
        let mut sha3 = Sha3_512::new();
        sha3.input(&rng.next_u64().to_le_bytes());
        sha3.input(b",");
        sha3.input(&id.to_le_bytes());
        sha3.input(b";");
        sha3.input(&self.key);
        sha3.input(b", stream key ");
        sha3.input(&self.stream_key);
        let mut result = [0; 32];
        for chunk in sha3.result().chunks(32) {
            for (r, c) in result.iter_mut().zip(chunk) {
                *r ^= c
            }
        }
        result
    }
}

impl<'a> Verifiable for (RawShardId, &'a ShardState) {
    type Error = ShardError;
    type Proof = ();
    type Output = ShardId;
    fn verify(self, _: Self::Proof) -> Result<Self::Output, Self::Error> {
        let (RawShardId { id, serial, .. }, proof) = self;
        let ShardNonce(nonce) = ShardNonce::new(&proof, id, serial);
        let ShardState { key, .. } = proof;
        Ok(ShardId {
            id,
            serial,
            nonce,
            key: *key,
        })
    }
}

impl Shard {
    fn generate_shard_id(&self, serial: u64, state: &ShardState) -> ShardId {
        let ShardNonce(nonce) = ShardNonce::new(&state, self.id, serial);
        let ShardState { key, .. } = state;
        let Self { id, .. } = self;
        ShardId {
            key: *key,
            id: *id,
            nonce,
            serial,
        }
    }

    pub fn encode_shard(
        &self,
        stream: u8,
        serial: u64,
        state: &ShardState,
    ) -> (RawShard, RawShardId) {
        let proof = self.generate_shard_id(serial, state);
        let aead = Aes256GcmSiv::new(GenericArray::clone_from_slice(&proof.key));
        let aad = proof.to_aad();

        let mut data = vec![];
        data.extend(&[self.id]);
        data.extend(&serial.to_le_bytes());
        data.extend(&self.data);

        let raw_data = aead
            .encrypt(
                &GenericArray::clone_from_slice(&proof.nonce),
                Payload {
                    msg: data.as_slice(),
                    aad: aad.as_slice(),
                },
            )
            .map_err(|e| ShardError::Decrypt(format!("{:?}", e)))
            .expect("encryption should succeed; check data bounds");
        (
            RawShard { raw_data },
            RawShardId {
                id: self.id,
                serial: serial,
                stream,
            },
        )
    }
}

pub struct ReceiveQueue {
    queue: RwLock<VecDeque<Mutex<Quorum>>>,
    start: RwLock<Wrapping<u64>>,
    window: Option<u32>,
}

#[derive(Fail, Debug, From)]
pub enum ReceiveError {
    #[fail(display = "quorum: {}", _0)]
    Quorum(#[cause] QuorumError),
    #[fail(display = "queue is full, size={}", _0)]
    Full(usize),
    #[fail(display = "shard recovery: {}", _0)]
    Shard(#[cause] ShardError),
    #[fail(display = "out of bounds, size={}", _0)]
    OutOfBound(u64, usize),
}

impl ReceiveQueue {
    pub fn new() -> Self {
        Self {
            queue: <_>::default(),
            start: <_>::default(),
            window: <_>::default(),
        }
    }

    pub async fn admit(
        &self,
        raw_shard: RawShard,
        raw_shard_id: RawShardId,
        shard_state: &ShardState,
    ) -> Result<(u8, u8), ReceiveError> {
        let serial = raw_shard_id.serial;
        let shard_id = (raw_shard_id, shard_state).verify_proof(())?;
        let shard = raw_shard.clone().verify_proof(shard_id.into_inner())?;

        let window = self.window.unwrap_or(256) as usize;
        let start = self.start.read().await;
        let Wrapping(idx) = Wrapping(serial) - *start;
        let idx = idx as usize;
        if idx < 4 * window {
            let queue = self.queue.read().await;
            if idx >= queue.len() {
                drop(queue);
                let mut queue = self.queue.write().await;
                let len = queue.len();
                queue.resize_with(std::cmp::max(len, idx + 1), <_>::default);
            }
            let queue = self.queue.read().await;
            let mut q = queue[idx].lock().await;
            let result = q.insert(serial, shard)?;
            if idx > window {
                Err(ReceiveError::Full(queue.len()))
            } else {
                Ok(result)
            }
        } else {
            Err(ReceiveError::OutOfBound(
                start.0,
                self.queue.read().await.len(),
            ))
        }
    }

    pub async fn pop_front(&self) -> Option<Quorum> {
        let mut start = self.start.write().await;
        let mut queue = self.queue.write().await;
        if let Some(q) = queue.pop_front() {
            *start += Wrapping(1);
            Some(q.into_inner())
        } else {
            None
        }
    }

    pub async fn poll(
        &self,
        codec: &RSCodec,
    ) -> Option<Result<(u64, Vec<u8>, HashSet<u8>), QuorumError>> {
        let mut start = self.start.write().await;
        let mut queue = self.queue.write().await;
        if let Some(front) = queue.front() {
            let front = front.lock().await;
            let result = front.poll(&codec);
            if result.is_ok() {
                drop(front);
                *start += Wrapping(1);
                queue.pop_front();
            }
            Some(result)
        } else {
            None
        }
    }

    pub async fn reset(&self) {
        let mut start = self.start.write().await;
        let mut queue = self.queue.write().await;
        *start = Wrapping(0);
        queue.drain(..);
    }
}

#[derive(Fail, Debug, From)]
pub enum SendError {
    #[fail(display = "codec: {}", _0)]
    Codec(CodecError, Backtrace),
    #[fail(display = "remote lost")]
    RemoteLost(Backtrace),
    #[fail(display = "remote: {}", _0)]
    Remote(RemoteRecvError),
    #[fail(display = "broken pipe")]
    BrokenPipe,
    #[fail(display = "exhausted")]
    Exhausted,
}

#[derive(Fail, Debug)]
pub enum RemoteRecvError {
    #[fail(display = "receive complete code")]
    Complete,
    #[fail(display = "receive malformed code")]
    Malformed,
    #[fail(display = "decode failure")]
    Decode,
}

pub type TaskProgressNotifier =
    Weak<Mutex<dyn Sink<Result<(u8, u8), RemoteRecvError>, Error = GenericError> + Unpin + Send>>;

pub type TaskProgressNotifierSink =
    Box<dyn Sink<(u64, TaskProgressNotifier), Error = GenericError> + Unpin + Send>;

pub struct SendQueue {
    queue: RwLock<ArrayQueue<(RawShard, RawShardId)>>,
    stream: u8,
    serial: AtomicU64,
    task_notifiers: Mutex<TaskProgressNotifierSink>,
    window: usize,
    block_sending: Mutex<Option<BoxFuture<'static, ()>>>,
}

impl SendQueue {
    pub fn new(stream: u8, window: usize, task_notifiers: TaskProgressNotifierSink) -> Self {
        let task_notifiers = Mutex::new(task_notifiers);
        Self {
            stream,
            window,
            task_notifiers,
            serial: AtomicU64::default(),
            queue: RwLock::new(ArrayQueue::new(window)),
            block_sending: <_>::default(),
        }
    }

    pub async fn block_sending(&self, condition: impl 'static + Future<Output = ()> + Send) {
        *self.block_sending.lock().await = Some(condition.boxed())
    }

    pub async fn reset(&self) {
        let mut queue = self.queue.write().await;
        *queue = ArrayQueue::new(self.window);
    }

    pub async fn enqueue(
        &self,
        data: (RawShard, RawShardId),
    ) -> Result<(), (RawShard, RawShardId)> {
        use crossbeam::queue::PushError;

        let block_sending = self.block_sending.lock().await.take();
        if let Some(block_sending) = block_sending {
            block_sending.await
        }
        if let Err(PushError(data)) = self.queue.read().await.push(data) {
            Err(data)
        } else {
            Ok(())
        }
    }

    pub async fn pop(&self) -> Option<(RawShard, RawShardId)> {
        self.queue.read().await.pop().ok()
    }

    pub async fn send<Timeout>(
        &self,
        data: impl AsRef<[u8]>,
        shard_state: &ShardState,
        codec: &RSCodec,
        timeout_generator: impl Fn(Duration) -> Timeout,
        timeout: Duration,
    ) -> Result<(), SendError>
    where
        Timeout: Future,
    {
        let shards = Shard::from_codes(
            codec
                .encode(data.as_ref())
                .map_err(|e| SendError::Codec(e, <_>::default()))?,
        );
        let serial = self.serial.fetch_add(1, Ordering::Relaxed);
        let mut shards: Vec<_> = shards
            .iter()
            .map(|shard| shard.encode_shard(self.stream, serial, &shard_state))
            .collect();

        let (tx, rx) = unbounded();
        let tx = Arc::new(Mutex::new(tx.sink_map_err(|e| Box::new(e) as GenericError)));
        self.task_notifiers
            .lock()
            .await
            .send((serial, Arc::downgrade(&tx) as _))
            .await
            .map_err(|_| SendError::BrokenPipe)?;
        let mut status = rx.fuse();

        let threshold = codec.threshold();
        for (mut shard, mut shard_id) in shards.drain(..threshold) {
            loop {
                trace!("enqueue");
                if let Err((shard_, shard_id_)) = self.enqueue((shard, shard_id)).await {
                    shard = shard_;
                    shard_id = shard_id_;
                } else {
                    break;
                }
            }
        }

        // hear from the peer about how the reception goes
        let mut quorum = HashSet::new();
        for _ in 0..threshold {
            select! {
                status = status.next() => {
                    match status {
                        None => return Err(SendError::RemoteLost(<_>::default())),
                        Some(status) => match status {
                            Ok((id, quorum_size)) => {
                                quorum.insert(id);
                            }
                            Err(RemoteRecvError::Complete) => {
                                return Ok(())
                            }
                            Err(e) => {
                                return Err(SendError::Remote(e))
                            }
                        }
                    }
                },
                _ = timeout_generator(timeout).fuse() => break,
            }
        }

        // and we need to try harder now
        for (mut shard, mut shard_id) in shards {
            loop {
                trace!("enqueue");
                if let Err((shard_, shard_id_)) = self.enqueue((shard, shard_id)).await {
                    shard = shard_;
                    shard_id = shard_id_;
                } else {
                    break;
                }
            }
            select! {
                status = status.next() => {
                    match status {
                        None => return Err(SendError::RemoteLost(<_>::default())),
                        Some(status) => match status {
                            Ok((id, quorum_size)) => {
                                quorum.insert(id);
                            }
                            Err(RemoteRecvError::Complete) => {
                                return Ok(())
                            }
                            Err(e) => {
                                return Err(SendError::Remote(e))
                            }
                        }
                    }
                },
                _ = timeout_generator(timeout).fuse() => break,
            }
        }
        // okay, maybe we have to drop it
        Err(SendError::Exhausted)
    }
}

pub fn signature_hasher(input: Vec<u8>) -> Vec<u8> {
    sha3::Sha3_512::digest(&input).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let codec = RSCodec::new(31).unwrap();
        let recv_q = ReceiveQueue::new();
        let input_data = &[33, 55, 23, 251];
        let shards = Shard::from_codes(codec.encode(input_data).unwrap());
        let mut key = [0; 32];
        let mut stream_key = [0; 32];
        for i in 0..32 {
            key[i as usize] = i;
            stream_key[i as usize] = 32 - i;
        }
        let state = ShardState { key, stream_key };
        let stream = 0;
        let serial = 0;
        futures::stream::iter(shards.iter().take(193))
            .map(|shard| {
                let (raw_shard, raw_shard_id) = shard.encode_shard(stream, serial, &state);
                recv_q.admit(raw_shard, raw_shard_id, &state)
            })
            .buffer_unordered(20)
            .try_collect::<Vec<_>>()
            .await?;
        let (serial_, result, _) = recv_q.poll(&codec).await.unwrap()?;
        assert_eq!(serial, serial_);
        assert_eq!(result, input_data);
        Ok(())
    }
}
