use core::{
    mem::{transmute, MaybeUninit},
    ops::{Deref, DerefMut},
    time::Duration,
};
use std::{
    collections::HashSet,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Weak},
};

use aead::{Aead, NewAead, Payload};
use async_std::sync::{
    channel as mpmc_channel, Condvar, Mutex as AsyncMutex, Receiver as MPMCReceiver,
    Sender as MPMCSender,
};
use backtrace::Backtrace as Bt;
use chacha20poly1305::ChaCha20Poly1305;
use futures::{channel::mpsc::channel, future::BoxFuture, pin_mut, prelude::*, select_biased};
use generic_array::GenericArray;
use lazy_static::lazy_static;
use log::{debug, trace, warn};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use rayon::prelude::*;
use sha3::{Digest, Sha3_512};
use sss::{
    field::GF2561D,
    fourier::{GF2561DG2_255_FFT, GF2561DG2_UNITY_ROOT},
    reed_solomon::{DecodeError, ReedSolomon},
};
use thiserror::Error;

use crate::{
    common::{Verifiable, Verified},
    utils::ClonableSink,
    GenericError,
};

mod quorum;
mod recv_queue;
mod send_queue;

use self::quorum::QuorumState;
pub use self::{quorum::QuorumResolve, recv_queue::ReceiveQueue, send_queue::SendQueue};

lazy_static! {
    static ref RS_255_223: ReedSolomon<GF2561D> =
        ReedSolomon::new(16, GF2561DG2_UNITY_ROOT.clone(), GF2561DG2_255_FFT.clone());
}

#[derive(Clone)]
pub struct RSCodec {
    data: u8,
    codec: ReedSolomon<GF2561D>,
}

#[derive(Error, Debug)]
pub enum CodecError {
    #[error("invalid codec config")]
    RSCodec,
    #[error("reed solomon: {0}, backtrace: {1:?}")]
    RS(DecodeError, Bt),
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
                    .map_err(|e| CodecError::RS(e, Bt::new()))?;
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
                    Err(e) => Err(CodecError::RS(e, Bt::new())),
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

#[derive(Error, Debug)]
pub enum QuorumError {
    #[error("duplicate shard")]
    Duplicate(u8, u8),
    #[error("mismatch shard")]
    Mismatch(u8),
    #[error("mismatch shard content")]
    MismatchContent(u8),
    #[error("threshold not met: threshold={threshold}, current={current}, block={block:?}")]
    Absent {
        threshold: u8,
        current: u8,
        block: Option<usize>,
    },
    #[error("malformed input")]
    Malformed { data: Vec<u8>, errors: Vec<u8> },
    #[error("reed solomon: {0}")]
    RS(#[from] CodecError),
    #[error("completely lost")]
    Lost,
}

#[derive(Error, Debug)]
pub enum ShardError {
    #[error("mismatching id")]
    Mismatch(Bt),
    #[error("decrypt: {0}")]
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

        let aead = ChaCha20Poly1305::new(&GenericArray::clone_from_slice(&proof.key));
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
        sha3.update(&rng.next_u64().to_le_bytes());
        sha3.update(b",");
        sha3.update(&id.to_le_bytes());
        sha3.update(b";");
        sha3.update(&self.key);
        sha3.update(b", stream key ");
        sha3.update(&self.stream_key);
        let mut result = [0; 32];
        for chunk in sha3.finalize().chunks(32) {
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
        let aead = ChaCha20Poly1305::new(&GenericArray::clone_from_slice(&proof.key));
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
                serial,
                stream,
            },
        )
    }
}

#[derive(Error, Debug)]
pub enum SendError {
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    #[error("remote lost, backtrace: {0:?}")]
    RemoteLost(Bt),
    #[error("remote: {0}")]
    Remote(#[from] RemoteRecvError),
    #[error("broken pipe")]
    BrokenPipe,
    #[error("exhausted")]
    Exhausted,
}

#[derive(Error, Debug)]
pub enum ReceiveError {
    #[error("quorum: {0}")]
    Quorum(#[from] QuorumError),
    #[error("queue is full, size={0}")]
    Full(usize),
    #[error("shard recovery: {0}")]
    Shard(#[from] ShardError),
    #[error("out of bounds, size={0}")]
    OutOfBound(u64, usize),
}

#[derive(Error, Debug)]
pub enum RemoteRecvError {
    #[error("receive complete code")]
    Complete,
    #[error("receive malformed code")]
    Malformed,
    #[error("decode failure")]
    Decode,
}

pub type TaskProgressNotifier =
    Weak<Box<dyn ClonableSink<Result<(u8, u8), RemoteRecvError>, GenericError> + Send + Sync>>;

pub type TaskProgressNotifierSink =
    Box<dyn ClonableSink<(u64, TaskProgressNotifier), GenericError> + Unpin + Send + Sync>;

pub fn signature_hasher(input: Vec<u8>) -> Vec<u8> {
    sha3::Sha3_512::digest(&input).to_vec()
}
