use super::*;

use core::{
    mem::{transmute, MaybeUninit},
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, Ordering::*},
};

use rand::{prelude::*, rngs::OsRng};

use crate::utils::make_arc_clone;

struct Quorum {
    vote: [AtomicPtr<Box<[u8]>>; 256],
    incoherent: [AtomicBool; 256],
    quorum_size: AtomicU8,
}

impl Quorum {
    fn new() -> Self {
        let mut vote: [MaybeUninit<AtomicPtr<Vec<u8>>>; 256] =
            unsafe { MaybeUninit::uninit().assume_init() };
        let mut incoherent: [MaybeUninit<AtomicBool>; 256] =
            unsafe { MaybeUninit::uninit().assume_init() };
        for v in &mut vote[..] {
            *v = MaybeUninit::new(AtomicPtr::default());
        }
        for ic in &mut incoherent[..] {
            *ic = MaybeUninit::new(AtomicBool::default());
        }
        Self {
            vote: unsafe { transmute(vote) },
            incoherent: unsafe { transmute(incoherent) },
            quorum_size: <_>::default(),
        }
    }
    fn insert(&self, shard: Shard) -> Result<(u8, u8), QuorumError> {
        let Shard { id, data } = shard;
        let data = Arc::new(data.into_boxed_slice());
        loop {
            if self.incoherent[id as usize].load(Relaxed) {
                return Err(QuorumError::Mismatch(id));
            }
            let old = self.vote[id as usize].load(Acquire);
            if let Some(old_data) = make_arc_clone(old) {
                if *old_data == *data {
                    return Err(QuorumError::Duplicate(id, self.quorum_size.load(Relaxed)));
                } else {
                    self.incoherent[id as usize].store(true, Relaxed);
                    return Err(QuorumError::Mismatch(id));
                }
            } else {
                let new = Arc::into_raw(Arc::clone(&data)) as _;
                if let Ok(_) =
                    self.vote[id as usize].compare_exchange_weak(old, new, Release, Relaxed)
                {
                    let quorum_size = 1 + self.quorum_size.fetch_add(1, Relaxed);
                    return Ok((id, quorum_size));
                } else {
                    unsafe {
                        Arc::from_raw(new);
                    }
                }
            }
        }
    }
    fn poll(&self) -> Option<Vec<PartialCode>> {
        let mut shards = vec![];
        for i in 0..255 {
            if self.incoherent[i].load(Relaxed) {
                continue;
            }
            if let Some(data) = make_arc_clone(self.vote[i].load(Acquire)) {
                let data = &*data;
                shards.push((i, data.clone()));
            }
        }
        let mut data_len = 0;
        let mut majority = 0;
        for (_, shard) in &shards {
            if data_len == shard.len() {
                majority += 1;
            } else if majority > 1 {
                majority -= 1;
            } else {
                data_len = shard.len();
                majority = 1;
            }
        }
        let mut codes = vec![PartialCode::default(); data_len];
        for (cid, data) in shards {
            if data_len == data.len() {
                for (&val, code) in data.iter().zip(&mut codes) {
                    code[cid] = Some(val);
                }
            }
        }
        Some(codes)
    }
}

impl Drop for Quorum {
    fn drop(&mut self) {
        for v in &self.vote[..] {
            let v = v.load(Acquire);
            if v.is_null() {
                continue;
            }
            unsafe {
                Arc::from_raw(v);
            }
        }
    }
}

pub struct QuorumResolve {
    pub data: Vec<u8>,
    pub serial: u64,
    pub errors: Vec<u8>,
}

enum QuorumStateInner {
    Resolved {
        data: Vec<u8>,
        serial: u64,
        errors: Vec<u8>,
    },
    Pooling {
        quorum: Quorum,
        serial: u64,
    },
}

#[derive(Default)]
pub struct QuorumState {
    inner: AtomicPtr<QuorumStateInner>,
}

impl Drop for QuorumState {
    fn drop(&mut self) {
        let inner = self.inner.load(Acquire);
        if inner.is_null() {
            return;
        }
        unsafe {
            Arc::from_raw(inner);
        }
    }
}

impl QuorumState {
    pub fn try_resolve(&self) -> Option<QuorumResolve> {
        let inner = self.inner.load(Acquire);
        if let Some(inner) = make_arc_clone(inner) {
            if let QuorumStateInner::Resolved {
                data,
                serial,
                errors,
            } = &*inner
            {
                Some(QuorumResolve {
                    data: data.clone(),
                    serial: *serial,
                    errors: errors.clone(),
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    fn try_decode(
        quorum_size: u8,
        codes: &[PartialCode],
        codec: &RSCodec,
    ) -> Result<(Vec<u8>, Vec<u8>), QuorumError> {
        let mut all_errors = HashSet::new();
        let mut result = vec![];
        for (block, report) in codec
            .decode(&codes)
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
                    if quorum_size == 255 {
                        return Err(QuorumError::Lost);
                    } else {
                        return Err(QuorumError::Absent {
                            threshold: codec.threshold() as u8,
                            current: quorum_size,
                            block: Some(block),
                        });
                    }
                }
            }
        }
        Ok((result, all_errors.into_iter().collect()))
    }

    fn replace_or_resolve(&self, resolved: QuorumStateInner) {
        let mut resolved = Arc::new(resolved);
        loop {
            let inner_ptr = self.inner.load(Relaxed);
            if let Some(inner) = make_arc_clone(inner_ptr) {
                let inner = &*inner;
                if let QuorumStateInner::Resolved { .. } = &*inner {
                    return;
                }
            }
            let resolved_ptr = Arc::into_raw(resolved) as _;
            if let Ok(_) =
                self.inner
                    .compare_exchange_weak(inner_ptr, resolved_ptr, Release, Relaxed)
            {
                if !inner_ptr.is_null() {
                    unsafe {
                        Arc::from_raw(inner_ptr);
                    }
                }
                return;
            } else {
                unsafe {
                    resolved = Arc::from_raw(resolved_ptr);
                }
            }
        }
    }

    fn resolve(&self, serial: u64, data: Vec<u8>, errors: Vec<u8>) {
        self.replace_or_resolve(QuorumStateInner::Resolved {
            data,
            serial,
            errors,
        });
    }

    pub fn insert(
        &self,
        serial: u64,
        shard: Verified<Shard>,
        rs: &RSCodec,
    ) -> Result<(), QuorumError> {
        if let Some(inner) = make_arc_clone(self.inner.load(Relaxed)) {
            match &*inner {
                QuorumStateInner::Resolved { .. } => Ok(()),
                QuorumStateInner::Pooling {
                    serial: serial_,
                    quorum,
                } if serial == *serial_ => {
                    let shard = shard.into_inner();
                    let (_, quorum_size) = quorum.insert(shard)?;
                    if quorum_size >= rs.threshold() as u8 {
                        if let Some(codes) = quorum.poll() {
                            let (result, errors) = Self::try_decode(quorum_size, &codes, rs)?;
                            self.resolve(serial, result, errors);
                            return Ok(());
                        }
                    }
                    Err(QuorumError::Absent {
                        threshold: rs.threshold() as u8,
                        current: quorum_size,
                        block: None,
                    })
                }
                _ => Err(QuorumError::Mismatch(shard.id)),
            }
        } else {
            let quorum = Quorum::new();
            let shard = shard.into_inner();
            let (_, quorum_size) = quorum
                .insert(shard)
                .expect("first insert should be successful");
            let result = if quorum_size >= rs.threshold() as u8 {
                let codes = quorum.poll().expect("first poll should be successful");
                match Self::try_decode(quorum_size, &codes, rs) {
                    Ok((result, errors)) => {
                        self.resolve(serial, result, errors);
                        return Ok(());
                    }
                    Err(e) => Err(e),
                }
            } else {
                Err(QuorumError::Absent {
                    threshold: rs.threshold() as u8,
                    current: quorum_size,
                    block: None,
                })
            };

            self.replace_or_resolve(QuorumStateInner::Pooling { serial, quorum });
            result
        }
    }
}

fn _send_and_sync()
where
    Quorum: Send + Sync,
{
}
