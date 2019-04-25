use curve25519_dalek::{constants, edwards::EdwardsPoint, scalar::Scalar, traits::Identity};
use failure::Fail;
use rand::{CryptoRng, Error as RngError, RngCore};
use sha3::digest::{FixedOutput, Input};
use sha3::Sha3_256;

use crate::common::{Verifiable, Verified};

pub mod dleq;

fn ed25519_base_mul(s: &Scalar) -> EdwardsPoint {
    constants::ED25519_BASEPOINT_POINT * s
}

fn random_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Scalar, Error> {
    let mut v = [0u8; 32];
    rng.try_fill_bytes(&mut v)?;
    Ok(Scalar::from_bytes_mod_order(v))
}

pub fn u64_to_scalar(value: u64) -> Scalar {
    let mut v = [0u8; 32];
    v[0..8].copy_from_slice(&value.to_le_bytes());
    Scalar::from_bytes_mod_order(v)
}

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "rng error: {}", _0)]
    Rng(#[cause] RngError),
    #[fail(display = "there should be at least one custodian")]
    ZeroCustodian,
    #[fail(display = "custodian id is zero")]
    ZeroCustodianId,
    #[fail(display = "custodian id is invalid")]
    InvalidCustodianId(u64),
    #[fail(display = "custodian id is invalid")]
    InvalidCustodianProof(dleq::Error),
    #[fail(display = "no enough custodian")]
    NoEnoughCustodian { allocated: usize, requested: usize },
    #[fail(display = "invalid dealer proof: {}", _0)]
    InvalidDealerProof(dleq::Error),
}

impl From<RngError> for Error {
    fn from(err: RngError) -> Self {
        Error::Rng(err)
    }
}

pub struct Polynomial(Vec<Scalar>);

impl Polynomial {
    /// A polynomial with coefficients in Ed25519
    fn new<R: CryptoRng + RngCore>(
        rng: &mut R,
        degree: usize,
        r#const: [u8; 32],
    ) -> Result<Self, Error> {
        assert!(degree > 0, "degree must be positive");
        let size = degree * 32;
        let mut coef = Vec::with_capacity(size);
        coef.resize(size, 0);
        rng.try_fill_bytes(&mut coef[32..])?;
        coef[0..32].copy_from_slice(&r#const[..]);
        let coef = coef
            .as_slice()
            .chunks(32)
            .map(|chunk| {
                let mut c = [0u8; 32];
                c.copy_from_slice(chunk);
                Scalar::from_bytes_mod_order(c)
            })
            .collect();
        Ok(Polynomial(coef))
    }

    fn eval(&self, x: &Scalar) -> Scalar {
        let mut acc = Scalar::zero();
        for a in self.0.iter().rev() {
            acc *= x;
            acc += a;
        }
        acc
    }
}

#[derive(PartialEq, Eq)]
pub struct Custodian {
    id: u64,
    key: EdwardsPoint,
}

impl std::cmp::PartialOrd for Custodian {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(<u64 as std::cmp::Ord>::cmp(&self.id, &other.id))
    }
}

impl std::cmp::Ord for Custodian {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        <u64 as std::cmp::Ord>::cmp(&self.id, &other.id)
    }
}

impl Verifiable for Vec<Custodian> {
    type Error = Error;
    type Proof = ();
    fn verify(mut self, _: ()) -> Result<Self, Self::Error> {
        if self.len() == 0 {
            return Err(Error::ZeroCustodian);
        }
        self.sort();
        self.dedup();
        Ok(self)
    }
}

pub struct Shard {
    pub id: u64,
    pub value: EdwardsPoint,
}

impl Shard {
    pub fn new(p: &Polynomial, id: u64, key: &EdwardsPoint) -> (Self, Scalar) {
        let eval = p.eval(&u64_to_scalar(id));
        let value = key * eval;
        (Self { id, value }, eval)
    }
}

pub struct Seed(Scalar);

impl Seed {
    fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self, Error> {
        Ok(Self(random_scalar(rng)?))
    }
}

pub struct SignedSeed(EdwardsPoint);

impl SignedSeed {
    pub fn new(seed: &Seed, base: &EdwardsPoint) -> Self {
        let Seed(ref seed) = seed;
        Self(base * seed)
    }
}

#[derive(Clone)]
pub struct Commits(Vec<EdwardsPoint>);

impl Commits {
    fn new(p: &Polynomial) -> Self {
        Self(p.0.iter().map(ed25519_base_mul).collect())
    }
}

pub struct Challenge(Scalar);

impl Challenge {
    fn new(commits: &Commits, dealer_signed_seeds: &[SignedSeed], shards: &[Shard]) -> Self {
        let Commits(ref commits) = commits;
        let mut sha3 = Sha3_256::default();
        for commit in commits {
            sha3.input(commit.to_montgomery().as_bytes());
        }
        for SignedSeed(ref signed_seed) in dealer_signed_seeds {
            sha3.input(signed_seed.to_montgomery().as_bytes());
        }
        for shard in shards {
            sha3.input(shard.value.to_montgomery().as_bytes());
        }
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(sha3.fixed_result().as_slice());
        Self(Scalar::from_bytes_mod_order(challenge))
    }
}

pub struct Responses(Vec<Scalar>);

impl Responses {
    fn new(challenge: &Challenge, seeds: &[Seed], secret_shards: &[Scalar]) -> Self {
        let Challenge(ref challenge) = challenge;
        assert_eq!(
            seeds.len(),
            secret_shards.len(),
            "there should be equal number of seeds and shards"
        );
        Self(
            seeds
                .iter()
                .zip(secret_shards.iter())
                .map(|(Seed(ref seed), secret)| seed - challenge * secret)
                .collect(),
        )
    }
}

#[derive(Clone)]
pub struct ShardWithProof {
    id: u64,
    value: EdwardsPoint,
    dealer_signed_seed: EdwardsPoint,
    custodian_signed_seed: EdwardsPoint,
    custodian_key: EdwardsPoint,
    response: Scalar,
}

#[derive(Clone)]
pub struct ShardsWithProof {
    pub shards: Vec<ShardWithProof>,
    pub secret: EdwardsPoint,
    pub dealer_proof: DealerProof,
}

impl ShardsWithProof {
    pub fn new<R: CryptoRng + RngCore>(
        rng: &mut R,
        threshold: usize,
        custodian_base: &EdwardsPoint,
        custodians: &Verified<Vec<Custodian>>,
    ) -> Result<Self, Error> {
        let count = custodians.len();
        if count < threshold {
            return Err(Error::NoEnoughCustodian {
                allocated: count,
                requested: threshold,
            });
        }
        let mut secret = [0u8; 32];
        rng.try_fill_bytes(&mut secret)?;
        let polynomial = Polynomial::new(rng, count, secret)?;
        let secret = custodian_base * Scalar::from_bytes_mod_order(secret);

        let mut shards = Vec::with_capacity(count); // y_i ^ p(i)
        let mut secret_shards = Vec::with_capacity(count); // p(i) = sum{k_j * i^j | 0 <= j < d}

        for custodian in custodians.iter() {
            let (shard, secret_shard) = Shard::new(&polynomial, custodian.id, &custodian.key);
            shards.push(shard);
            secret_shards.push(secret_shard);
        }
        let mut seeds = Vec::with_capacity(count); // w_i
        let mut dealer_signed_seeds = Vec::with_capacity(count); // g ^ w_i
        let mut custodian_signed_seeds = Vec::with_capacity(count); // y_i ^ w_i
        for i in 0..count {
            let seed = Seed::new(rng)?;
            dealer_signed_seeds.push(SignedSeed::new(&seed, &constants::ED25519_BASEPOINT_POINT));
            custodian_signed_seeds.push(SignedSeed::new(&seed, &custodians[i].key));
            seeds.push(seed);
        }
        let commits = Commits::new(&polynomial); // g ^ k_d
        let challenge = Challenge::new(&commits, &dealer_signed_seeds, shards.as_slice()); // c
        let responses = Responses::new(&challenge, &seeds, secret_shards.as_slice()); // w_i - c * p(i)
        let shards = (0..count)
            .map(|i| ShardWithProof {
                id: shards[i].id,
                value: shards[i].value,
                dealer_signed_seed: dealer_signed_seeds[i].0,
                custodian_signed_seed: custodian_signed_seeds[i].0,
                custodian_key: custodians[i].key,
                response: responses.0[i],
            })
            .collect();
        let dealer_proof = DealerProof {
            challenge: challenge.0,
            commits,
        };

        Ok(Self {
            shards,
            secret,
            dealer_proof,
        })
    }
}

impl Verifiable for ShardWithProof {
    type Error = Error;
    type Proof = DealerProof;

    fn verify(self, proof: Self::Proof) -> Result<Self, Error> {
        let mut h1 = EdwardsPoint::identity();
        let id = u64_to_scalar(self.id);
        for commit in proof.commits.0.iter().rev() {
            h1 *= id;
            h1 += commit;
        }
        let dleq_proof = dleq::Proof {
            g1: constants::ED25519_BASEPOINT_POINT, // g
            g2: self.custodian_key,                 // y_i
            h1,                                     // g ^ p(i)
            h2: self.value,                         // y_i ^ p(i)
            a1: self.dealer_signed_seed,            // g ^ w_i
            a2: self.custodian_signed_seed,         // y_i ^ w_i
            challenge: proof.challenge,             // c
            response: self.response,                // w_i - c * p(i)
        };
        dleq_proof
            .verify_proof(())
            .map_err(|e| Error::InvalidDealerProof(e))?;
        Ok(self)
    }
}

#[derive(Clone)]
pub struct DealerProof {
    pub challenge: Scalar,
    pub commits: Commits,
}

pub struct CustodianDecryption {
    pub id: u64,
    pub recovered: EdwardsPoint,
}

impl CustodianDecryption {
    pub fn new<R: CryptoRng + RngCore>(
        rng: &mut R,
        custodian_base: &EdwardsPoint,
        private_key: &Scalar,
        shard: &Verified<ShardWithProof>,
    ) -> Result<(Self, CustodianProof), Error> {
        if shard.id == 0 {
            return Err(Error::ZeroCustodianId);
        }
        let id = shard.id;
        let recovered = shard.value * private_key.invert();
        let proof =
            CustodianProof::new(rng, custodian_base, private_key, &recovered, &shard.value)?;
        Ok((Self { id, recovered }, proof))
    }
}

pub struct CustodianProof {
    pub custodian_seed: EdwardsPoint,
    pub shard_seed: EdwardsPoint,
    pub encrypted: EdwardsPoint,
    pub challenge: Scalar,
    pub response: Scalar,
}

impl CustodianProof {
    fn new<R: CryptoRng + RngCore>(
        rng: &mut R,
        custodian_base: &EdwardsPoint,
        private_key: &Scalar,
        recovered: &EdwardsPoint,
        encrypted: &EdwardsPoint,
    ) -> Result<Self, Error> {
        let seed = Seed::new(rng)?;
        let shard_seed = SignedSeed::new(&seed, custodian_base);
        let custodian_seed = SignedSeed::new(&seed, recovered);
        let custodian_key = custodian_base * private_key;

        let mut sha3 = Sha3_256::default();
        sha3.input(shard_seed.0.to_montgomery().as_bytes());
        sha3.input(custodian_seed.0.to_montgomery().as_bytes());
        sha3.input(
            constants::ED25519_BASEPOINT_POINT
                .to_montgomery()
                .as_bytes(),
        );
        sha3.input(recovered.to_montgomery().as_bytes());
        sha3.input(custodian_key.to_montgomery().as_bytes());
        sha3.input(encrypted.to_montgomery().as_bytes());
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(sha3.fixed_result().as_slice());
        let challenge = Scalar::from_bytes_mod_order(challenge);
        let response = seed.0 - challenge * private_key;
        let encrypted = encrypted.clone();
        let SignedSeed(custodian_seed) = custodian_seed;
        let SignedSeed(shard_seed) = shard_seed;
        Ok(Self {
            custodian_seed,
            shard_seed,
            encrypted,
            challenge,
            response,
        })
    }
}

impl Verifiable for CustodianDecryption {
    type Error = Error;
    /// Proof is a product between custodian base, custodian public key and custodian decryption proof
    type Proof = (EdwardsPoint, EdwardsPoint, CustodianProof);
    fn verify(self, proof: Self::Proof) -> Result<Self, Error> {
        let (custodian_base, custodian_key, proof) = proof;
        let dleq_proof = dleq::Proof {
            g1: custodian_base,       // b
            g2: self.recovered,       // b ^ p(i)
            h1: custodian_key,        // b ^ x_i
            h2: proof.encrypted,      // b ^ (p(i) * x_i)
            a1: proof.shard_seed,     // b ^ w_i
            a2: proof.custodian_seed, // b ^ (p(i) * w_i)
            challenge: proof.challenge,
            response: proof.response,
        };
        dleq_proof
            .verify_proof(())
            .map_err(|e| Error::InvalidCustodianProof(e))?;
        Ok(self)
    }
}

pub struct Poll {
    pub threshold: usize,
    pub poll: Vec<Verified<CustodianDecryption>>,
}

impl Verifiable for Poll {
    type Error = Error;
    type Proof = Verified<Vec<Custodian>>;
    fn verify(self, custodians: Self::Proof) -> Result<Self, Error> {
        let Self {
            threshold,
            mut poll,
        } = self;
        if threshold > poll.len() {
            return Err(Error::NoEnoughCustodian {
                requested: threshold,
                allocated: poll.len(),
            });
        }
        let mut valid_poll: Vec<_> = poll
            .into_iter()
            .filter(|decrypt| {
                custodians
                    .binary_search_by(|c| c.id.cmp(&decrypt.id))
                    .is_ok()
            })
            .collect();
        valid_poll.sort_by(|a, b| a.id.cmp(&b.id));
        valid_poll.dedup_by(|a, b| a.id == b.id);
        if threshold > valid_poll.len() {
            Err(Error::NoEnoughCustodian {
                requested: threshold,
                allocated: valid_poll.len(),
            })
        } else {
            Ok(Self {
                threshold,
                poll: valid_poll,
            })
        }
    }
}

pub fn recover_secret(poll: Verified<Poll>) -> EdwardsPoint {
    let mut secret = EdwardsPoint::identity();
    for a in poll.poll.iter() {
        let mut lagrange = Scalar::one();
        for b in poll.poll.iter() {
            let a = u64_to_scalar(a.id);
            let b = u64_to_scalar(b.id);
            if a != b {
                lagrange *= b * (b - a).invert();
            }
        }
        secret += a.recovered * lagrange;
    }
    secret
}

#[cfg(test)]
mod tests;
