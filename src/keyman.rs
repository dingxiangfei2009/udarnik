use std::convert::TryFrom;

use backtrace::Backtrace as Bt;
use serde::{Deserialize, Serialize};
use sss::lattice::{Init, Poly, PrivateKey, PublicKey, SigningKey, VerificationKey};
use thiserror::Error;

#[derive(Serialize, Deserialize)]
pub struct RawInit(Vec<Vec<u8>>);

#[derive(Serialize, Deserialize)]
pub struct RawPrivateKey {
    s: Vec<Vec<u8>>,
    e: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
pub struct RawPublicKey {
    p: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
pub struct RawSigningKey {
    x: Vec<Vec<u8>>,
    y: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
pub struct RawVerificationKey {
    v: Vec<Vec<u8>>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("malformed representation, backtrace: {0:?}")]
    Malformed(Bt),
}

impl TryFrom<RawInit> for Init {
    type Error = Error;
    fn try_from(RawInit(a): RawInit) -> Result<Self, Self::Error> {
        let a = Poly::from_coeff_bytes(a).ok_or_else(|| Error::Malformed(<_>::default()))?;
        Ok(Self(a))
    }
}

impl TryFrom<RawPrivateKey> for PrivateKey {
    type Error = Error;
    fn try_from(RawPrivateKey { s, e }: RawPrivateKey) -> Result<Self, Self::Error> {
        let s = Poly::from_coeff_bytes(s).ok_or_else(|| Error::Malformed(<_>::default()))?;
        let e = Poly::from_coeff_bytes(e).ok_or_else(|| Error::Malformed(<_>::default()))?;
        Ok(Self { s, e })
    }
}

impl TryFrom<RawPublicKey> for PublicKey {
    type Error = Error;
    fn try_from(RawPublicKey { p }: RawPublicKey) -> Result<Self, Self::Error> {
        let p = Poly::from_coeff_bytes(p).ok_or_else(|| Error::Malformed(<_>::default()))?;
        Ok(Self(p))
    }
}

impl TryFrom<RawSigningKey> for SigningKey {
    type Error = Error;
    fn try_from(RawSigningKey { x, y }: RawSigningKey) -> Result<Self, Self::Error> {
        let x = Poly::from_coeff_bytes(x).ok_or_else(|| Error::Malformed(<_>::default()))?;
        let y = Poly::from_coeff_bytes(y).ok_or_else(|| Error::Malformed(<_>::default()))?;
        Ok(Self(x, y))
    }
}

impl TryFrom<RawVerificationKey> for VerificationKey {
    type Error = Error;
    fn try_from(RawVerificationKey { v }: RawVerificationKey) -> Result<Self, Self::Error> {
        let v = Poly::from_coeff_bytes(v).ok_or_else(|| Error::Malformed(<_>::default()))?;
        Ok(Self(v))
    }
}

impl From<Init> for RawInit {
    fn from(Init(a): Init) -> Self {
        Self(a.into_coeff_bytes())
    }
}

impl From<PrivateKey> for RawPrivateKey {
    fn from(PrivateKey { s, e }: PrivateKey) -> Self {
        Self {
            s: s.into_coeff_bytes(),
            e: e.into_coeff_bytes(),
        }
    }
}

impl From<PublicKey> for RawPublicKey {
    fn from(PublicKey(p): PublicKey) -> Self {
        Self {
            p: p.into_coeff_bytes(),
        }
    }
}

impl From<SigningKey> for RawSigningKey {
    fn from(SigningKey(x, y): SigningKey) -> Self {
        Self {
            x: x.into_coeff_bytes(),
            y: y.into_coeff_bytes(),
        }
    }
}

impl From<VerificationKey> for RawVerificationKey {
    fn from(VerificationKey(v): VerificationKey) -> Self {
        Self {
            v: v.into_coeff_bytes(),
        }
    }
}
