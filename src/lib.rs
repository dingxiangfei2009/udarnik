#![type_length_limit = "4000000"]
#![recursion_limit = "4096"]
#[macro_use]
extern crate derive_more;

use std::{
    error::Error as StdError,
    fmt::{Debug, Formatter, Result as FmtResult},
};

pub mod bridge;
pub mod client;
pub mod common;
pub mod keyman;
pub mod protocol;
pub mod pvss;
pub mod server;
pub mod state;
pub mod utils;

pub type GenericError = Box<dyn 'static + StdError + Send + Sync>;

#[derive(Deref, From)]
pub struct Redact<T>(pub T);

impl<T> Debug for Redact<T> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "<REDACTED>")
    }
}

fn reference_seeder_chacha(input: &[u8]) -> [u8; 32] {
    use sha3::digest::Digest;
    let mut s = [0; 32];
    for chunks in sha3::Sha3_512::digest(input).chunks(32) {
        for (s, c) in s.iter_mut().zip(chunks) {
            *s ^= c;
        }
    }
    s
}
