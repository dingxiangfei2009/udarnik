#![recursion_limit = "4096"]
#[macro_use]
extern crate derive_more;

use std::{
    error::Error as StdError,
    fmt::{Debug, Formatter, Result as FmtResult},
};

pub mod common;
pub mod keyman;
pub mod protocol;
pub mod pvss;
pub mod server;
pub mod state;

pub type GenericError = Box<dyn 'static + StdError + Send + Sync>;

#[derive(Deref, From)]
pub struct Redact<T>(pub T);

impl<T> Debug for Redact<T> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "<REDACTED>")
    }
}
