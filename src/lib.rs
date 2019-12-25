#[macro_use]
extern crate derive_more;

use std::fmt::{Debug, Formatter, Result as FmtResult};

pub mod common;
pub mod protocol;
pub mod pvss;
pub mod state;

#[derive(Deref, From)]
pub struct Redact<T>(pub T);

impl<T> Debug for Redact<T> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "<REDACTED>")
    }
}
