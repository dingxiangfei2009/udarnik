use backtrace::Backtrace as Bt;
use cfg_if::cfg_if;
use thiserror::Error;

cfg_if! {
    if #[cfg(target_os = "linux")] {
        pub mod linux;
    }
}

pub struct TunDevice {}

#[derive(Error, Debug)]
pub enum Error {
    #[error("os: {0}, backtrace: {1:?}")]
    Os(String, Bt),
}

impl TunDevice {
    pub fn new() -> Result<Self, Error> {
        todo!()
    }
}
