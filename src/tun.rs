use cfg_if::cfg_if;
use failure::{Backtrace, Fail};

cfg_if! {
    if #[cfg(target_os = "linux")] {
        pub mod linux;
    }
}

pub struct TunDevice {}

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "os: {}", _0)]
    Os(String, Backtrace),
}

impl TunDevice {
    pub fn new() -> Result<Self, Error> {
        todo!()
    }
}
