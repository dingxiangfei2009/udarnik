use futures::{executor::block_on, prelude::*};
use udarnik::tun::linux::UtunDev;

fn main() {
    let _guard = slog_envlogger::init();
    let (dev, tx, mut rx) = UtunDev::new("tun%d").unwrap();
    block_on(async move {
        while let Some(packet) = rx.next().await {
            println!("pkt={:?}", packet);
        }
    });
}
