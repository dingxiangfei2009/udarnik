#![type_length_limit = "4000000"]
#[macro_use]
extern crate derive_more;

use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
    fs::File,
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};

use async_std::{
    io::{stdin, stdout, BufReader, BufWriter},
    task::sleep,
};
use blake2::Blake2b;
use futures::{
    channel::{
        mpsc::{channel, SendError},
        oneshot::channel as oneshot,
    },
    prelude::*,
    select,
    stream::repeat,
};
use http::Uri;
use log::{error, info};
use rand_chacha::ChaCha20Rng;
use sss::lattice::{keygen, Init, PrivateKey, PublicKey, SigningKey};
use structopt::StructOpt;
use thiserror::Error;
use udarnik::{
    client::{client, ClientBootstrap},
    keyman::{
        Error as KeyError, RawInit, RawPrivateKey, RawPublicKey, RawSigningKey, RawVerificationKey,
    },
    reference_seeder_chacha,
    server::{server, ServerBootstrap},
    state::{Identity, InitIdentity, KeyExchangeAnkeIdentity, Params, RLWEAnkeIdentity, SafeGuard},
    utils::TokioSpawn,
};

#[derive(Debug, StructOpt)]
struct Config {
    #[structopt(short)]
    key: PathBuf,
    #[structopt(short)]
    init: PathBuf,
    #[structopt(short)]
    addr: SocketAddr,
}

#[derive(Error, Debug)]
enum Error {
    #[error("serialization: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("key: {0}")]
    Key(#[from] KeyError),
    #[error("pipe: {0}")]
    Pipe(#[from] SendError),
}

async fn entry(cfg: Config, handle: tokio::runtime::Handle) -> Result<(), Error> {
    let Config { key, init, addr } = cfg;
    let init: RawInit = serde_json::from_reader(File::open(init)?)?;
    let init = Init::try_from(init)?;
    let prikey: RawPrivateKey = serde_json::from_reader(File::open(key)?)?;
    let prikey = PrivateKey::try_from(prikey)?;
    let pubkey = prikey.public_key(&init);

    let spawn = TokioSpawn(handle.clone());
    let (input, input_rx) = channel(4096);
    let (output_tx, output) = channel(4096);
    let (terminate, terminate_rx) = oneshot();
    let client = client::<SafeGuard, ChaCha20Rng, Blake2b, _, _, _, _>(
        ClientBootstrap {
            addr: format!("http://{}", addr).parse().unwrap(),
            params: Params {
                correction: 4,
                entropy: 0,
                window: 4096,
            },
            kex: KeyExchangeAnkeIdentity::RLWE(RLWEAnkeIdentity::new(
                InitIdentity::from(&init),
                init,
                Identity::from(&pubkey),
                Identity::from(&pubkey),
                prikey,
                pubkey.clone(),
                pubkey,
                vec![],
                vec![],
            )),
        },
        reference_seeder_chacha,
        input_rx,
        output_tx,
        terminate_rx,
        spawn,
        |duration| tokio::time::delay_for(duration),
    );
    let client = handle.spawn(client);
    // let stdin = stdin();
    // let stdin = BufReader::new(stdin.lock().await);
    let stdin = handle.spawn(
        repeat(vec![1])
            .map(Ok)
            .forward(input.clone().sink_map_err(Error::Pipe)),
    );
    let stdout = stdout();
    let stdout = BufWriter::new(stdout.lock().await);
    let stdout = handle.spawn(
        output
            .map(Ok)
            .try_fold(stdout, move |mut stdout, output| async move {
                stdout.write_all(&output).await?;
                Ok::<_, std::io::Error>(stdout)
            })
            .map_ok(|_| ()),
    );
    select! {
        r = stdin.fuse() => r.unwrap().unwrap(),
        r = client.fuse() => r.unwrap().unwrap(),
        r = stdout.fuse() => r.unwrap().unwrap(),
    }
    Ok(())
}

fn main() {
    let cfg = Config::from_args();
    let _guard = slog_envlogger::init();
    let mut rt = tokio::runtime::Builder::new()
        .threaded_scheduler()
        .enable_all()
        .build()
        .unwrap();
    let handle = rt.handle().clone();
    rt.block_on(entry(cfg, handle)).unwrap();
}
