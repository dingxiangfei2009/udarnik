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
use failure::Fail;
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
use sss::lattice::{keygen, Init, PrivateKey, PublicKey, SigningKey};
use structopt::StructOpt;
use udarnik::{
    client::{client, ClientBootstrap},
    keyman::{
        Error as KeyError, RawInit, RawPrivateKey, RawPublicKey, RawSigningKey, RawVerificationKey,
    },
    server::{server, ServerBootstrap},
    state::{Identity, InitIdentity, Params},
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

#[derive(Fail, Debug, From)]
enum Error {
    #[fail(display = "serialization: {}", _0)]
    Serialization(#[cause] serde_json::Error),
    #[fail(display = "io: {}", _0)]
    Io(#[cause] std::io::Error),
    #[fail(display = "key: {}", _0)]
    Key(#[cause] KeyError),
    #[fail(display = "pipe: {}", _0)]
    Pipe(SendError),
}

async fn entry(cfg: Config, handle: tokio::runtime::Handle) -> Result<(), Error> {
    let Config { key, init, addr } = cfg;
    let init: RawInit = serde_json::from_reader(File::open(init)?)?;
    let init = Init::try_from(init)?;
    let prikey: RawPrivateKey = serde_json::from_reader(File::open(key)?)?;
    let prikey = PrivateKey::try_from(prikey)?;
    let pubkey = prikey.public_key(&init);
    let sign_key = SigningKey::from_private_key(&prikey);
    let verify_key = sign_key.verification_key(&init);

    let mut init_db = BTreeMap::default();
    init_db.insert(InitIdentity::from(&init), init.clone());

    let mut allowed_identities: HashMap<_, HashMap<_, _>> = <_>::default();
    allowed_identities
        .entry(InitIdentity::from(&init))
        .or_default()
        .insert(Identity::from(&pubkey), pubkey.clone());

    let mut identity_db: BTreeMap<_, BTreeMap<_, _>> = <_>::default();
    identity_db
        .entry(InitIdentity::from(&init))
        .or_default()
        .insert(Identity::from(&pubkey), prikey);

    let mut sign_db: BTreeMap<_, BTreeMap<_, _>> = <_>::default();
    sign_db
        .entry(InitIdentity::from(&init))
        .or_default()
        .insert(Identity::from(&pubkey), sign_key);

    let mut verify_db: BTreeMap<_, BTreeMap<_, _>> = <_>::default();
    verify_db
        .entry(InitIdentity::from(&init))
        .or_default()
        .insert(Identity::from(&pubkey), verify_key);

    let identity_sequence = vec![(InitIdentity::from(&init), Identity::from(&pubkey))];

    let spawn = TokioSpawn(handle.clone());
    let (input, input_rx) = channel(4096);
    let (output_tx, output) = channel(4096);
    let (terminate, terminate_rx) = oneshot();
    let client = client(
        ClientBootstrap {
            addr: format!("http://{}", addr).parse().unwrap(),
            params: Params {
                correction: 4,
                entropy: 0,
                window: 4096,
            },
            allowed_identities,
            anke_data: vec![],
            boris_data: vec![],
            identity_db,
            identity_sequence,
            init_db,
            retries: Some(3),
            sign_db,
        },
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
            .try_fold(stdout, move |mut stdout, output| {
                async move {
                    stdout.write_all(&output).await?;
                    Ok::<_, std::io::Error>(stdout)
                }
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
