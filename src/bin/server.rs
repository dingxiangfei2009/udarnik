#[macro_use]
extern crate derive_more;

use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
    fs::File,
    io::Write,
    net::SocketAddr,
    path::PathBuf,
};

use futures::{
    channel::{mpsc::channel, oneshot::channel as oneshot},
    prelude::*,
};
use log::{error, info};
use sss::lattice::{keygen, Init, PrivateKey, PublicKey, SigningKey};
use structopt::StructOpt;
use thiserror::Error;
use tokio::runtime::Handle;
use udarnik::{
    keyman::{Error as KeyError, RawInit, RawPrivateKey},
    server::{server, ServerBootstrap},
    state::{Identity, InitIdentity},
    utils::TokioSpawn,
    GenericError,
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
}

async fn entry(cfg: Config, handle: Handle) -> Result<(), Error> {
    let Config { key, init, addr } = cfg;
    let init: RawInit = serde_json::from_reader(File::open(init)?)?;
    let init = Init::try_from(init)?;
    let prikey: RawPrivateKey = serde_json::from_reader(File::open(key)?)?;
    let prikey = PrivateKey::try_from(prikey)?;
    let pubkey = prikey.public_key(&init);
    let sign_key = SigningKey::from_private_key(&prikey);
    let verify_key = sign_key.verification_key(&init);
    let (new_channel_tx, mut new_channel) = channel(32);

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
    let server = server(
        ServerBootstrap {
            addr: addr.clone(),
            allowed_identities: allowed_identities.clone(),
            anke_data: vec![],
            boris_data: vec![],
            identity_db: identity_db.clone(),
            init_db: init_db.clone(),
            identity_sequence: identity_sequence.clone(),
            retries: Some(3),
            verify_db: verify_db.clone(),
        },
        new_channel_tx,
        spawn.clone(),
        |duration| tokio::time::delay_for(duration),
    );
    handle.spawn({
        let handle = handle.clone();
        async move {
            while let Some((input, output)) = new_channel.next().await {
                info!("server: new channel, short-circuiting");
                handle.spawn(async {
                    output
                        .map(Ok)
                        .inspect_ok(|m| info!("got {:?}", m))
                        .forward(input)
                        .await
                        .unwrap_or_else(|e| error!("server: channel: {}", e))
                });
            }
        }
    });
    Ok(server.await.unwrap())
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
