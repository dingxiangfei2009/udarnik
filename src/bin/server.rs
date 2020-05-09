use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
    fs::File,
    net::SocketAddr,
    path::PathBuf,
};

use blake2::Blake2b;
use futures::{channel::mpsc::channel, prelude::*};
use log::{error, info};
use rand_chacha::ChaCha20Rng;
use sss::lattice::{Init, PrivateKey, SigningKey};
use structopt::StructOpt;
use thiserror::Error;
use tokio::runtime::Handle;
use udarnik::{
    keyman::{Error as KeyError, RawInit, RawPrivateKey},
    reference_seeder_chacha,
    server::{server, ServerBootstrap},
    state::{
        Identity, InitIdentity, KeyExchangeBorisIdentity, McElieceBorisIdentity, RLWEBorisIdentity,
    },
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

    let spawn = TokioSpawn(handle.clone());
    let server = server(
        ServerBootstrap {
            addr: addr.clone(),
            kex: KeyExchangeBorisIdentity {
                rlwe: <RLWEBorisIdentity<ChaCha20Rng>>::new(
                    init_db,
                    identity_db,
                    allowed_identities,
                    vec![],
                    vec![],
                ),
                mc: <McElieceBorisIdentity<Blake2b>>::new(<_>::default(), <_>::default()),
            },
        },
        new_channel_tx,
        reference_seeder_chacha,
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
