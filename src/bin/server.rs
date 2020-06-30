#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static _GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;
use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
    fs::File,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use blake2::Blake2b;
use futures::{channel::mpsc::channel, prelude::*};
use log::{error, info};
use rand_chacha::ChaCha20Rng;
use sss::{
    artin::GF65536NPreparedMultipointEvalVZG,
    field::F2,
    galois::{GF65536NTower, GF65536N},
    goppa::{BinaryPacked, GoppaDecoder, GoppaEncoder},
    lattice::{Init, PrivateKey, PublicKey},
    mceliece::{McElieceKEM65536PrivateKey, McElieceKEM65536PublicKey},
};
use structopt::StructOpt;
use thiserror::Error;
use tokio::runtime::Handle;
use udarnik::{
    keyman::{Error as KeyError, RawInit, RawPrivateKey, RawPublicKey},
    reference_seeder_chacha,
    server::{server, ServerBootstrap},
    state::{
        BridgeConstructorParams, Identity, InitIdentity, KeyExchangeBorisIdentity,
        McElieceBorisIdentity, RLWEBorisIdentity, TimeoutParams,
    },
    utils::TokioSpawn,
};

#[derive(Debug)]
enum Key {
    RLWE { path: PathBuf, init_idx: usize },
    McEliece { path: PathBuf },
}

impl FromStr for Key {
    type Err = Error;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut iter = input.splitn(3, ':');
        match iter
            .next()
            .ok_or_else(|| Error::Arg("no colon separator".into()))?
        {
            "rlwe" => {
                let init_idx = iter
                    .next()
                    .ok_or_else(|| Error::Arg("expect init file index".into()))?
                    .parse()?;
                let path = iter
                    .next()
                    .ok_or_else(|| Error::Arg("expect path to key".into()))?
                    .parse()
                    .unwrap();
                Ok(Key::RLWE { path, init_idx })
            }
            "mc" => {
                let path = iter
                    .next()
                    .ok_or_else(|| Error::Arg("expect path to key".into()))?
                    .parse()
                    .unwrap();
                Ok(Key::McEliece { path })
            }
            _ => Err(Error::Arg("unknown key type".into())),
        }
    }
}

#[derive(Debug)]
enum Entity {
    RLWE { path: PathBuf, init_idx: usize },
    McEliece { path: PathBuf },
}

impl FromStr for Entity {
    type Err = Error;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut iter = input.splitn(3, ':');
        match iter
            .next()
            .ok_or_else(|| Error::Arg("no colon separator".into()))?
        {
            "rlwe" => {
                let init_idx = iter
                    .next()
                    .ok_or_else(|| Error::Arg("expect init file index".into()))?
                    .parse()?;
                let path = match iter
                    .next()
                    .ok_or_else(|| Error::Arg("expect path to key".into()))?
                    .parse()
                {
                    Ok(p) => p,
                    _ => unreachable!(),
                };
                Ok(Entity::RLWE { path, init_idx })
            }
            "mc" => {
                let path = match iter
                    .next()
                    .ok_or_else(|| Error::Arg("expect path to key".into()))?
                    .parse()
                {
                    Ok(p) => p,
                    _ => unreachable!(),
                };
                Ok(Entity::McEliece { path })
            }
            _ => Err(Error::Arg("unknown key type".into())),
        }
    }
}

#[derive(Debug, StructOpt)]
struct Config {
    #[structopt(short)]
    secretkey: Vec<Key>,
    #[structopt(short)]
    pubkey: Vec<Entity>,
    #[structopt(short)]
    init: Vec<PathBuf>,
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
    #[error("argument: {0}")]
    Arg(String),
    #[error("unknown init")]
    UnknownInit,
    #[error("{0}")]
    ParseInt(#[from] std::num::ParseIntError),
}

async fn entry(cfg: Config, handle: Handle) -> Result<(), Error> {
    let Config {
        pubkey,
        secretkey,
        init,
        addr,
    } = cfg;
    let init: Vec<_> = init.into_iter().map(File::open).collect::<Result<_, _>>()?;
    let init: Vec<RawInit> = init
        .into_iter()
        .map(serde_json::from_reader)
        .collect::<Result<_, _>>()?;
    let init: Vec<_> = init
        .into_iter()
        .map(Init::try_from)
        .collect::<Result<_, _>>()?;
    let init_idents: Vec<_> = init.iter().map(InitIdentity::from).collect();
    let init_db: BTreeMap<_, _> = init
        .into_iter()
        .map(|init| (InitIdentity::from(&init), init))
        .collect();

    let mut allowed_identities: HashMap<_, HashMap<_, _>> = <_>::default();
    let mut identity_db: BTreeMap<_, BTreeMap<_, _>> = <_>::default();
    let mut mc_allowed_identities = BTreeMap::new();
    let mut mc_identity_db = BTreeMap::new();
    for key in secretkey {
        match key {
            Key::RLWE { init_idx, path } => {
                let prikey: RawPrivateKey = serde_json::from_reader(File::open(path)?)?;
                let prikey = PrivateKey::try_from(prikey)?;
                let init_ident = init_idents
                    .get(init_idx)
                    .ok_or_else(|| Error::UnknownInit)?;
                let init = init_db.get(init_ident).ok_or_else(|| Error::UnknownInit)?;
                let pubkey = prikey.public_key(init);
                let rlwe_ident = Identity::from(&pubkey);
                info!("load: rlwe identity {}", rlwe_ident);
                identity_db
                    .entry(init_ident.clone())
                    .or_default()
                    .insert(rlwe_ident, prikey);
            }
            Key::McEliece { path } => {
                let BinaryPacked(dec): BinaryPacked<
                    GoppaDecoder<GF65536N, GF65536NTower, GF65536NPreparedMultipointEvalVZG>,
                > = serde_json::from_reader(File::open(path)?)?;
                let enc = dec
                    .encoder()
                    .ok_or_else(|| KeyError::Malformed(<_>::default()))?;
                let prikey = McElieceKEM65536PrivateKey::new(dec)
                    .ok_or_else(|| KeyError::Malformed(<_>::default()))?;
                let mc_ident = Identity::from(&McElieceKEM65536PublicKey::new(enc));
                info!("load: mc identity {}", mc_ident);
                mc_identity_db.insert(mc_ident, prikey);
            }
        }
    }
    for key in pubkey {
        match key {
            Entity::RLWE { init_idx, path } => {
                let pubkey: RawPublicKey = serde_json::from_reader(File::open(path)?)?;
                let pubkey = PublicKey::try_from(pubkey)?;
                let init_ident = init_idents
                    .get(init_idx)
                    .ok_or_else(|| Error::UnknownInit)?;

                let rlwe_ident = Identity::from(&pubkey);
                info!("load: rlwe public key {}", rlwe_ident);
                allowed_identities
                    .entry(init_ident.clone())
                    .or_default()
                    .insert(rlwe_ident, pubkey);
            }
            Entity::McEliece { path } => {
                let BinaryPacked(enc): BinaryPacked<GoppaEncoder<F2, GF65536NTower>> =
                    serde_json::from_reader(File::open(path)?)?;
                let pk = McElieceKEM65536PublicKey::new(enc);
                let mc_ident = Identity::from(&pk);
                info!("load: mc public key {}", mc_ident);
                mc_allowed_identities.insert(mc_ident, pk);
            }
        }
    }
    let (new_channel_tx, mut new_channel) = channel(32);

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
                mc: <McElieceBorisIdentity<Blake2b>>::new(mc_allowed_identities, mc_identity_db),
            },
            timeout_params: TimeoutParams {
                stream_timeout: Duration::new(3600, 0),
                stream_reset_timeout: Duration::new(60, 0),
                send_cooldown: Duration::new(0, 150_000_000),
                recv_timeout: Duration::new(5, 0),
                invite_cooldown: Duration::new(30, 0),
            },
            bridge_constructor_params: BridgeConstructorParams {
                ip_listener_address: "127.0.0.1".parse().unwrap(),
                ip_listener_mask: 32,
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
                handle.spawn(
                    output
                        .map(Ok)
                        .inspect_ok(|_| info!("server frontend: got message"))
                        .forward(input)
                        .unwrap_or_else(|e| error!("server: channel: {}", e))
                        .map(|_| info!("session terminated")),
                );
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
