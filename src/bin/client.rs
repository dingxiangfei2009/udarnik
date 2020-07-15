#![type_length_limit = "4000000"]

use std::{
    convert::TryFrom, fs::File, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration,
};

use async_std::io::{stdout, BufWriter};
use blake2::Blake2b;
use futures::{
    channel::{
        mpsc::{channel, SendError},
        oneshot::channel as oneshot,
    },
    prelude::*,
    select_biased,
    stream::repeat,
};
use log::{error, info};
use rand_chacha::ChaCha20Rng;
use serde_json::from_reader;
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
use udarnik::{
    client::{client, ClientBootstrap},
    keyman::{Error as KeyError, RawInit, RawPrivateKey, RawPublicKey},
    reference_seeder_chacha,
    state::{
        BridgeConstructorParams, Identity, InitIdentity, KeyExchangeAnkeIdentity,
        McElieceAnkeIdentity, Params, RLWEAnkeIdentity, SafeGuard, TimeoutParams,
    },
    utils::TokioSpawn,
};

#[derive(Debug)]
enum Key {
    RLWE {
        path: PathBuf,
        boris_pub_path: PathBuf,
    },
    McEliece {
        path: PathBuf,
        anke_pub_path: PathBuf,
        boris_pub_path: PathBuf,
    },
}

impl FromStr for Key {
    type Err = Error;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut iter = input.split(':');
        match iter
            .next()
            .ok_or_else(|| Error::Arg("no colon separator".into()))?
        {
            "rlwe" => {
                let path = iter
                    .next()
                    .ok_or_else(|| Error::Arg("expect path to key".into()))?
                    .parse()
                    .unwrap();
                let boris_pub_path = iter
                    .next()
                    .ok_or_else(|| Error::Arg("expect path to server pubkey".into()))?
                    .parse()
                    .unwrap();
                Ok(Key::RLWE {
                    path,
                    boris_pub_path,
                })
            }
            "mc" => {
                let path = iter
                    .next()
                    .ok_or_else(|| Error::Arg("expect path to key".into()))?
                    .parse()
                    .unwrap();
                let anke_pub_path = iter
                    .next()
                    .ok_or_else(|| Error::Arg("expect path to client pubkey".into()))?
                    .parse()
                    .unwrap();
                let boris_pub_path = iter
                    .next()
                    .ok_or_else(|| Error::Arg("expect path to server pubkey".into()))?
                    .parse()
                    .unwrap();
                Ok(Key::McEliece {
                    path,
                    anke_pub_path,
                    boris_pub_path,
                })
            }
            _ => Err(Error::Arg("unknown key type".into())),
        }
    }
}

#[derive(Debug, StructOpt)]
struct Config {
    #[structopt(short)]
    key: Key,
    #[structopt(short)]
    init: Option<PathBuf>,
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
    #[error("{0}")]
    Arg(String),
}

async fn entry(cfg: Config, handle: tokio::runtime::Handle) -> Result<(), Error> {
    let Config { key, init, addr } = cfg;
    let kex = match key {
        Key::RLWE {
            path,
            boris_pub_path,
        } => {
            let init: RawInit = from_reader(File::open(
                init.ok_or_else(|| Error::Arg("missing init".into()))?,
            )?)?;
            let init = Init::try_from(init)?;
            let prikey: RawPrivateKey = from_reader(File::open(path)?)?;
            let prikey = PrivateKey::try_from(prikey)?;
            let anke_pubkey = prikey.public_key(&init);

            let pubkey: RawPublicKey = from_reader(File::open(boris_pub_path)?)?;
            let boris_pubkey = PublicKey::try_from(pubkey)?;
            let anke_identity = Identity::from(&anke_pubkey);
            let boris_identity = Identity::from(&boris_pubkey);
            info!(
                "load: rlwe identity, anke {}, boris {}",
                anke_identity, boris_identity
            );
            KeyExchangeAnkeIdentity::RLWE(RLWEAnkeIdentity::new(
                InitIdentity::from(&init),
                init,
                anke_identity,
                boris_identity,
                prikey,
                anke_pubkey,
                boris_pubkey,
                vec![],
                vec![],
            ))
        }
        Key::McEliece {
            path,
            anke_pub_path,
            boris_pub_path,
        } => {
            let BinaryPacked(dec): BinaryPacked<
                GoppaDecoder<GF65536N, GF65536NTower, GF65536NPreparedMultipointEvalVZG>,
            > = from_reader(File::open(path)?)?;
            info!("load: mc decoder get");
            let anke_prikey = McElieceKEM65536PrivateKey::new(dec)
                .ok_or_else(|| KeyError::Malformed(<_>::default()))?;
            info!("load: mc identity, anke private");
            let BinaryPacked(enc): BinaryPacked<GoppaEncoder<F2, GF65536NTower>> =
                from_reader(File::open(anke_pub_path)?)?;
            info!("load: mc encoder get");
            let anke_pubkey = McElieceKEM65536PublicKey::new(enc);
            let anke_identity = Identity::from(&anke_pubkey);
            info!("load: mc identity, anke {}", anke_identity);

            let BinaryPacked(enc): BinaryPacked<GoppaEncoder<F2, GF65536NTower>> =
                from_reader(File::open(boris_pub_path)?)?;
            let boris_pubkey = McElieceKEM65536PublicKey::new(enc);
            let boris_identity = Identity::from(&boris_pubkey);

            info!(
                "load: mc identity, anke {}, boris {}",
                anke_identity, boris_identity
            );
            KeyExchangeAnkeIdentity::McEliece(McElieceAnkeIdentity::new(
                anke_prikey,
                anke_pubkey,
                boris_pubkey,
            ))
        }
    };

    let spawn = TokioSpawn(handle.clone());
    let (input, input_rx) = channel(4096);
    let (output_tx, output) = channel(4096);
    let (_terminate, terminate_rx) = oneshot();
    let client = client::<SafeGuard, ChaCha20Rng, Blake2b, _, _, _, _>(
        ClientBootstrap {
            addr: format!("http://{}", addr).parse().unwrap(),
            params: Params {
                correction: 4,
                entropy: 0,
                window: 16,
            },
            kex,
            timeout_params: TimeoutParams {
                stream_timeout: Duration::new(3600, 0),
                stream_reset_timeout: Duration::new(60, 0),
                send_cooldown: Duration::new(0, 150_000_000),
                recv_timeout: Duration::new(1, 0),
                invite_cooldown: Duration::new(30, 0),
            },
            bridge_constructor_params: BridgeConstructorParams {
                ip_listener_address: "127.0.0.1".parse().unwrap(),
                ip_listener_mask: 32,
            },
        },
        reference_seeder_chacha,
        input_rx,
        output_tx,
        terminate_rx,
        spawn,
        |duration| tokio::time::delay_for(duration),
    );
    let client = handle.spawn(client);
    let stdin = handle.spawn(
        repeat(vec![1; 1500])
            .map(Ok)
            .forward(input.clone().sink_map_err(Error::Pipe)),
    );
    let stdout = BufWriter::new(stdout());
    let stdout = handle.spawn(
        output
            .map(Ok)
            .try_fold(stdout, move |mut stdout, output| async move {
                stdout.write_all(&output).await?;
                Ok::<_, std::io::Error>(stdout)
            })
            .map_ok(|_| ()),
    );
    select_biased! {
        r = stdin.fuse() => (),
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
