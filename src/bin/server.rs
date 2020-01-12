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

use failure::Fail;
use futures::{
    channel::{mpsc::channel, oneshot::channel as oneshot},
    prelude::*,
};
use sss::lattice::{keygen, Init, PrivateKey, PublicKey, SigningKey};
use structopt::StructOpt;
use tokio::runtime::Handle;
use udarnik::{
    keyman::{Error as KeyError, RawInit, RawPrivateKey},
    server::{server, ServerBootstrap},
    state::{Identity, InitIdentity},
    utils::TokioSpawn,
};

#[derive(Debug, StructOpt)]
struct Config {
    key: PathBuf,
    init: PathBuf,
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
    Ok(())
}

fn main() {}
