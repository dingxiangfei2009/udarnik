#![type_length_limit = "4000000"]
use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
    net::SocketAddr,
    time::Duration,
};

use async_std::task::sleep;
use futures::{
    channel::{mpsc::channel, oneshot::channel as oneshot},
    prelude::*,
};
use http::Uri;
use log::{error, info};
use sss::lattice::{keygen, Init, PrivateKey, PublicKey, SigningKey};
use udarnik::{
    client::{client, ClientBootstrap},
    keyman::{
        Error as KeyError, RawInit, RawPrivateKey, RawPublicKey, RawSigningKey, RawVerificationKey,
    },
    server::{server, ServerBootstrap},
    state::{Identity, InitIdentity, Params},
    utils::TokioSpawn,
};

const INIT: &str = include_str!("init");
const PRIVATE_KEY: &str = include_str!("pri");
const PUBLIC_KEY: &str = include_str!("pub");
const SING_KEY: &str = include_str!("sign");
const VERIFY_KEY: &str = include_str!("verify");

async fn start(handle: tokio::runtime::Handle) {
    let init: RawInit = serde_json::from_str(&INIT).unwrap();
    let init = Init::try_from(init).unwrap();
    let prikey: RawPrivateKey = serde_json::from_str(&PRIVATE_KEY).unwrap();
    let prikey = PrivateKey::try_from(prikey).unwrap();
    let pubkey: RawPublicKey = serde_json::from_str(&PUBLIC_KEY).unwrap();
    let pubkey: PublicKey = PublicKey::try_from(pubkey).unwrap();
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

    let addr: SocketAddr = "[::]:8080".parse().unwrap();
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
    let server = handle.spawn(server);
    sleep(Duration::new(1, 0)).await;
    info!("set up client");
    let (mut input, input_rx) = channel(4096);
    let (output_tx, mut output) = channel(4096);
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
    let handle_ = handle.clone();
    handle.spawn(async move {
        let handle = handle_;
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
    });
    handle.spawn(async move {
        loop {
            if let Err(e) = input.send(vec![10, 20, 30u8]).await {
                error!("client: send to input: {}", e);
                break;
            }
            sleep(Duration::new(8, 0)).await;
        }
    });
    handle.spawn(output.for_each(|m| {
        async move {
            info!("client: output: {:?}", m);
        }
    }));
    sleep(Duration::new(10000, 0)).await;
}

#[test]
fn entry() {
    let _guard = slog_envlogger::init();
    let mut rt = tokio::runtime::Builder::new()
        .threaded_scheduler()
        .enable_all()
        .core_threads(512)
        // .thread_stack_size(32 << 30)
        .build()
        .unwrap();
    let h = rt.spawn(start(rt.handle().clone()));
    rt.block_on(h).unwrap();
    eprintln!("joined");
}
