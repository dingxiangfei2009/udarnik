use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
    error::Error as StdError,
    fmt::Debug,
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use async_std::sync::{Arc, Mutex, RwLock};
use failure::{Error as TopError, Fail};
use futures::{
    channel::{
        mpsc::{channel, Receiver, Sender},
        oneshot::Receiver as OneshotReceiver,
    },
    future::{pending, poll_fn, select_all},
    pin_mut,
    prelude::*,
    select, stream,
};
use http::Uri;
use log::{error, info};
use pin_utils::unsafe_pinned;
use rand::{CryptoRng, RngCore, SeedableRng};
use sss::lattice::{
    Init, PrivateKey, PublicKey, SessionKeyPart, SessionKeyPartMix, SigningKey, VerificationKey,
};
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use crate::{
    protocol::signature_hasher,
    reference_seeder_chacha,
    state::{
        key_exchange_anke, wire, Guard, Identity, InitIdentity, KeyExchange, Message, Params,
        SafeGuard, Session, SessionBootstrap, SessionError, SessionHandle, SessionId,
    },
    GenericError,
};

pub struct ClientBootstrap<S> {
    addr: Uri,
    params: Params,
    allowed_identities: HashMap<InitIdentity, HashMap<Identity, PublicKey>>,
    anke_data: Vec<u8>,
    boris_data: Vec<u8>,
    identity_db: BTreeMap<InitIdentity, BTreeMap<Identity, PrivateKey>>,
    identity_sequence: Vec<(InitIdentity, Identity)>,
    init_db: BTreeMap<InitIdentity, Init>,
    retries: Option<u32>,
    sign_db: BTreeMap<InitIdentity, BTreeMap<Identity, SigningKey>>,
    seeder: S,
}

pub async fn client<G, R, S>(
    bootstrap: ClientBootstrap<S>,
    input: Receiver<Vec<u8>>,
    output: Sender<Vec<u8>>,
    terminate: OneshotReceiver<()>,
) -> Result<(), GenericError>
where
    G: 'static + Send + Sync + Guard<Params, ()> + for<'a> From<&'a [u8]> + Debug,
    G::Error: Debug,
    R: 'static + Send + Sync + SeedableRng + RngCore + CryptoRng,
    S: Send + Sync + Clone + Fn(&[u8]) -> R::Seed,
{
    let ClientBootstrap {
        addr,
        params,
        allowed_identities,
        anke_data,
        boris_data,
        identity_db,
        identity_sequence,
        init_db,
        retries,
        sign_db,
        seeder,
    } = bootstrap;
    let mut client = wire::master_client::MasterClient::connect(addr).await?;
    let (message_sink, master_in) = channel(4096);
    let message_stream = client
        .key_exchange(Request::new(master_in.map(wire::Message::from)))
        .await?
        .into_inner()
        .map_err(|e| Box::new(e) as GenericError)
        .and_then(|m| {
            async { Message::<G>::try_from(m).map_err(|e| Box::new(e.compat()) as GenericError) }
        })
        .map_err(TopError::from_boxed_compat)
        .boxed();
    let kex = KeyExchange {
        retries,
        init_db,
        identity_db,
        allowed_identities,
        identity_sequence,
        session_key_part_sampler: SessionKeyPart::parallel_sampler::<R>(2, 4096),
        anke_session_key_part_mix_sampler: SessionKeyPartMix::parallel_sampler::<R>(2, 4096),
        boris_session_key_part_mix_sampler: SessionKeyPartMix::parallel_sampler::<R>(2, 4096),
        anke_data,
        boris_data,
    };
    let session_bootstrap = key_exchange_anke(kex, message_stream, message_sink, seeder, params)
        .await
        .map_err(|e| Box::new(e.compat()))?;

    let (master_sink, master_in) = channel(4096);
    let (master_out, master_messages) = channel(4096);
    let master_sink = Box::new(master_sink.sink_map_err(|e| Box::new(e) as GenericError)) as _;
    let timeout_generator = |duration| async_std::task::sleep(duration).boxed();
    let SessionHandle {
        session,
        poll,
        input,
        output,
        mut progress,
    } = Session::<SafeGuard>::new(
        session_bootstrap,
        master_messages,
        master_sink,
        timeout_generator,
    )
    .map_err(|e| Box::new(e.compat()))?;
    let master_in = master_in.peekable();
    let master_adapter = async move {
        pin_mut!(master_in);
        // let (client_out_tx, client_out_rx) = channel(4096);
        // let (client_in_tx, client_in_rx) = channel(4096);
        // let send = async {};
        // let recv = async {};
        loop {
            let peek = Peek { inner: Some(master_in.as_mut()) };
            if let Some(_) = peek.await {
                let x = master_in.next().await;
            }
            // let mut master_in = master_in.as_mut();
            // let f = |ctx| {
            //     let master_in = master_in.as_mut();
            //     master_in.poll_peek(ctx);
            // };
            //     select! {

            //     }
            //     let (client_in, client_out) = channel(4096);
            //     client
        }
    };
    Ok(())
}

struct Peek<'a, St: Stream> {
    inner: Option<Pin<&'a mut stream::Peekable<St>>>,
}

impl<'a, St> Future for Peek<'a, St>
where
    St: Stream,
{
    type Output = Option<&'a St::Item>;
    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        if let Some(peekable) = self.inner.take() {
            peekable.poll_peek(ctx)
        } else {
            Poll::Pending
        }
    }
}
