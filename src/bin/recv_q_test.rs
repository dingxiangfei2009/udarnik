use std::sync::Arc;

use futures::{
    prelude::*,
    stream::{iter, repeat},
};
use rand::{prelude::*, rngs::OsRng};

use udarnik::protocol::{QuorumResolve, RSCodec, ReceiveError, ReceiveQueue, Shard, ShardState};

#[tokio::main]
async fn main() -> Result<(), ReceiveError> {
    let _guard = slog_envlogger::init();
    let codec = RSCodec::new(31).unwrap();
    let recv_q = Arc::new(ReceiveQueue::new(Some(8)));
    let mut input_data = [0u8; 1500];
    OsRng.fill_bytes(&mut input_data);
    let shards = Shard::from_codes(codec.encode(&input_data).unwrap());
    let mut key = [0; 32];
    let mut stream_key = [0; 32];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut stream_key);
    let state = ShardState { key, stream_key };
    let stream = 0u8;
    let handle = async_std::task::spawn({
        let recv_q = Arc::clone(&recv_q);
        let input_data = Arc::new(input_data.clone());
        repeat(())
            .map(move |_| {
                let input_data = Arc::clone(&input_data);
                let recv_q = Arc::clone(&recv_q);
                async move {
                    let QuorumResolve { serial, data, .. } = recv_q.poll().await;
                    println!("serial {} data_len {}", serial, data.len());
                    assert_eq!(&data[..], &input_data[..], "data mismatch, {}", serial);
                }
            })
            .buffer_unordered(8)
            .for_each_concurrent(8, |_| async {})
    });
    iter(0u64..)
        .map(|serial| {
            let recv_q = &recv_q;
            let codec = &codec;
            iter(shards.iter().take(193).cloned()).for_each_concurrent(8, move |shard| async move {
                let (raw_shard, raw_shard_id) = shard.encode_shard(stream, serial, &state);
                recv_q.admit(raw_shard, raw_shard_id, &state, codec).await;
            })
        })
        .buffer_unordered(8)
        .collect::<Vec<_>>()
        .await;
    handle.await;
    Ok(())
}
