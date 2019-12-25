use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, traits::Identity};

use super::*;
use rand::{rngs::StdRng, SeedableRng};

#[test]
fn it_works() {
    let mut rng = StdRng::from_entropy();
    let custodian_base = ED25519_BASEPOINT_POINT * u64_to_scalar(2);
    let ids = vec![1, 2, 3];
    let private_keys = vec![u64_to_scalar(3), u64_to_scalar(4), u64_to_scalar(5)];
    let custodians = ids
        .iter()
        .zip(private_keys.iter())
        .map(|(&id, &key)| Custodian {
            id,
            key: custodian_base * key,
        })
        .collect::<Vec<_>>()
        .verify_proof(())
        .unwrap();
    let shards = ShardsWithProof::new(&mut rng, 2, &custodian_base, &custodians).unwrap();
    assert_eq!(shards.shards.len(), 3);
    let verified_shards: Vec<_> = shards
        .shards
        .iter()
        .map(|shard| {
            shard
                .clone()
                .verify_proof(shards.dealer_proof.clone())
                .unwrap()
        })
        .collect();
    let custodian_decryptions: Vec<_> = verified_shards
        .iter()
        .enumerate()
        .map(|(idx, shard)| {
            let (dec, proof) =
                CustodianDecryption::new(&mut rng, &custodian_base, &private_keys[idx], &shard)
                    .unwrap();
            dec.verify_proof((custodian_base, custodians[idx].key, proof))
                .unwrap()
        })
        .collect();
    let poll = Poll {
        threshold: 2,
        poll: custodian_decryptions,
    }
    .verify_proof(custodians)
    .unwrap();
    assert_eq!(recover_secret(poll), shards.secret);
}

#[test]
fn polynomial() {
    let mut rng = StdRng::from_entropy();
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    let polynomial = Polynomial::new(&mut rng, 5, secret).unwrap();
    let commits = Commits::new(&polynomial);
    let mut a = EdwardsPoint::identity();
    let id = u64_to_scalar(39);
    for commit in commits.0.iter().rev() {
        a *= id;
        a += commit;
    }
    assert_eq!(a, ED25519_BASEPOINT_POINT * polynomial.eval(&id));
}
