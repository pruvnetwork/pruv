//! Integration tests — batch_prover (parallel Rayon proofs).
//!
//! Fast tests: empty-batch edge cases, order-preservation assertions.
//! Slow tests (#[ignore]): real Halo2 proof generation in parallel.

use halo2_proofs::halo2curves::bn256::Fr;
use pruv_circuits::{
    batch_prover::{batch_merkle, batch_vote},
    circuit_params::fr_to_bytes,
    merkle::MerkleWitness,
    poseidon_hasher::{hash_two, leaf_commitment},
};

const DEPTH: usize = 20;

// ── Witness helpers ───────────────────────────────────────────────────────────

fn merkle_witness(seed: u64) -> MerkleWitness {
    let leaf_fr = leaf_commitment(Fr::from(seed + 1), Fr::from(seed + 2));
    let mut siblings  = Vec::with_capacity(DEPTH);
    let mut path_bits = Vec::with_capacity(DEPTH);
    let mut current   = leaf_fr;
    for i in 0..DEPTH {
        let sib      = Fr::from((i as u64 + seed) * 7 + 1);
        let is_right = i % 2 == 0;
        path_bits.push(is_right);
        siblings.push(sib);
        current = if is_right { hash_two(sib, current) } else { hash_two(current, sib) };
    }
    MerkleWitness {
        leaf:      fr_to_bytes(leaf_fr),
        siblings:  siblings.iter().map(|&s| fr_to_bytes(s)).collect(),
        path_bits,
        root:      fr_to_bytes(current),
    }
}

// ── Fast (no keygen) ─────────────────────────────────────────────────────────

#[test]
fn batch_merkle_empty_slice_returns_empty_vec() {
    let results = batch_merkle(&[]);
    assert!(results.is_empty(), "empty batch must return empty Vec");
    println!("[PASS] batch_merkle_empty_slice_returns_empty_vec");
}

#[test]
fn batch_vote_empty_slice_returns_empty_vec() {
    let results = batch_vote(&[]);
    assert!(results.is_empty(), "empty batch must return empty Vec");
    println!("[PASS] batch_vote_empty_slice_returns_empty_vec");
}

// ── Slow (real proofs) ────────────────────────────────────────────────────────

#[test]
#[ignore = "slow: 2 parallel Halo2 Merkle proofs ~30s"]
fn batch_merkle_two_witnesses_succeed() {
    let witnesses: Vec<_> = (1u64..=2).map(merkle_witness).collect();
    let results = batch_merkle(&witnesses);
    assert_eq!(results.len(), 2, "output length must equal input length");
    for (i, r) in results.iter().enumerate() {
        assert!(r.is_ok(), "witness[{i}] failed: {:?}", r);
        let proof = r.as_ref().unwrap();
        println!("  witness[{i}] proof_bytes={}B", proof.proof_bytes.len());
    }
    println!("[PASS] batch_merkle_two_witnesses_succeed");
}

#[test]
#[ignore = "slow: 3 parallel Halo2 Merkle proofs ~45s"]
fn batch_merkle_three_witnesses_order_preserved() {
    let witnesses: Vec<_> = (10u64..13).map(merkle_witness).collect();
    let expected_roots: Vec<[u8; 32]> = witnesses.iter().map(|w| w.root).collect();

    let results = batch_merkle(&witnesses);
    assert_eq!(results.len(), 3);
    for (i, (r, expected_root)) in results.iter().zip(expected_roots.iter()).enumerate() {
        let proof = r.as_ref().expect(&format!("witness[{i}] failed"));
        // public_inputs = [root, leaf]; index 0 is the Merkle root.
        assert_eq!(
            proof.public_inputs[0], *expected_root,
            "witness[{i}] root mismatch — order not preserved"
        );
        println!("  witness[{i}] root ok, proof_bytes={}B", proof.proof_bytes.len());
    }
    println!("[PASS] batch_merkle_three_witnesses_order_preserved");
}

#[test]
#[ignore = "slow: 2 parallel Halo2 Merkle proofs ~30s"]
fn batch_merkle_bad_witness_produces_err_not_abort() {
    let good = merkle_witness(0);
    let mut bad  = merkle_witness(1);
    bad.root = [0xFFu8; 32]; // mismatch → prove() returns Err

    let results = batch_merkle(&[good, bad]);
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok(),  "valid witness at index 0 must succeed");
    assert!(results[1].is_err(), "invalid witness at index 1 must fail");
    println!("[PASS] batch_merkle_bad_witness_produces_err_not_abort");
}

#[test]
#[ignore = "slow: 2 parallel Halo2 Merkle proofs ~30s"]
fn batch_merkle_results_verify() {
    use pruv_circuits::merkle::verify;
    let witnesses: Vec<_> = (5u64..7).map(merkle_witness).collect();
    let proofs: Vec<_> = batch_merkle(&witnesses)
        .into_iter()
        .map(|r| r.expect("prove must succeed"))
        .collect();
    for (i, p) in proofs.iter().enumerate() {
        let ok = verify(p).expect("verify must not error");
        assert!(ok, "proof[{i}] must verify");
        println!("  proof[{i}] verified OK");
    }
    println!("[PASS] batch_merkle_results_verify");
}