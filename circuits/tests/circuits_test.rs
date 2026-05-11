//! Integration tests for pruv circuits — pure-logic and caching layer.
//!
//! These tests run as a separate binary (`cargo test -p pruv-circuits`) so
//! every `OnceLock` proving-key slot starts empty.
//!
//! # Test groups
//! - `circuit_params` — `fr_to_bytes` / `fr_from_bytes` byte-layout helpers
//! - `proving_key_cache` — OnceLock idempotency and concurrent keygen safety
//! - `batch_prover` — empty-batch edge cases and order-preservation guarantees
//!
//! # Slow tests
//! Tests that invoke actual Halo2 keygen / prove are marked `#[ignore = "slow"]`
//! and must be opted into explicitly:
//!   cargo test -p pruv-circuits --test circuits_test -- --ignored

use std::sync::Arc;

use ff::PrimeField;
use halo2_proofs::halo2curves::bn256::Fr;

use pruv_circuits::{
    batch_prover::{batch_merkle, batch_vote},
    circuit_params::{fr_from_bytes, fr_to_bytes, MERKLE_K},
    merkle::{MerkleWitness, DEPTH},
    poseidon_hasher::{hash_two, leaf_commitment},
};

// ═════════════════════════════════════════════════════════════════════════════
// circuit_params — fr_to_bytes / fr_from_bytes
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn fr_zero_roundtrip() {
    let zero = Fr::zero();
    let bytes = fr_to_bytes(zero);
    let back = fr_from_bytes(&bytes).expect("Fr::zero should be in-range");
    assert_eq!(zero, back);
}

#[test]
fn fr_one_roundtrip() {
    let one = Fr::one();
    let bytes = fr_to_bytes(one);
    let back = fr_from_bytes(&bytes).expect("Fr::one should be in-range");
    assert_eq!(one, back);
}

#[test]
fn fr_large_value_roundtrip() {
    for seed in [1u64, 42, u32::MAX as u64, u64::MAX / 2, u64::MAX] {
        let f = Fr::from(seed);
        let bytes = fr_to_bytes(f);
        let back = fr_from_bytes(&bytes).expect("Fr::from(seed) should be in-range");
        assert_eq!(f, back, "roundtrip failed for seed={seed}");
    }
}

#[test]
fn fr_to_bytes_is_little_endian() {
    // Fr::from(1) in LE → first byte is 1, rest are 0.
    let bytes = fr_to_bytes(Fr::from(1u64));
    assert_eq!(bytes[0], 1, "first LE byte of Fr(1) should be 1");
    assert!(bytes[1..].iter().all(|&b| b == 0), "upper bytes of Fr(1) should be zero");
}

#[test]
fn fr_to_bytes_deterministic() {
    let f = Fr::from(0xdeadbeef_cafebabeu64);
    let a = fr_to_bytes(f);
    let b = fr_to_bytes(f);
    assert_eq!(a, b);
}

#[test]
fn fr_from_bytes_all_ff_returns_none() {
    // [0xFF; 32] > BN254 field modulus → should return None.
    let bytes = [0xFFu8; 32];
    assert!(
        fr_from_bytes(&bytes).is_none(),
        "[0xFF;32] is above the BN254 modulus and must be rejected"
    );
}

#[test]
fn fr_from_bytes_zero_bytes_returns_zero() {
    let back = fr_from_bytes(&[0u8; 32]).expect("zero bytes → Fr::zero");
    assert_eq!(back, Fr::zero());
}

#[test]
fn fr_from_bytes_and_fr_to_bytes_are_inverses() {
    // Encode N canonical field elements and decode them back.
    for i in 0u64..64 {
        let orig = Fr::from(i.wrapping_mul(0x9e3779b9_7f4a7c15));
        let bytes = fr_to_bytes(orig);
        let recovered = fr_from_bytes(&bytes).expect("should decode");
        assert_eq!(orig, recovered, "encode→decode failed for i={i}");
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// proving_key_cache — CircuitId enum & OnceLock idempotency
// ═════════════════════════════════════════════════════════════════════════════

use pruv_circuits::proving_key_cache::{get_or_build, CircuitId};

#[test]
fn circuit_id_equality_and_copy() {
    // Enum implements Copy + PartialEq + Eq + Hash
    let a = CircuitId::Merkle;
    let b = a; // Copy
    assert_eq!(a, b);
    assert_ne!(CircuitId::Merkle, CircuitId::GovernanceVote);
    assert_ne!(CircuitId::Merkle, CircuitId::CodeIntegrity);
    assert_ne!(CircuitId::GovernanceVote, CircuitId::CodeIntegrity);
}

#[test]
fn circuit_id_debug_does_not_panic() {
    let _ = format!("{:?}", CircuitId::Merkle);
    let _ = format!("{:?}", CircuitId::GovernanceVote);
    let _ = format!("{:?}", CircuitId::CodeIntegrity);
}

/// Build Merkle proving keys twice and assert the second call returns the
/// exact same Arc (pointer equality ⇒ keys built only once).
///
/// Marked `#[ignore]` because `keygen` takes ~1–5 s per circuit.
/// Run with: cargo test -p pruv-circuits --test circuits_test -- --ignored
#[test]
#[ignore = "slow: invokes Halo2 keygen (~5 s)"]
fn get_or_build_idempotent_returns_same_arc() {
    use pruv_circuits::{merkle::MerkleCircuit, srs};

    let params = srs::get(MERKLE_K).expect("SRS");

    let kp1 = get_or_build(CircuitId::Merkle, &params, MerkleCircuit::empty)
        .expect("first keygen");
    let kp2 = get_or_build(CircuitId::Merkle, &params, MerkleCircuit::empty)
        .expect("second keygen");

    // Arc::ptr_eq ensures the underlying allocation is shared (not just equal).
    assert!(
        Arc::ptr_eq(&kp1.pk, &kp2.pk),
        "second get_or_build must return the cached ProvingKey Arc"
    );
    assert!(
        Arc::ptr_eq(&kp1.vk, &kp2.vk),
        "second get_or_build must return the cached VerifyingKey Arc"
    );
}

/// Spawn 8 threads, all calling `get_or_build` for the Merkle circuit.
/// All must succeed and all must hold the same Arc pointer.
#[test]
#[ignore = "slow: invokes Halo2 keygen (~5 s) under concurrency"]
fn get_or_build_concurrent_no_panic_or_data_race() {
    use pruv_circuits::{merkle::MerkleCircuit, srs};

    let params = srs::get(MERKLE_K).expect("SRS");

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let p = Arc::clone(&params);
            std::thread::spawn(move || {
                get_or_build(CircuitId::Merkle, &p, MerkleCircuit::empty)
                    .expect("concurrent keygen")
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All threads must have received the same ProvingKey Arc.
    let first_ptr = Arc::as_ptr(&results[0].pk);
    for (i, kp) in results.iter().enumerate() {
        assert_eq!(
            Arc::as_ptr(&kp.pk),
            first_ptr,
            "thread {i} got a different ProvingKey Arc — OnceLock violated"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// batch_prover — edge cases and ordering
// ═════════════════════════════════════════════════════════════════════════════

/// Helper: build a consistent Merkle witness from a seed.
fn make_merkle_witness(seed: u64) -> MerkleWitness {
    let leaf_fr = leaf_commitment(Fr::from(seed + 1), Fr::from(seed + 2));
    let mut siblings = Vec::with_capacity(DEPTH);
    let mut path_bits = Vec::with_capacity(DEPTH);
    let mut current = leaf_fr;
    for i in 0..DEPTH {
        let sib = Fr::from((i as u64 + seed + 10) * 13 + 1);
        let is_right = (i + seed as usize) % 2 == 0;
        path_bits.push(is_right);
        siblings.push(sib);
        current = if is_right {
            hash_two(sib, current)
        } else {
            hash_two(current, sib)
        };
    }
    MerkleWitness {
        leaf: fr_to_bytes(leaf_fr),
        siblings: siblings.iter().map(|&s| fr_to_bytes(s)).collect(),
        path_bits,
        root: fr_to_bytes(current),
    }
}

#[test]
fn batch_merkle_empty_returns_empty_vec() {
    let results = batch_merkle(&[]);
    assert!(results.is_empty(), "empty batch should return empty Vec");
}

#[test]
fn batch_vote_empty_returns_empty_vec() {
    let results = batch_vote(&[]);
    assert!(results.is_empty(), "empty batch should return empty Vec");
}

/// Prove 3 Merkle witnesses in parallel and verify output length + order.
/// Marked `#[ignore]` because each proof takes several seconds.
#[test]
#[ignore = "slow: 3 × Halo2 Merkle proofs (~30 s total)"]
fn batch_merkle_three_witnesses_all_succeed_in_order() {
    let witnesses: Vec<_> = (0u64..3).map(make_merkle_witness).collect();
    // Record expected roots so we can check order-preservation.
    let expected_roots: Vec<[u8; 32]> = witnesses.iter().map(|w| w.root).collect();

    let results = batch_merkle(&witnesses);
    assert_eq!(results.len(), 3, "result count must match input count");

    for (i, (res, expected_root)) in results.iter().zip(expected_roots.iter()).enumerate() {
        let proof = res.as_ref().unwrap_or_else(|e| panic!("witness {i} failed: {e}"));
        // public_inputs = [root, leaf]  (index 0 is the Merkle root)
        assert_eq!(
            proof.public_inputs[0], *expected_root,
            "witness {i}: root in proof does not match expected root"
        );
    }
}

/// One invalid Merkle witness (mismatched root) must produce an Err, while
/// a valid witness in the same batch still produces Ok.
#[test]
#[ignore = "slow: 2 × Halo2 Merkle proofs (~20 s)"]
fn batch_merkle_bad_witness_produces_err_without_aborting_batch() {
    let good = make_merkle_witness(0);

    // Corrupt the root so the constraint system is unsatisfied.
    let mut bad = make_merkle_witness(1);
    bad.root = [0xFFu8; 32]; // wrong root → proof must fail

    let results = batch_merkle(&[good, bad]);
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok(),  "valid witness at index 0 should succeed");
    assert!(results[1].is_err(), "invalid witness at index 1 should fail");
}

// ═════════════════════════════════════════════════════════════════════════════
// cross-module: fr_to_bytes / fr_from_bytes contract with poseidon_hasher
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn poseidon_hash_two_result_is_valid_field_element() {
    // hash_two must always return a value that survives the byte roundtrip.
    for (a, b) in [(0u64, 1u64), (u64::MAX, 0), (42, 999)] {
        let h = hash_two(Fr::from(a), Fr::from(b));
        let bytes = fr_to_bytes(h);
        let back = fr_from_bytes(&bytes)
            .expect("Poseidon output must be a canonical field element");
        assert_eq!(h, back, "poseidon output roundtrip failed for ({a},{b})");
    }
}

#[test]
fn leaf_commitment_result_is_valid_field_element() {
    let leaf = leaf_commitment(Fr::from(123u64), Fr::from(456u64));
    let bytes = fr_to_bytes(leaf);
    let back = fr_from_bytes(&bytes).expect("leaf_commitment must produce a canonical Fr");
    assert_eq!(leaf, back);
}