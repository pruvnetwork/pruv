//! Integration tests — Merkle inclusion proof circuit.
//!
//! Fast tests: witness construction, root validation (native).
//! Slow tests (#[ignore]): full Halo2 prove + verify pipeline.

use halo2_proofs::halo2curves::bn256::Fr;
use pruv_circuits::{
    circuit_params::{fr_to_bytes, fr_from_bytes},
    merkle::{prove, verify, MerkleWitness},
    poseidon_hasher::{hash_two, leaf_commitment, merkle_root_from_path},
};

const DEPTH: usize = 20;

// ── Witness builder ───────────────────────────────────────────────────────────

fn make_witness(leaf_seed: u64) -> MerkleWitness {
    let leaf_fr = leaf_commitment(Fr::from(leaf_seed), Fr::from(leaf_seed + 1));
    let mut siblings  = Vec::with_capacity(DEPTH);
    let mut path_bits = Vec::with_capacity(DEPTH);
    let mut current   = leaf_fr;
    for i in 0..DEPTH {
        let sib      = Fr::from((i as u64 + leaf_seed + 7) * 13 + 3);
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

// ── Native-only (fast) ────────────────────────────────────────────────────────

#[test]
fn witness_root_is_consistent() {
    let w = make_witness(42);
    // Recompute root natively; must match w.root.
    let leaf_fr = fr_from_bytes(&w.leaf).unwrap();
    let sibs: Vec<Fr> = w.siblings.iter()
        .map(|b| fr_from_bytes(b).unwrap())
        .collect();
    let computed = merkle_root_from_path(leaf_fr, &sibs, &w.path_bits);
    let stored   = fr_from_bytes(&w.root).unwrap();
    assert_eq!(computed, stored, "native root recomputation must match stored root");
    println!("[PASS] witness_root_is_consistent  depth={DEPTH}");
}

#[test]
fn different_leaves_produce_different_roots() {
    let w1 = make_witness(1);
    let w2 = make_witness(2);
    assert_ne!(w1.root, w2.root, "distinct leaf seeds must yield distinct roots");
    println!("[PASS] different_leaves_produce_different_roots");
}

#[test]
fn wrong_root_caught_before_proof() {
    let mut w = make_witness(77);
    w.root[0] ^= 0xaa;
    let err = prove(&w).expect_err("corrupted root must fail at prove()");
    assert!(
        err.to_string().contains("mismatch") || err.to_string().contains("invalid"),
        "error message should mention mismatch: {err}"
    );
    println!("[PASS] wrong_root_caught_before_proof  err={err}");
}

#[test]
fn siblings_length_mismatch_panics() {
    let mut w = make_witness(5);
    w.siblings.pop(); // now len = DEPTH - 1
    let result = std::panic::catch_unwind(|| prove(&w));
    assert!(result.is_err(), "siblings.len() != DEPTH must panic");
    println!("[PASS] siblings_length_mismatch_panics");
}

#[test]
fn path_bits_length_mismatch_panics() {
    let mut w = make_witness(5);
    w.path_bits.pop(); // now len = DEPTH - 1
    let result = std::panic::catch_unwind(|| prove(&w));
    assert!(result.is_err(), "path_bits.len() != DEPTH must panic");
    println!("[PASS] path_bits_length_mismatch_panics");
}

// ── Full prove + verify pipeline (slow) ──────────────────────────────────────

#[test]
#[ignore = "slow: Halo2 keygen + prove ~30s"]
fn prove_verify_depth20() {
    let w = make_witness(42);
    let proof = prove(&w).expect("prove must succeed");
    println!("  proof_bytes.len() = {}", proof.proof_bytes.len());
    println!("  public_inputs[0] (root) = {:?}", proof.public_inputs[0]);

    let ok = verify(&proof).expect("verify must succeed");
    assert!(ok, "valid proof must verify as true");
    println!("[PASS] prove_verify_depth20  (proof_bytes={}B)", proof.proof_bytes.len());
}

#[test]
#[ignore = "slow: Halo2 keygen + prove ~30s"]
fn prove_verify_different_leaf_seeds() {
    for seed in [1u64, 100, 999] {
        let w     = make_witness(seed);
        let proof = prove(&w).expect(&format!("prove failed for seed={seed}"));
        let ok    = verify(&proof).expect("verify failed");
        assert!(ok, "proof for seed={seed} must verify");
        println!("  [OK] seed={seed}  proof_bytes={}B", proof.proof_bytes.len());
    }
    println!("[PASS] prove_verify_different_leaf_seeds");
}

#[test]
#[ignore = "slow: Halo2 keygen + prove ~30s"]
fn tampered_proof_bytes_fails_verify() {
    let w     = make_witness(42);
    let mut proof = prove(&w).expect("prove must succeed");
    // Flip bits in the middle of the proof transcript.
    let mid = proof.proof_bytes.len() / 2;
    proof.proof_bytes[mid] ^= 0xff;
    let ok = verify(&proof).expect("verify should not error on tampered proof");
    assert!(!ok, "tampered proof must fail verification");
    println!("[PASS] tampered_proof_bytes_fails_verify");
}

#[test]
#[ignore = "slow: Halo2 keygen + prove ~60s (2 proofs)"]
fn two_independent_proofs_both_verify() {
    let w1 = make_witness(10);
    let w2 = make_witness(20);
    let p1 = prove(&w1).expect("prove w1");
    let p2 = prove(&w2).expect("prove w2");
    assert!(verify(&p1).expect("verify p1"), "proof 1 must verify");
    assert!(verify(&p2).expect("verify p2"), "proof 2 must verify");
    println!("[PASS] two_independent_proofs_both_verify");
}