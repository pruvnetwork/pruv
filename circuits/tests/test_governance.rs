//! Integration tests — governance vote circuit.

use halo2_proofs::halo2curves::bn256::Fr;
use pruv_circuits::{
    circuit_params::fr_to_bytes,
    governance_vote::{prove, verify, VoteWitness},
    poseidon_hasher::{hash_two, leaf_commitment},
};

const DEPTH: usize = 20;

fn make_vote_witness(vote_value: u8) -> VoteWitness {
    let voter_secret_fr  = Fr::from(0xdeadbeefu64);
    let voter_pk_hash_fr = Fr::from(0xcafebabeu64);
    let weight_fr        = Fr::from(100u64);
    let proposal_id_fr   = Fr::from(42u64);

    let leaf_fr = leaf_commitment(voter_pk_hash_fr, weight_fr);
    let mut siblings  = Vec::new();
    let mut path_bits = Vec::new();
    let mut current   = leaf_fr;
    for i in 0..DEPTH {
        let sib      = Fr::from((i as u64 + 200) * 3 + 1);
        let is_right = i % 2 == 0;
        path_bits.push(is_right);
        siblings.push(sib);
        current = if is_right { hash_two(sib, current) } else { hash_two(current, sib) };
    }
    VoteWitness {
        voter_secret:  fr_to_bytes(voter_secret_fr),
        voter_pk_hash: fr_to_bytes(voter_pk_hash_fr),
        weight:        fr_to_bytes(weight_fr),
        siblings:      siblings.iter().map(|&s| fr_to_bytes(s)).collect(),
        path_bits,
        merkle_root:   fr_to_bytes(current),
        proposal_id:   fr_to_bytes(proposal_id_fr),
        vote_value,
    }
}

// ── Fast (native validation only) ────────────────────────────────────────────

#[test]
fn wrong_merkle_root_rejected_at_prove() {
    let mut w = make_vote_witness(1);
    w.merkle_root[0] ^= 0xff;
    let err = prove(&w).expect_err("corrupted root must fail at prove()");
    println!("[PASS] wrong_merkle_root_rejected_at_prove  err={err}");
}

#[test]
fn invalid_vote_value_panics() {
    let w = make_vote_witness(2);
    let result = std::panic::catch_unwind(|| prove(&w));
    assert!(result.is_err(), "vote_value=2 must panic");
    println!("[PASS] invalid_vote_value_panics");
}

#[test]
fn invalid_vote_value_255_panics() {
    let w = make_vote_witness(255);
    let result = std::panic::catch_unwind(|| prove(&w));
    assert!(result.is_err(), "vote_value=255 must panic");
    println!("[PASS] invalid_vote_value_255_panics");
}

// ── Full prove + verify pipeline (slow) ──────────────────────────────────────

#[test]
#[ignore = "slow: Halo2 keygen + prove ~45s"]
fn prove_verify_vote_yes() {
    let w = make_vote_witness(1);
    let proof = prove(&w).expect("prove vote=1 must succeed");
    println!("  proof_bytes.len() = {}", proof.proof_bytes.len());
    let ok = verify(&proof).expect("verify must succeed");
    assert!(ok, "vote=1 proof must verify");
    println!("[PASS] prove_verify_vote_yes");
}

#[test]
#[ignore = "slow: Halo2 keygen + prove ~45s"]
fn prove_verify_vote_no() {
    let w = make_vote_witness(0);
    let proof = prove(&w).expect("prove vote=0 must succeed");
    let ok = verify(&proof).expect("verify must succeed");
    assert!(ok, "vote=0 proof must verify");
    println!("[PASS] prove_verify_vote_no  (proof_bytes={}B)", proof.proof_bytes.len());
}

#[test]
#[ignore = "slow: Halo2 keygen + prove ~90s (2 proofs)"]
fn nullifier_differs_across_proposals() {
    let w1 = make_vote_witness(1);
    let mut w2 = make_vote_witness(1);
    w2.proposal_id[0] ^= 0x01;
    // Both witnesses have the same Merkle root so both prove() should succeed.
    let p1 = prove(&w1).expect("prove w1");
    let p2 = prove(&w2).expect("prove w2");
    // public_inputs[1] is the nullifier
    assert_ne!(
        p1.public_inputs[1], p2.public_inputs[1],
        "different proposal_id must produce different nullifier"
    );
    println!("[PASS] nullifier_differs_across_proposals");
}

#[test]
#[ignore = "slow: Halo2 keygen + prove ~45s"]
fn tampered_proof_bytes_fails_verify() {
    let w = make_vote_witness(1);
    let mut proof = prove(&w).expect("prove must succeed");
    let mid = proof.proof_bytes.len() / 2;
    proof.proof_bytes[mid] ^= 0xff;
    let ok = verify(&proof).expect("verify should not error on tampered proof");
    assert!(!ok, "tampered proof must fail verification");
    println!("[PASS] tampered_proof_bytes_fails_verify");
}