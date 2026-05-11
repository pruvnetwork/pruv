//! Integration tests — poseidon_hasher native primitives.

use halo2_proofs::halo2curves::bn256::Fr;
use pruv_circuits::poseidon_hasher::{
    hash_chain3, hash_one, hash_two, leaf_commitment, merkle_root_from_path, nullifier,
};

#[test]
fn hash_two_deterministic() {
    let a = Fr::from(1u64);
    let b = Fr::from(2u64);
    assert_eq!(hash_two(a, b), hash_two(a, b));
    println!("[PASS] hash_two_deterministic");
}

#[test]
fn hash_two_not_symmetric() {
    let a = Fr::from(1u64);
    let b = Fr::from(2u64);
    assert_ne!(hash_two(a, b), hash_two(b, a), "Poseidon(a,b) must differ from Poseidon(b,a)");
    println!("[PASS] hash_two_not_symmetric");
}

#[test]
fn hash_two_nonzero_inputs_nonzero() {
    let h = hash_two(Fr::from(3u64), Fr::from(7u64));
    assert_ne!(h, Fr::from(0u64), "hash of nonzero inputs must not be zero");
    println!("[PASS] hash_two_nonzero_inputs_nonzero");
}

#[test]
fn hash_two_different_inputs_differ() {
    let h1 = hash_two(Fr::from(100u64), Fr::from(200u64));
    let h2 = hash_two(Fr::from(101u64), Fr::from(200u64));
    assert_ne!(h1, h2, "distinct inputs must produce distinct outputs");
    println!("[PASS] hash_two_different_inputs_differ");
}

#[test]
fn hash_one_deterministic() {
    let a = Fr::from(42u64);
    assert_eq!(hash_one(a), hash_one(a));
    println!("[PASS] hash_one_deterministic");
}

#[test]
fn hash_one_differs_from_hash_two() {
    let a = Fr::from(5u64);
    let h1 = hash_one(a);
    let h2 = hash_two(a, a);
    assert_ne!(h1, h2, "hash_one(a) should differ from hash_two(a,a)");
    println!("[PASS] hash_one_differs_from_hash_two");
}

#[test]
fn nullifier_deterministic() {
    let secret   = Fr::from(999u64);
    let proposal = Fr::from(42u64);
    assert_eq!(nullifier(secret, proposal), nullifier(secret, proposal));
    println!("[PASS] nullifier_deterministic");
}

#[test]
fn nullifier_differs_by_proposal() {
    let secret = Fr::from(999u64);
    let n1 = nullifier(secret, Fr::from(1u64));
    let n2 = nullifier(secret, Fr::from(2u64));
    assert_ne!(n1, n2, "different proposal_id must yield different nullifier");
    println!("[PASS] nullifier_differs_by_proposal");
}

#[test]
fn nullifier_differs_by_secret() {
    let proposal = Fr::from(42u64);
    let n1 = nullifier(Fr::from(1u64), proposal);
    let n2 = nullifier(Fr::from(2u64), proposal);
    assert_ne!(n1, n2, "different voter_secret must yield different nullifier");
    println!("[PASS] nullifier_differs_by_secret");
}

#[test]
fn leaf_commitment_deterministic() {
    let pk_hash = Fr::from(0xcafeu64);
    let weight  = Fr::from(100u64);
    assert_eq!(leaf_commitment(pk_hash, weight), leaf_commitment(pk_hash, weight));
    println!("[PASS] leaf_commitment_deterministic");
}

#[test]
fn leaf_commitment_weight_sensitive() {
    let pk_hash = Fr::from(0xcafeu64);
    let l1 = leaf_commitment(pk_hash, Fr::from(1u64));
    let l2 = leaf_commitment(pk_hash, Fr::from(2u64));
    assert_ne!(l1, l2, "different weight must yield different leaf");
    println!("[PASS] leaf_commitment_weight_sensitive");
}

#[test]
fn merkle_root_depth1_left() {
    let leaf = Fr::from(7u64);
    let sib  = Fr::from(13u64);
    let got = merkle_root_from_path(leaf, &[sib], &[false]);
    assert_eq!(got, hash_two(leaf, sib), "is_right=false → hash_two(leaf, sib)");
    println!("[PASS] merkle_root_depth1_left");
}

#[test]
fn merkle_root_depth1_right() {
    let leaf = Fr::from(7u64);
    let sib  = Fr::from(13u64);
    let got = merkle_root_from_path(leaf, &[sib], &[true]);
    assert_eq!(got, hash_two(sib, leaf), "is_right=true → hash_two(sib, leaf)");
    println!("[PASS] merkle_root_depth1_right");
}

#[test]
fn merkle_root_path_changes_with_bit() {
    let leaf = Fr::from(42u64);
    let sib  = Fr::from(99u64);
    let r_left  = merkle_root_from_path(leaf, &[sib], &[false]);
    let r_right = merkle_root_from_path(leaf, &[sib], &[true]);
    assert_ne!(r_left, r_right, "different path bit must yield different root");
    println!("[PASS] merkle_root_path_changes_with_bit");
}

#[test]
fn hash_chain3_deterministic() {
    let a = Fr::from(1u64);
    let b = Fr::from(2u64);
    let c = Fr::from(3u64);
    assert_eq!(hash_chain3(a, b, c), hash_chain3(a, b, c));
    println!("[PASS] hash_chain3_deterministic");
}

#[test]
fn hash_chain3_matches_manual() {
    let a = Fr::from(10u64);
    let b = Fr::from(20u64);
    let c = Fr::from(30u64);
    let manual = hash_two(hash_two(a, b), c);
    assert_eq!(hash_chain3(a, b, c), manual, "hash_chain3 must equal hash_two(hash_two(a,b),c)");
    println!("[PASS] hash_chain3_matches_manual");
}

#[test]
fn hash_chain3_sensitive_to_each_arg() {
    let a = Fr::from(1u64);
    let b = Fr::from(2u64);
    let c = Fr::from(3u64);
    let base = hash_chain3(a, b, c);
    assert_ne!(base, hash_chain3(Fr::from(99u64), b, c), "must differ when a changes");
    assert_ne!(base, hash_chain3(a, Fr::from(99u64), c), "must differ when b changes");
    assert_ne!(base, hash_chain3(a, b, Fr::from(99u64)), "must differ when c changes");
    println!("[PASS] hash_chain3_sensitive_to_each_arg");
}