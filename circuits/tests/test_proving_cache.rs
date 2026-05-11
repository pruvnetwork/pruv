//! Integration tests — proving_key_cache (CircuitId enum, fast tests only).

use pruv_circuits::proving_key_cache::CircuitId;

#[test]
fn circuit_id_copy_and_eq() {
    let a = CircuitId::Merkle;
    let b = a; // Copy trait
    assert_eq!(a, b);
    assert_ne!(CircuitId::Merkle, CircuitId::GovernanceVote);
    assert_ne!(CircuitId::Merkle, CircuitId::CodeIntegrity);
    assert_ne!(CircuitId::GovernanceVote, CircuitId::CodeIntegrity);
    println!("[PASS] circuit_id_copy_and_eq");
}

#[test]
fn circuit_id_debug_does_not_panic() {
    let _ = format!("{:?}", CircuitId::Merkle);
    let _ = format!("{:?}", CircuitId::GovernanceVote);
    let _ = format!("{:?}", CircuitId::CodeIntegrity);
    println!("[PASS] circuit_id_debug_does_not_panic");
}

#[test]
fn circuit_id_hash_works() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(CircuitId::Merkle);
    set.insert(CircuitId::GovernanceVote);
    set.insert(CircuitId::CodeIntegrity);
    assert_eq!(set.len(), 3, "all three CircuitId values must hash distinctly");
    println!("[PASS] circuit_id_hash_works");
}

#[test]
fn circuit_id_is_not_equal_to_different_variant() {
    assert!(CircuitId::Merkle != CircuitId::GovernanceVote);
    assert!(CircuitId::Merkle != CircuitId::CodeIntegrity);
    println!("[PASS] circuit_id_is_not_equal_to_different_variant");
}