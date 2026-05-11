//! Shared circuit parameters for all pruv Halo2 circuits.
//!
//! This module contains only well-typed constants that control circuit size
//! and environment-variable names.  All Poseidon constants are sourced from
//! `halo2_gadgets::poseidon` — no hand-rolled round constants here.

// ─── Circuit size (k) ─────────────────────────────────────────────────────────

/// `2^k` rows allocated for the Merkle inclusion circuit (depth=20).
/// 20 Poseidon hashes × ~30 rows each ≈ 600 rows; k=10 gives 1 024 rows with
/// comfortable headroom.  Use k=20 for mainnet to allow full audit.
pub const MERKLE_K: u32 = 13;

/// `2^k` rows for the governance-vote circuit (nullifier + Merkle subtree).
pub const GOVERNANCE_K: u32 = 14;

/// `2^k` rows for the code-integrity attestation circuit.
pub const CODE_INTEGRITY_K: u32 = 12;

// ─── Environment variables ────────────────────────────────────────────────────

/// Path to the KZG ceremony SRS file (Powers of Tau, BN254).
/// In production set this to the downloaded `ptau` file path.
/// When unset the node generates an **insecure** random SRS — acceptable only
/// for testing / local development.
pub const SRS_PATH_ENV: &str = "PRUV_SRS_PATH";

// ─── Byte-conversion helpers (Fr ↔ [u8; 32]) ─────────────────────────────────

use ff::PrimeField;
use halo2_proofs::halo2curves::bn256::Fr;

/// Encode a field element as 32 little-endian bytes.
#[inline]
pub fn fr_to_bytes(f: Fr) -> [u8; 32] {
    let repr = f.to_repr();
    let mut out = [0u8; 32];
    out.copy_from_slice(repr.as_ref());
    out
}

/// Decode 32 little-endian bytes into a field element.
/// Returns `None` if the value is ≥ the field modulus.
#[inline]
pub fn fr_from_bytes(b: &[u8; 32]) -> Option<Fr> {
    Fr::from_repr((*b).into()).into_option()
}
