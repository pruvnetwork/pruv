//! pruv circuits — production-grade Halo2 KZG/BN254 zero-knowledge proofs.
//!
//! # Modules
//! - [`circuit_params`] — circuit size constants (`k`), env-var names, Fr byte helpers
//! - [`poseidon_hasher`] — native + in-circuit Poseidon-128 (halo2_gadgets Pow5)
//! - [`srs`]            — thread-safe KZG SRS loader / cache (DashMap)
//! - [`proving_key_cache`] — per-circuit OnceLock proving-key cache
//! - [`merkle`]         — Merkle inclusion proof circuit (depth=20)
//! - [`governance_vote`] — governance vote circuit (nullifier + Merkle + boolean vote)
//! - [`code_integrity`] — code-integrity attestation circuit (SHA-256 + Poseidon)
//! - [`batch_prover`]   — Rayon-parallel batch proof generation

// ─── Shared error / proof-bytes types (used by sub-modules) ──────────────────

/// Serialised proof bytes.
pub type ProofBytes = Vec<u8>;

/// Unified circuit error type.
#[derive(Debug, thiserror::Error)]
pub enum CircuitError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("proving error: {0}")]
    ProvingError(String),
    #[error("verification failed")]
    VerificationError,
    #[error("serde error: {0}")]
    SerdeError(String),
    #[error("SRS error: {0}")]
    SrsError(String),
}

pub mod batch_prover;
pub mod circuit_params;
pub mod code_integrity;
pub mod governance_vote;
pub mod merkle;
pub mod poseidon_hasher;
pub mod proving_key_cache;
pub mod srs;

// ─── Convenience re-exports ───────────────────────────────────────────────────

/// Load (or generate) a KZG SRS for `2^k` rows.  Panics on failure.
/// Used by `code_integrity` and other modules that cannot propagate errors.
pub fn load_srs(
    k: u32,
) -> std::sync::Arc<halo2_proofs::poly::kzg::commitment::ParamsKZG<halo2_proofs::halo2curves::bn256::Bn256>>
{
    srs::get(k).expect("pruv: failed to load/generate KZG SRS")
}
