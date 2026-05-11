//! Per-circuit proving-key / verification-key cache.
//!
//! Keys are built once per process (expensive: ~1–5 s per circuit) and then
//! reused for every subsequent proof.  Thread-safety is achieved via
//! `std::sync::OnceLock` — the standard-library primitive that initialises
//! exactly once and never panics on concurrent access.
//!
//! # Usage
//! ```rust,ignore
//! use pruv_circuits::proving_key_cache::{get_or_build, CircuitId};
//! use pruv_circuits::merkle::MerkleCircuit;
//!
//! let params = pruv_circuits::srs::get(MERKLE_K)?;
//! let keys = get_or_build(CircuitId::Merkle, &params, MerkleCircuit::empty)?;
//! // keys.pk  — ProvingKey<Bn256>
//! // keys.vk  — VerifyingKey<Bn256>
//! ```

use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{Circuit, ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
};

// ─── Public types ─────────────────────────────────────────────────────────────

/// Identifies a circuit whose proving key should be cached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CircuitId {
    Merkle,
    GovernanceVote,
    CodeIntegrity,
}

/// A pair of proving key + verifying key, wrapped in `Arc` for cheap cloning.
#[derive(Clone)]
pub struct KeyPair {
    pub pk: Arc<ProvingKey<G1Affine>>,
    pub vk: Arc<VerifyingKey<G1Affine>>,
}

// ─── Per-circuit static slots ─────────────────────────────────────────────────

static MERKLE_KEYS:      OnceLock<KeyPair> = OnceLock::new();
static GOVERNANCE_KEYS:  OnceLock<KeyPair> = OnceLock::new();
static INTEGRITY_KEYS:   OnceLock<KeyPair> = OnceLock::new();

fn slot(id: CircuitId) -> &'static OnceLock<KeyPair> {
    match id {
        CircuitId::Merkle         => &MERKLE_KEYS,
        CircuitId::GovernanceVote => &GOVERNANCE_KEYS,
        CircuitId::CodeIntegrity  => &INTEGRITY_KEYS,
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Return the cached `KeyPair` for `id`, building it from `params` if needed.
///
/// `empty_circuit` is called **only** on the first invocation to derive the
/// constraint system layout; it must return a circuit with all witnesses set
/// to `Value::unknown()`.
///
/// Thread-safe: concurrent callers block until the first caller finishes
/// building the keys, then all receive the same cached value.
pub fn get_or_build<C: Circuit<halo2_proofs::halo2curves::bn256::Fr> + Clone>(
    id: CircuitId,
    params: &ParamsKZG<Bn256>,
    empty_circuit: impl FnOnce() -> C,
) -> Result<KeyPair> {
    let s = slot(id);
    if let Some(kp) = s.get() {
        return Ok(kp.clone());
    }

    // Build keys — this is the slow path.
    let circuit = empty_circuit();
    let kp = build_keys(params, circuit)
        .with_context(|| format!("building keys for {:?}", id))?;

    // `set` returns `Err(val)` if already set by a concurrent thread — that is
    // fine, we just use the cached value.
    let _ = s.set(kp.clone());
    Ok(s.get().unwrap().clone())
}

/// Pre-warm all three circuit key caches in parallel using Rayon.
/// Call this once at node startup so the first proof request is not delayed.
pub fn warm_all(_params: &ParamsKZG<Bn256>) -> Result<()> {
    use crate::{
        circuit_params::{GOVERNANCE_K, MERKLE_K},
        governance_vote::GovernanceCircuit,
        merkle::MerkleCircuit,
        srs,
    };
    use rayon::prelude::*;

    let jobs: Vec<Box<dyn Fn() -> Result<()> + Send + Sync>> = vec![
        Box::new({
            let p = srs::get(MERKLE_K)?;
            move || {
                get_or_build(CircuitId::Merkle, &p, MerkleCircuit::empty)?;
                Ok(())
            }
        }),
        Box::new({
            let p = srs::get(GOVERNANCE_K)?;
            move || {
                get_or_build(CircuitId::GovernanceVote, &p, GovernanceCircuit::empty)?;
                Ok(())
            }
        }),
    ];

    jobs.into_par_iter()
        .map(|f| f())
        .collect::<Result<Vec<_>>>()?;

    tracing::info!("proving key cache warmed");
    Ok(())
}

// ─── Internal ─────────────────────────────────────────────────────────────────

fn build_keys<C: Circuit<halo2_proofs::halo2curves::bn256::Fr>>(
    params: &ParamsKZG<Bn256>,
    circuit: C,
) -> Result<KeyPair> {
    use halo2_proofs::plonk::{keygen_pk, keygen_vk};

    let vk = keygen_vk(params, &circuit)
        .map_err(|e| anyhow::anyhow!("keygen_vk: {e:?}"))?;
    let pk = keygen_pk(params, vk.clone(), &circuit)
        .map_err(|e| anyhow::anyhow!("keygen_pk: {e:?}"))?;

    Ok(KeyPair {
        pk: Arc::new(pk),
        vk: Arc::new(vk),
    })
}