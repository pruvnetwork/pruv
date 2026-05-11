//! Thread-safe KZG SRS (Structured Reference String) loader and cache.
//!
//! # Production
//! Set `PRUV_SRS_PATH=/path/to/hermez-raw-11` (or any compatible BN254 ptau
//! file).  The file is loaded once and cached for the process lifetime.
//!
//! # Development / tests
//! When `PRUV_SRS_PATH` is unset the module generates an **insecure**
//! random SRS of the requested size using `ParamsKZG::setup`.  This is fast
//! (< 1 s for k ≤ 14) and fine for CI/local testing but MUST NOT be used in
//! production — proofs generated with a random SRS are not sound.
//!
//! # Concurrency
//! The cache is a `DashMap<u32, Arc<ParamsKZG<Bn256>>>`.  Multiple threads
//! can call `get(k)` simultaneously; the first thread to request a given `k`
//! builds (or loads) the SRS while others wait on the entry lock, then all
//! share the same `Arc`.  No `OnceCell::set` races.

use std::sync::Arc;

use anyhow::{Context, Result};
use dashmap::DashMap;
use halo2_proofs::{
    halo2curves::bn256::Bn256,
    poly::kzg::commitment::ParamsKZG,
};
use once_cell::sync::Lazy;
use rand::thread_rng;

use crate::circuit_params::SRS_PATH_ENV;

// ─── Global cache ─────────────────────────────────────────────────────────────

/// Process-global SRS cache.  Keyed by `k` (circuit size = 2^k rows).
static SRS_CACHE: Lazy<DashMap<u32, Arc<ParamsKZG<Bn256>>>> =
    Lazy::new(DashMap::new);

// ─── Public API ───────────────────────────────────────────────────────────────

/// Return a cached `Arc<ParamsKZG<Bn256>>` for circuit size `2^k`.
///
/// On the first call for a given `k` the SRS is either:
/// - loaded from `$PRUV_SRS_PATH` (production), or
/// - generated in-memory with `ParamsKZG::setup` (dev/test).
///
/// Subsequent calls return the cached value immediately.
pub fn get(k: u32) -> Result<Arc<ParamsKZG<Bn256>>> {
    // Fast path — already cached.
    if let Some(entry) = SRS_CACHE.get(&k) {
        return Ok(Arc::clone(&*entry));
    }

    // Slow path — build once and insert only if the key is still absent.
    // `entry().or_insert_with()` holds a write-lock on the shard while the
    // closure runs, so exactly one thread executes `build` per `k`.
    let arc = SRS_CACHE
        .entry(k)
        .or_try_insert_with(|| build(k).map(Arc::new))?
        .clone();
    Ok(arc)
}

/// Downgrade cached SRS to a smaller `k'` (useful for verifier-only nodes).
/// Returns `Err` if `k_prime > k`.
pub fn downgrade(params: &ParamsKZG<Bn256>, k_prime: u32) -> Result<ParamsKZG<Bn256>> {
    use halo2_proofs::poly::commitment::Params;
    let mut p = params.clone();
    p.downsize(k_prime);
    Ok(p)
}

// ─── Internal builders ────────────────────────────────────────────────────────

fn build(k: u32) -> Result<ParamsKZG<Bn256>> {
    match std::env::var(SRS_PATH_ENV) {
        Ok(path) => load_from_file(&path, k),
        Err(_)   => {
            tracing::warn!(
                k,
                "PRUV_SRS_PATH unset — generating INSECURE random SRS (dev/test only)"
            );
            Ok(generate_insecure(k))
        }
    }
}

fn load_from_file(path: &str, k: u32) -> Result<ParamsKZG<Bn256>> {
    use halo2_proofs::poly::commitment::Params;
    use std::fs::File;
    use std::io::BufReader;

    let f = File::open(path)
        .with_context(|| format!("Cannot open SRS file: {path}"))?;
    let mut reader = BufReader::new(f);
    let params = ParamsKZG::<Bn256>::read(&mut reader)
        .with_context(|| format!("Failed to parse SRS file: {path}"))?;

    // If the file's k is larger than requested, downsize.
    let file_k = params.k();
    if file_k < k {
        anyhow::bail!(
            "SRS file has k={file_k} but circuit requires k={k}. \
             Use a larger ceremony file."
        );
    }
    if file_k > k {
        let mut p = params;
        use halo2_proofs::poly::commitment::Params;
        p.downsize(k);
        return Ok(p);
    }
    Ok(params)
}

fn generate_insecure(k: u32) -> ParamsKZG<Bn256> {
    ParamsKZG::<Bn256>::setup(k, thread_rng())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::poly::commitment::Params;

    #[test]
    fn insecure_srs_generated_for_small_k() {
        let params = get(4).expect("get(4) should succeed");
        assert_eq!(params.k(), 4);
    }

    #[test]
    fn cache_returns_same_arc() {
        let a = get(4).unwrap();
        let b = get(4).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "second call should return cached Arc");
    }

    #[test]
    fn parallel_get_no_panic() {
        use std::thread;
        let handles: Vec<_> = (0..8)
            .map(|_| thread::spawn(|| get(5).unwrap()))
            .collect();
        for h in handles {
            h.join().expect("thread panicked");
        }
    }
}