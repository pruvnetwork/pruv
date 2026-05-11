//! Parallel batch proof generation using Rayon.
//!
//! Proves multiple witnesses concurrently, returning results in input order.
//! Failures are collected per-item — a single bad witness does not abort the batch.

use anyhow::Result;
use rayon::prelude::*;

use crate::{
    governance_vote::{prove as prove_vote, VoteProof, VoteWitness},
    merkle::{prove as prove_merkle, MerkleProof, MerkleWitness},
};

// ─── Batch Merkle ─────────────────────────────────────────────────────────────

/// Prove a batch of Merkle witnesses in parallel.
/// Returns one `Result<MerkleProof>` per input, in order.
pub fn batch_merkle(witnesses: &[MerkleWitness]) -> Vec<Result<MerkleProof>> {
    witnesses
        .par_iter()
        .map(prove_merkle)
        .collect()
}

// ─── Batch governance vote ────────────────────────────────────────────────────

/// Prove a batch of governance vote witnesses in parallel.
/// Returns one `Result<VoteProof>` per input, in order.
pub fn batch_vote(witnesses: &[VoteWitness]) -> Vec<Result<VoteProof>> {
    witnesses
        .par_iter()
        .map(prove_vote)
        .collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::halo2curves::bn256::Fr;

    use crate::{
        circuit_params::fr_to_bytes,
        merkle::DEPTH,
        poseidon_hasher::{hash_two, leaf_commitment},
    };

    fn merkle_witness(seed: u64) -> MerkleWitness {
        let leaf_fr = leaf_commitment(Fr::from(seed), Fr::from(seed + 1));
        let mut siblings  = vec![];
        let mut path_bits = vec![];
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

    #[test]
    fn batch_merkle_two_witnesses() {
        let witnesses: Vec<_> = (1u64..=2).map(merkle_witness).collect();
        let results = batch_merkle(&witnesses);
        assert_eq!(results.len(), 2);
        for r in &results {
            assert!(r.is_ok(), "batch proof failed: {:?}", r);
        }
    }
}