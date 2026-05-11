//! Governance vote ZK circuit (Poseidon-128 / BN254 KZG).
//!
//! # Statement proven
//! "I know a secret `voter_secret` and a weight `weight` such that:
//!  1. `leaf = Poseidon(voter_pk_hash, weight)` is a leaf in the voter Merkle tree
//!     with root `merkle_root`.
//!  2. `nullifier = Poseidon(voter_secret, proposal_id)` has never been seen before
//!     (enforced off-chain by the contract using the public nullifier).
//!  3. `vote_value ∈ {0, 1}` (binary vote)."
//!
//! # Public inputs
//! 1. `merkle_root`  — voter registration tree root
//! 2. `nullifier`    — prevents double-voting
//! 3. `proposal_id`  — ties the proof to a specific proposal
//! 4. `vote_value`   — 0 = no, 1 = yes (Fr)

use anyhow::Result;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, ErrorFront, Expression,
        Instance, Selector,
    },
    poly::{
        kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::{ProverGWC, VerifierGWC},
            strategy::SingleStrategy,
        },
        Rotation,
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

use crate::{
    circuit_params::{fr_from_bytes, fr_to_bytes, GOVERNANCE_K},
    merkle::{MerkleCircuit, MerkleConfig, DEPTH},
    poseidon_hasher::{
        chip::{PoseidonChip, PoseidonConfig},
        hash_two, leaf_commitment, merkle_root_from_path, nullifier as compute_nullifier,
    },
    proving_key_cache::{get_or_build, CircuitId},
    srs,
};

// ─── Witness / proof types ────────────────────────────────────────────────────

/// All private and public inputs for a governance vote proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteWitness {
    // Private
    pub voter_secret:   [u8; 32],
    pub voter_pk_hash:  [u8; 32],
    pub weight:         [u8; 32],
    pub siblings:       Vec<[u8; 32]>,
    pub path_bits:      Vec<bool>,
    // Public
    pub merkle_root:    [u8; 32],
    pub proposal_id:    [u8; 32],
    pub vote_value:     u8,          // 0 or 1
}

/// A serialisable governance vote proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteProof {
    pub proof_bytes:  Vec<u8>,
    /// [merkle_root, nullifier, proposal_id, vote_value]
    pub public_inputs: Vec<[u8; 32]>,
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Generate a governance vote proof.
pub fn prove(w: &VoteWitness) -> Result<VoteProof> {
    assert_eq!(w.siblings.len(), DEPTH, "siblings must have length DEPTH");
    assert_eq!(w.path_bits.len(), DEPTH, "path_bits must have length DEPTH");
    assert!(w.vote_value <= 1, "vote_value must be 0 or 1");

    let params = srs::get(GOVERNANCE_K)?;

    // Decode field elements.
    let voter_secret  = decode(&w.voter_secret,  "voter_secret")?;
    let voter_pk_hash = decode(&w.voter_pk_hash, "voter_pk_hash")?;
    let weight        = decode(&w.weight,        "weight")?;
    let merkle_root   = decode(&w.merkle_root,   "merkle_root")?;
    let proposal_id   = decode(&w.proposal_id,   "proposal_id")?;
    let vote_val_fr   = Fr::from(w.vote_value as u64);

    let siblings: Result<Vec<Fr>> = w.siblings.iter()
        .map(|b| decode(b, "sibling"))
        .collect();
    let siblings = siblings?;

    // Derive leaf and nullifier.
    let leaf_fr      = leaf_commitment(voter_pk_hash, weight);
    let nullifier_fr = compute_nullifier(voter_secret, proposal_id);

    // Verify Merkle path.
    let computed_root = merkle_root_from_path(leaf_fr, &siblings, &w.path_bits);
    if computed_root != merkle_root {
        anyhow::bail!("Merkle root mismatch — witness is invalid");
    }

    let circuit = GovernanceCircuit {
        voter_secret:  Value::known(voter_secret),
        voter_pk_hash: Value::known(voter_pk_hash),
        weight:        Value::known(weight),
        siblings:      siblings.iter().map(|&s| Value::known(s)).collect(),
        path_bits:     w.path_bits.iter().map(|&b| Value::known(b)).collect(),
        proposal_id:   Value::known(proposal_id),
        vote_value:    Value::known(vote_val_fr),
    };

    let keys = get_or_build(CircuitId::GovernanceVote, &params, GovernanceCircuit::empty)?;
    // The constraint system has TWO instance columns:
    //   col 0 — governance public inputs (4 rows: root, nullifier, proposal_id, vote)
    //   col 1 — inner MerkleCircuit::configure() creates a second instance column
    //           that is never used by GovernanceCircuit::synthesize (0 rows)
    let instances: Vec<Vec<Vec<Fr>>> = vec![vec![
        vec![merkle_root, nullifier_fr, proposal_id, vote_val_fr],
        vec![],
    ]];
    let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<_>>::init(vec![]);

    halo2_proofs::plonk::create_proof::<
        KZGCommitmentScheme<Bn256>, ProverGWC<Bn256>, _, _, _, _,
    >(
        &params,
        &keys.pk,
        &[circuit],
        &instances,
        thread_rng(),
        &mut transcript,
    )
    .map_err(|e| anyhow::anyhow!("prove: {e:?}"))?;

    Ok(VoteProof {
        proof_bytes: transcript.finalize(),
        public_inputs: vec![
            w.merkle_root,
            fr_to_bytes(nullifier_fr),
            w.proposal_id,
            fr_to_bytes(vote_val_fr),
        ],
    })
}

/// Verify a governance vote proof.
pub fn verify(proof: &VoteProof) -> Result<bool> {
    let params = srs::get(GOVERNANCE_K)?;
    let keys = get_or_build(CircuitId::GovernanceVote, &params, GovernanceCircuit::empty)?;

    let merkle_root  = decode(&proof.public_inputs[0], "merkle_root")?;
    let nullifier_fr = decode(&proof.public_inputs[1], "nullifier")?;
    let proposal_id  = decode(&proof.public_inputs[2], "proposal_id")?;
    let vote_val_fr  = decode(&proof.public_inputs[3], "vote_value")?;
    use halo2_proofs::poly::kzg::commitment::ParamsVerifierKZG;
    let verifier_params: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
    let mut transcript =
        Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof.proof_bytes[..]);

    let inst: Vec<Vec<Vec<Fr>>> = vec![vec![
        vec![merkle_root, nullifier_fr, proposal_id, vote_val_fr],
        vec![],
    ]];
    let ok = halo2_proofs::plonk::verify_proof_multi::<
        KZGCommitmentScheme<Bn256>, VerifierGWC<Bn256>, _, _,
        SingleStrategy<Bn256>,
    >(&verifier_params, &keys.vk, &inst, &mut transcript);

    Ok(ok)
}

// ─── Circuit ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct GovernanceConfig {
    // Advice columns
    voter_secret_col:  Column<Advice>,
    voter_pk_hash_col: Column<Advice>,
    weight_col:        Column<Advice>,
    vote_col:          Column<Advice>,
    nullifier_col:     Column<Advice>,
    // Selectors
    q_bool_vote:       Selector,
    // Instance column (public inputs)
    instance:          Column<Instance>,
    // Sub-chips
    poseidon:          PoseidonConfig,
    merkle:            MerkleConfig,
}

#[derive(Clone, Debug, Default)]
pub struct GovernanceCircuit {
    // Private witnesses
    pub voter_secret:  Value<Fr>,
    pub voter_pk_hash: Value<Fr>,
    pub weight:        Value<Fr>,
    pub siblings:      Vec<Value<Fr>>,
    pub path_bits:     Vec<Value<bool>>,
    // Public (also constrained via instance column)
    pub proposal_id:   Value<Fr>,
    pub vote_value:    Value<Fr>,
}

impl GovernanceCircuit {
    pub fn empty() -> Self {
        Self {
            voter_secret:  Value::unknown(),
            voter_pk_hash: Value::unknown(),
            weight:        Value::unknown(),
            siblings:      vec![Value::unknown(); DEPTH],
            path_bits:     vec![Value::unknown(); DEPTH],
            proposal_id:   Value::unknown(),
            vote_value:    Value::unknown(),
        }
    }
}

impl Circuit<Fr> for GovernanceCircuit {
    type Config = GovernanceConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::empty() }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> GovernanceConfig {
        let voter_secret_col  = meta.advice_column();
        let voter_pk_hash_col = meta.advice_column();
        let weight_col        = meta.advice_column();
        let vote_col          = meta.advice_column();
        let nullifier_col     = meta.advice_column();
        let instance          = meta.instance_column();
        let q_bool_vote       = meta.selector();

        for c in [voter_secret_col, voter_pk_hash_col, weight_col,
                  vote_col, nullifier_col] {
            meta.enable_equality(c);
        }
        meta.enable_equality(instance);

        // vote_value ∈ {0, 1}
        meta.create_gate("boolean_vote", |meta| {
            let q    = meta.query_selector(q_bool_vote);
            let vote = meta.query_advice(vote_col, Rotation::cur());
            vec![q * vote.clone() * (Expression::Constant(Fr::one()) - vote)]
        });

        let poseidon = PoseidonChip::configure(meta);
        let merkle   = MerkleCircuit::configure(meta);

        GovernanceConfig {
            voter_secret_col, voter_pk_hash_col, weight_col,
            vote_col, nullifier_col,
            q_bool_vote, instance, poseidon, merkle,
        }
    }

    fn synthesize(
        &self,
        config: GovernanceConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), ErrorFront> {
        // Pre-compute native witness hash values.
        let leaf_v      = self.voter_pk_hash.zip(self.weight)
            .map(|(a, b)| hash_two(a, b));
        let nullifier_v = self.voter_secret.zip(self.proposal_id)
            .map(|(a, b)| hash_two(a, b));

        // ── 1. Witness region: private inputs + leaf/nullifier hashes ──────────
        let (vote_cell, proposal_id_cell, leaf_cell, nullifier_cell) = layouter.assign_region(
            || "witnesses_hashes",
            |mut region| {
                config.q_bool_vote.enable(&mut region, 0)?;

                // Private witnesses at row 0
                region.assign_advice(|| "voter_secret",  config.voter_secret_col,  0, || self.voter_secret)?;
                region.assign_advice(|| "voter_pk_hash", config.voter_pk_hash_col, 0, || self.voter_pk_hash)?;
                region.assign_advice(|| "weight",        config.weight_col,        0, || self.weight)?;
                let vote_cell = region.assign_advice(|| "vote", config.vote_col,      0, || self.vote_value)?;
                let pid_cell  = region.assign_advice(|| "pid",  config.nullifier_col, 0, || self.proposal_id)?;

                // Leaf = Poseidon(voter_pk_hash, weight) at row 0
                region.assign_advice(|| "leaf_a",   config.poseidon.in_a, 0, || self.voter_pk_hash)?;
                region.assign_advice(|| "leaf_b",   config.poseidon.in_b, 0, || self.weight)?;
                let leaf_cell = region.assign_advice(|| "leaf", config.poseidon.out, 0, || leaf_v)?;

                // Nullifier = Poseidon(voter_secret, proposal_id) at row 1
                region.assign_advice(|| "null_a",    config.poseidon.in_a, 1, || self.voter_secret)?;
                region.assign_advice(|| "null_b",    config.poseidon.in_b, 1, || self.proposal_id)?;
                let null_cell = region.assign_advice(|| "null", config.poseidon.out, 1, || nullifier_v)?;

                Ok((vote_cell, pid_cell, leaf_cell, null_cell))
            },
        )?;

        // ── 2. Constrain public outputs ────────────────────────────────────────
        layouter.constrain_instance(nullifier_cell.cell(),  config.instance, 1)?;
        layouter.constrain_instance(proposal_id_cell.cell(), config.instance, 2)?;
        layouter.constrain_instance(vote_cell.cell(),        config.instance, 3)?;

        // ── 3. Merkle inclusion proof (inline, depth = DEPTH) ─────────────────
        let mut current = leaf_cell;
        for i in 0..DEPTH {
            let sib_val = self.siblings.get(i).copied().unwrap_or(Value::unknown());
            let bit_val = self.path_bits.get(i).copied().unwrap_or(Value::unknown());
            let bit_fr  = bit_val.map(|b| if b { Fr::one() } else { Fr::zero() });
            let cur_v   = current.value().copied();
            let left_v  = cur_v.zip(sib_val).zip(bit_val).map(|((c, s), b)| if b { s } else { c });
            let right_v = cur_v.zip(sib_val).zip(bit_val).map(|((c, s), b)| if b { c } else { s });
            let hash_v  = left_v.zip(right_v).map(|(l, r)| hash_two(l, r));

            current = layouter.assign_region(
                || format!("merkle_{i}"),
                |mut region| {
                    config.merkle.q_bool.enable(&mut region, 0)?;
                    config.merkle.q_select.enable(&mut region, 0)?;
                    config.merkle.q_poseidon.enable(&mut region, 0)?;

                    region.assign_advice(|| "sib",   config.merkle.sibling_col,     0, || sib_val)?;
                    region.assign_advice(|| "bit",   config.merkle.bit_col,         0, || bit_fr)?;
                    current.copy_advice(|| "cur",    &mut region, config.merkle.current_col, 0)?;
                    region.assign_advice(|| "left",  config.merkle.left_col,        0, || left_v)?;
                    region.assign_advice(|| "right", config.merkle.right_col,       0, || right_v)?;
                    region.assign_advice(|| "p_a",   config.merkle.poseidon.in_a,   0, || left_v)?;
                    region.assign_advice(|| "p_b",   config.merkle.poseidon.in_b,   0, || right_v)?;
                    region.assign_advice(|| "p_out", config.merkle.poseidon.out,    0, || hash_v)
                },
            )?;
        }

        // instance[0] = merkle_root
        layouter.constrain_instance(current.cell(), config.instance, 0)?;

        Ok(())
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn decode(b: &[u8; 32], label: &str) -> Result<Fr> {
    fr_from_bytes(b).ok_or_else(|| anyhow::anyhow!("invalid bytes for {label}"))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon_hasher::{hash_two, leaf_commitment};
    use ff::PrimeField;

    fn make_witness(vote: u8) -> VoteWitness {
        let voter_secret_fr  = Fr::from(0xdeadbeefu64);
        let voter_pk_hash_fr = Fr::from(0xcafebabeu64);
        let weight_fr        = Fr::from(100u64);
        let proposal_id_fr   = Fr::from(42u64);

        let leaf_fr = leaf_commitment(voter_pk_hash_fr, weight_fr);
        let mut siblings = vec![];
        let mut path_bits = vec![];
        let mut current = leaf_fr;
        for i in 0..DEPTH {
            let sib = Fr::from((i as u64 + 200) * 3);
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
            vote_value:    vote,
        }
    }

    #[test]
    fn prove_verify_roundtrip() {
        let w = make_witness(1);
        let proof = prove(&w).expect("prove failed");
        assert!(verify(&proof).expect("verify failed"), "valid proof must verify");
    }

    #[test]
    fn wrong_root_rejected() {
        let mut w = make_witness(1);
        w.merkle_root[0] ^= 0xff;
        assert!(prove(&w).is_err(), "corrupted root must fail at prove time");
    }

    #[test]
    fn invalid_vote_rejected() {
        let w = VoteWitness {
            vote_value: 2, // invalid
            ..make_witness(0)
        };
        // assert panics (vote_value > 1)
        let result = std::panic::catch_unwind(|| prove(&w));
        assert!(result.is_err(), "vote_value=2 should panic");
    }
}