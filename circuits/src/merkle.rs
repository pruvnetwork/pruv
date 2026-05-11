//! Merkle inclusion proof circuit (depth = 20, Poseidon-128 / BN254).
//!
//! Public inputs (instance column): [root, leaf]

use anyhow::Result;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Fr, G1Affine},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, ErrorFront, Expression, Instance, Selector,
    },
    poly::Rotation,
};
use serde::{Deserialize, Serialize};

use crate::{
    circuit_params::{fr_from_bytes, MERKLE_K},
    poseidon_hasher::{
        chip::{PoseidonChip, PoseidonConfig},
        hash_two, merkle_root_from_path,
    },
    proving_key_cache::{get_or_build, CircuitId},
    srs,
};

pub const DEPTH: usize = 20;

// ─── Public types ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleWitness {
    pub leaf:      [u8; 32],
    pub siblings:  Vec<[u8; 32]>,
    pub path_bits: Vec<bool>,
    pub root:      [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub proof_bytes:   Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
}

// ─── Public API ───────────────────────────────────────────────────────────────

pub fn prove(witness: &MerkleWitness) -> Result<MerkleProof> {
    use halo2_proofs::{
        halo2curves::bn256::Bn256,
        plonk::create_proof,
        poly::kzg::{commitment::KZGCommitmentScheme, multiopen::ProverGWC},
        transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
    };
    use rand::rngs::OsRng;

    assert_eq!(witness.siblings.len(),  DEPTH, "siblings length mismatch");
    assert_eq!(witness.path_bits.len(), DEPTH, "path_bits length mismatch");

    let params = srs::get(MERKLE_K)?;

    // Decode all field elements up front so we can validate the path.
    let leaf_decoded = fr_from_bytes(&witness.leaf)
        .ok_or_else(|| anyhow::anyhow!("invalid leaf bytes"))?;
    let root_decoded = fr_from_bytes(&witness.root)
        .ok_or_else(|| anyhow::anyhow!("invalid root bytes"))?;
    let siblings_decoded: Result<Vec<Fr>> = witness.siblings.iter()
        .map(|b| fr_from_bytes(b).ok_or_else(|| anyhow::anyhow!("invalid sibling")))
        .collect();
    let siblings_decoded = siblings_decoded?;

    // Early validation: reject witnesses where the path doesn't open to the
    // declared root.  create_proof does NOT check this — it would silently
    // produce an unverifiable proof.
    let computed_root = merkle_root_from_path(leaf_decoded, &siblings_decoded, &witness.path_bits);
    if computed_root != root_decoded {
        anyhow::bail!("Merkle root mismatch — witness is invalid");
    }

    let circuit = MerkleCircuit {
        leaf:      Value::known(leaf_decoded),
        siblings:  siblings_decoded.iter().map(|&s| Value::known(s)).collect(),
        path_bits: witness.path_bits.iter().map(|&b| Value::known(b)).collect(),
        root:      Value::known(root_decoded),
    };

    let keys = get_or_build(CircuitId::Merkle, &*params, MerkleCircuit::empty)?;
    // instances: &[Vec<Vec<Scalar>>]  — one circuit, one column, two values
    let instances: &[Vec<Vec<Fr>>] = &[vec![vec![root_decoded, leaf_decoded]]];
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, _>(
        &*params,
        &*keys.pk,
        &[circuit],
        instances,
        OsRng,
        &mut transcript,
    )
    .map_err(|e| anyhow::anyhow!("prove: {e:?}"))?;

    Ok(MerkleProof {
        proof_bytes:   transcript.finalize(),
        public_inputs: vec![witness.root, witness.leaf],
    })
}

pub fn verify(proof: &MerkleProof) -> Result<bool> {
    use halo2_proofs::{
        halo2curves::bn256::Bn256,
        plonk::verify_proof_multi,
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsVerifierKZG},
            multiopen::VerifierGWC,
            strategy::SingleStrategy,
        },
        transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer},
    };

    let params = srs::get(MERKLE_K)?;
    let keys   = get_or_build(CircuitId::Merkle, &*params, MerkleCircuit::empty)?;

    let root = fr_from_bytes(&proof.public_inputs[0])
        .ok_or_else(|| anyhow::anyhow!("invalid root"))?;
    let leaf = fr_from_bytes(&proof.public_inputs[1])
        .ok_or_else(|| anyhow::anyhow!("invalid leaf"))?;

    let verifier_params: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
    let mut transcript =
        Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof.proof_bytes[..]);

    let instances: &[Vec<Vec<Fr>>] = &[vec![vec![root, leaf]]];
    let ok = verify_proof_multi::<
        KZGCommitmentScheme<Bn256>,
        VerifierGWC<_>,
        _,
        _,
        SingleStrategy<_>,
    >(
        &verifier_params,
        &*keys.vk,
        instances,
        &mut transcript,
    );

    Ok(ok)
}

// ─── Circuit ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct MerkleConfig {
    pub current_col: Column<Advice>,
    pub sibling_col: Column<Advice>,
    pub bit_col:     Column<Advice>,
    pub left_col:    Column<Advice>,
    pub right_col:   Column<Advice>,
    pub q_bool:      Selector,
    pub q_select:    Selector,
    pub q_poseidon:  Selector,
    pub instance:    Column<Instance>,
    pub poseidon:    PoseidonConfig,
}

#[derive(Clone, Debug, Default)]
pub struct MerkleCircuit {
    pub leaf:      Value<Fr>,
    pub siblings:  Vec<Value<Fr>>,
    pub path_bits: Vec<Value<bool>>,
    pub root:      Value<Fr>,
}

impl MerkleCircuit {
    pub fn empty() -> Self {
        Self {
            leaf:      Value::unknown(),
            siblings:  vec![Value::unknown(); DEPTH],
            path_bits: vec![Value::unknown(); DEPTH],
            root:      Value::unknown(),
        }
    }
}

impl Circuit<Fr> for MerkleCircuit {
    type Config       = MerkleConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::empty() }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> MerkleConfig {
        let current_col = meta.advice_column();
        let sibling_col = meta.advice_column();
        let bit_col     = meta.advice_column();
        let left_col    = meta.advice_column();
        let right_col   = meta.advice_column();
        let instance    = meta.instance_column();
        let q_bool      = meta.selector();
        let q_select    = meta.selector();
        let q_poseidon  = meta.selector();

        for c in [current_col, sibling_col, bit_col, left_col, right_col] {
            meta.enable_equality(c);
        }
        meta.enable_equality(instance);

        // bit * (1 - bit) == 0
        meta.create_gate("boolean_bit", |meta| {
            let q   = meta.query_selector(q_bool);
            let bit = meta.query_advice(bit_col, Rotation::cur());
            let one = Expression::Constant(Fr::one());
            vec![q * bit.clone() * (one - bit)]
        });

        // left = cur*(1-bit) + sib*bit  ;  right = sib*(1-bit) + cur*bit
        meta.create_gate("select_lr", |meta| {
            let q     = meta.query_selector(q_select);
            let bit   = meta.query_advice(bit_col,     Rotation::cur());
            let cur   = meta.query_advice(current_col, Rotation::cur());
            let sib   = meta.query_advice(sibling_col, Rotation::cur());
            let left  = meta.query_advice(left_col,    Rotation::cur());
            let right = meta.query_advice(right_col,   Rotation::cur());
            let one_m = Expression::Constant(Fr::one()) - bit.clone();
            vec![
                q.clone() * (left  - cur.clone() * one_m.clone() - sib.clone() * bit.clone()),
                q          * (right - sib * one_m - cur * bit),
            ]
        });

        // Poseidon input linkage
        let poseidon = PoseidonChip::configure(meta);
        meta.create_gate("poseidon_input_link", |meta| {
            let q  = meta.query_selector(q_poseidon);
            let l  = meta.query_advice(left_col,       Rotation::cur());
            let r  = meta.query_advice(right_col,      Rotation::cur());
            let pa = meta.query_advice(poseidon.in_a,  Rotation::cur());
            let pb = meta.query_advice(poseidon.in_b,  Rotation::cur());
            vec![q.clone() * (l - pa), q * (r - pb)]
        });

        MerkleConfig {
            current_col, sibling_col, bit_col, left_col, right_col,
            q_bool, q_select, q_poseidon, instance, poseidon,
        }
    }

    fn synthesize(
        &self,
        config: MerkleConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), ErrorFront> {
        let mut current: AssignedCell<Fr, Fr> = layouter.assign_region(
            || "init_leaf",
            |mut region| {
                region.assign_advice(|| "leaf", config.current_col, 0, || self.leaf)
            },
        )?;

        for i in 0..DEPTH {
            let sib_val = self.siblings.get(i).copied().unwrap_or(Value::unknown());
            let bit_val = self.path_bits.get(i).copied().unwrap_or(Value::unknown());

            current = layouter.assign_region(
                || format!("level_{i}"),
                |mut region| {
                    config.q_bool.enable(&mut region, 0)?;
                    config.q_select.enable(&mut region, 0)?;
                    config.q_poseidon.enable(&mut region, 0)?;

                    let bit_fr = bit_val.map(|b| if b { Fr::one() } else { Fr::zero() });

                    region.assign_advice(|| "sib", config.sibling_col, 0, || sib_val)?;
                    region.assign_advice(|| "bit", config.bit_col,     0, || bit_fr)?;
                    current.copy_advice(|| "cur", &mut region, config.current_col, 0)?;

                    let cur_v  = current.value().copied();
                    let left_v = cur_v.zip(sib_val).zip(bit_val)
                        .map(|((c, s), b)| if b { s } else { c });
                    let right_v = cur_v.zip(sib_val).zip(bit_val)
                        .map(|((c, s), b)| if b { c } else { s });

                    region.assign_advice(|| "left",  config.left_col,  0, || left_v)?;
                    region.assign_advice(|| "right", config.right_col, 0, || right_v)?;

                    let hash_v = left_v.zip(right_v).map(|(l, r)| hash_two(l, r));
                    region.assign_advice(|| "p_a", config.poseidon.in_a, 0, || left_v)?;
                    region.assign_advice(|| "p_b", config.poseidon.in_b, 0, || right_v)?;
                    region.assign_advice(|| "out", config.poseidon.out,  0, || hash_v)
                },
            )?;
        }

        layouter.constrain_instance(current.cell(), config.instance, 0)?;
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuit_params::fr_to_bytes, poseidon_hasher::leaf_commitment};

    fn make_witness(depth: usize) -> MerkleWitness {
        let leaf_fr = leaf_commitment(Fr::from(123u64), Fr::from(10u64));
        let mut siblings  = vec![];
        let mut path_bits = vec![];
        let mut current   = leaf_fr;
        for i in 0..depth {
            let sib      = Fr::from((i as u64 + 100) * 7);
            let is_right = i % 2 == 0;
            path_bits.push(is_right);
            siblings.push(sib);
            current = if is_right {
                hash_two(sib, current)
            } else {
                hash_two(current, sib)
            };
        }
        MerkleWitness {
            leaf:      fr_to_bytes(leaf_fr),
            siblings:  siblings.iter().map(|&s| fr_to_bytes(s)).collect(),
            path_bits,
            root:      fr_to_bytes(current),
        }
    }

    #[test]
    fn prove_verify_depth20() {
        let w     = make_witness(DEPTH);
        let proof = prove(&w).expect("prove failed");
        assert!(verify(&proof).expect("verify failed"), "proof invalid");
    }

    #[test]
    fn verify_wrong_root_fails() {
        let mut w = make_witness(DEPTH);
        w.root[0] ^= 0xff;
        assert!(prove(&w).is_err(), "corrupt root must fail");
    }
}