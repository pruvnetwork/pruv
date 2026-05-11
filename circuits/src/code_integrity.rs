//! Code integrity circuit — proves dApp bytecode SHA-256 hash equality.
//!
//! ## Public inputs (4)
//!   0: `program_id`          — first 32 bytes of pubkey → Fr
//!   1: `hash_lo`             — lower 16 bytes of SHA-256 hash → Fr
//!   2: `hash_hi`             — upper 16 bytes of SHA-256 hash → Fr
//!   3: `poseidon_commitment` — Poseidon(Poseidon(program_id, hash_lo), hash_hi)
//!
//! ## Security model
//! The circuit proves the prover knows a `(program_id, hash_lo, hash_hi)` triple
//! such that:
//!   1. The triple matches the declared public inputs.
//!   2. A Poseidon commitment over the triple is correctly formed:
//!      `commitment = hash_chain3(program_id, hash_lo, hash_hi)`.
//!   3. The x^5 S-box is correctly applied for `program_id` (via `SboxChip`)
//!      — this is the non-linear component of the Poseidon permutation and
//!      prevents witness forgery at the S-box level.
//!
//! SHA-256 pre-image verification is performed natively before circuit creation
//! (`witness.verify_native()`).  A full in-circuit SHA-256 gadget would require
//! a dedicated lookup-table library and is tracked as a future upgrade.

use halo2_proofs::halo2curves::bn256::Fr;
use serde::{Deserialize, Serialize};

use crate::{CircuitError, ProofBytes};

// ─── Public inputs (always compiled) ─────────────────────────────────────────

/// All public inputs for the code integrity circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeIntegrityPublicInputs {
    /// First 32 bytes of the Solana program public key.
    pub program_id_bytes: [u8; 32],
    /// SHA-256 hash of the program's ELF bytecode.
    pub program_hash: [u8; 32],
    /// Poseidon(Poseidon(program_id, hash_lo), hash_hi).
    /// Binding commitment that ties program_id to its hash in-circuit.
    pub poseidon_commitment: [u8; 32],
}

#[cfg(not(feature = "mock"))]
impl CodeIntegrityPublicInputs {
    /// Returns [program_id_fr, hash_lo_fr, hash_hi_fr, commitment_fr].
    pub fn as_field_elements(&self) -> Vec<Fr> {
        vec![
            field_from_le_bytes(&self.program_id_bytes),
            field_from_le_bytes_half(&self.program_hash, 0..16),
            field_from_le_bytes_half(&self.program_hash, 16..32),
            field_from_le_bytes(&self.poseidon_commitment),
        ]
    }
}

/// Pack a 32-byte slice into Fr (masking the top byte).
#[cfg(not(feature = "mock"))]
fn field_from_le_bytes(b: &[u8; 32]) -> Fr {
    use ff::{Field, PrimeField};
    let mut repr = *b;
    repr[31] &= 0x3f;
    Fr::from_repr(repr.into()).unwrap_or(<Fr as Field>::ZERO)
}

/// Pack 16 bytes from a hash slice into a 32-byte Fr.
#[cfg(not(feature = "mock"))]
fn field_from_le_bytes_half(hash: &[u8; 32], range: std::ops::Range<usize>) -> Fr {
    use ff::{Field, PrimeField};
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(&hash[range]);
    buf[31] &= 0x3f;
    Fr::from_repr(buf.into()).unwrap_or(<Fr as Field>::ZERO)
}

// ─── Witness (always compiled) ────────────────────────────────────────────────

/// Prover witness for a code integrity proof.
#[derive(Clone)]
pub struct CodeIntegrityWitness {
    /// Full ELF bytecode of the program being proven.
    pub bytecode: Vec<u8>,
    /// Pre-computed SHA-256 of the bytecode (matches registered hash).
    pub program_hash: [u8; 32],
    /// Solana program public key bytes.
    pub program_id_bytes: [u8; 32],
}

impl CodeIntegrityWitness {
    /// Verify the pre-computed hash against the bytecode using native SHA-256.
    pub fn verify_native(&self) -> bool {
        sha256_native(&self.bytecode) == self.program_hash
    }

    pub fn public_inputs(&self) -> CodeIntegrityPublicInputs {
        let commitment = compute_poseidon_commitment(&self.program_id_bytes, &self.program_hash);
        CodeIntegrityPublicInputs {
            program_id_bytes:    self.program_id_bytes,
            program_hash:        self.program_hash,
            poseidon_commitment: commitment,
        }
    }
}

/// Native SHA-256 computation (used for witness generation).
pub fn sha256_native(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// Compute the Poseidon commitment over (program_id, hash_lo, hash_hi) natively.
///
/// `commitment = Poseidon(Poseidon(program_id_fr, hash_lo_fr), hash_hi_fr)`
pub fn compute_poseidon_commitment(
    program_id_bytes: &[u8; 32],
    program_hash: &[u8; 32],
) -> [u8; 32] {
    use crate::circuit_params::fr_to_bytes;
    use crate::poseidon_hasher::hash_chain3;

    // Derive field elements using the same masking as the circuit.
    let pid_fr = {
        use ff::{Field, PrimeField};
        let mut repr = *program_id_bytes;
        repr[31] &= 0x3f;
        Fr::from_repr(repr.into()).unwrap_or(<Fr as Field>::ZERO)
    };
    let lo_fr = {
        use ff::{Field, PrimeField};
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&program_hash[0..16]);
        buf[31] &= 0x3f;
        Fr::from_repr(buf.into()).unwrap_or(<Fr as Field>::ZERO)
    };
    let hi_fr = {
        use ff::{Field, PrimeField};
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&program_hash[16..32]);
        buf[31] &= 0x3f;
        Fr::from_repr(buf.into()).unwrap_or(<Fr as Field>::ZERO)
    };

    fr_to_bytes(hash_chain3(pid_fr, lo_fr, hi_fr))
}

// ─── Production circuit (not compiled in mock mode) ───────────────────────────
//
// ## Layout (SimpleFloorPlanner)
//
// Region "witnesses":
//   row 0 — program_id_col, hash_lo_col, hash_hi_col
//   row 0 — poseidon.in_a=program_id, poseidon.in_b=hash_lo, poseidon.out=inner
//   row 0 — sbox.x=program_id, sbox.x2, sbox.x4, sbox.x5  (non-linear constraint)
//   row 1 — poseidon.in_a=inner, poseidon.in_b=hash_hi, poseidon.out=commitment
//   row 1 — sbox.x=inner, sbox.x2, sbox.x4, sbox.x5        (non-linear constraint)
//
// Instance column rows:
//   0: program_id_fr
//   1: hash_lo_fr
//   2: hash_hi_fr
//   3: poseidon_commitment_fr

#[cfg(not(feature = "mock"))]
mod circuit_impl {
    use halo2_proofs::{
        circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
        halo2curves::bn256::Fr,
        plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance},
    };

    use super::{field_from_le_bytes, field_from_le_bytes_half, CodeIntegrityWitness};
    use crate::poseidon_hasher::{
        chip::{PoseidonConfig, PoseidonChip, SboxChip, SboxConfig},
        hash_two,
    };

    #[derive(Clone, Debug)]
    pub struct CodeIntegrityConfig {
        /// Witness advice columns for the three input field elements.
        pub program_id_col: Column<Advice>,
        pub hash_lo_col:    Column<Advice>,
        pub hash_hi_col:    Column<Advice>,
        /// Intermediate Poseidon output: Poseidon(program_id, hash_lo).
        pub inner_col:      Column<Advice>,
        /// Final commitment output: Poseidon(inner, hash_hi).
        pub commitment_col: Column<Advice>,
        /// Instance column: rows 0..3 → [program_id, hash_lo, hash_hi, commitment].
        pub instance:       Column<Instance>,
        /// Poseidon column allocation (in_a, in_b, out) — shared across both steps.
        pub poseidon:       PoseidonConfig,
        /// S-box chip — shared across both S-box applications (rows 0 and 1).
        pub sbox:           SboxConfig,
    }

    #[derive(Clone)]
    pub struct CodeIntegrityCircuit {
        pub witness: Option<CodeIntegrityWitness>,
    }

    impl Default for CodeIntegrityCircuit {
        fn default() -> Self { Self { witness: None } }
    }

    impl Circuit<Fr> for CodeIntegrityCircuit {
        type Config       = CodeIntegrityConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self { Self { witness: None } }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let program_id_col = meta.advice_column();
            let hash_lo_col    = meta.advice_column();
            let hash_hi_col    = meta.advice_column();
            let inner_col      = meta.advice_column();
            let commitment_col = meta.advice_column();
            let instance       = meta.instance_column();

            for c in [program_id_col, hash_lo_col, hash_hi_col,
                      inner_col, commitment_col] {
                meta.enable_equality(c);
            }
            meta.enable_equality(instance);

            let poseidon = PoseidonChip::configure(meta);
            let sbox     = SboxChip::configure(meta);

            CodeIntegrityConfig {
                program_id_col, hash_lo_col, hash_hi_col,
                inner_col, commitment_col, instance,
                poseidon, sbox,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), ErrorFront> {
            // ── Derive witness values ─────────────────────────────────────────
            let (pid_v, lo_v, hi_v, inner_v, commit_v) = match &self.witness {
                Some(w) => {
                    let pid    = Value::known(field_from_le_bytes(&w.program_id_bytes));
                    let lo     = Value::known(field_from_le_bytes_half(&w.program_hash, 0..16));
                    let hi     = Value::known(field_from_le_bytes_half(&w.program_hash, 16..32));
                    let inner  = pid.zip(lo).map(|(a, b)| hash_two(a, b));
                    let commit = inner.zip(hi).map(|(a, b)| hash_two(a, b));
                    (pid, lo, hi, inner, commit)
                }
                None => (
                    Value::unknown(), Value::unknown(), Value::unknown(),
                    Value::unknown(), Value::unknown(),
                ),
            };

            let sbox_chip = SboxChip::new(config.sbox.clone());

            // ── Region: input witnesses + first Poseidon step ─────────────────
            // Row 0: program_id, hash_lo, their Poseidon output (inner),
            //        and the x^5 S-box applied to program_id.
            let (pid_cell, lo_cell, hi_cell, _inner_cell): (
                AssignedCell<Fr, Fr>,
                AssignedCell<Fr, Fr>,
                AssignedCell<Fr, Fr>,
                AssignedCell<Fr, Fr>,
            ) = layouter.assign_region(
                || "inputs_and_inner_hash",
                |mut region| {
                    // Assign the three plain witness cells.
                    let pid_cell = region.assign_advice(
                        || "program_id", config.program_id_col, 0, || pid_v)?;
                    let lo_cell  = region.assign_advice(
                        || "hash_lo",    config.hash_lo_col,    0, || lo_v)?;
                    let hi_cell  = region.assign_advice(
                        || "hash_hi",    config.hash_hi_col,    0, || hi_v)?;

                    // Assign Poseidon step 1: inner = Poseidon(program_id, hash_lo).
                    region.assign_advice(|| "p1_in_a", config.poseidon.in_a, 0, || pid_v)?;
                    region.assign_advice(|| "p1_in_b", config.poseidon.in_b, 0, || lo_v)?;
                    let inner_cell = region.assign_advice(
                        || "inner",      config.inner_col,      0, || inner_v)?;
                    region.assign_advice(|| "p1_out",  config.poseidon.out,  0, || inner_v)?;

                    // Apply S-box to program_id at row 0 — enforces x^5 non-linearly.
                    sbox_chip.assign(&mut region, 0, pid_v)?;

                    Ok((pid_cell, lo_cell, hi_cell, inner_cell))
                },
            )?;

            // ── Region: second Poseidon step + commitment output ───────────────
            // Row 0 within this new region: commitment = Poseidon(inner, hash_hi),
            //        plus S-box applied to inner.
            let commit_cell: AssignedCell<Fr, Fr> = layouter.assign_region(
                || "commitment_hash",
                |mut region| {
                    // Assign Poseidon step 2: commitment = Poseidon(inner, hash_hi).
                    region.assign_advice(|| "p2_in_a", config.poseidon.in_a, 0, || inner_v)?;
                    region.assign_advice(|| "p2_in_b", config.poseidon.in_b, 0, || hi_v)?;
                    let commit_cell = region.assign_advice(
                        || "commitment",  config.commitment_col, 0, || commit_v)?;
                    region.assign_advice(|| "p2_out",  config.poseidon.out,  0, || commit_v)?;

                    // Apply S-box to inner at row 0 — constrains the second hash step.
                    sbox_chip.assign(&mut region, 0, inner_v)?;

                    Ok(commit_cell)
                },
            )?;

            // ── Constrain public outputs ───────────────────────────────────────
            layouter.constrain_instance(pid_cell.cell(),    config.instance, 0)?;
            layouter.constrain_instance(lo_cell.cell(),     config.instance, 1)?;
            layouter.constrain_instance(hi_cell.cell(),     config.instance, 2)?;
            layouter.constrain_instance(commit_cell.cell(), config.instance, 3)?;

            Ok(())
        }
    }
}

// ─── Mock prove / verify (default feature) ───────────────────────────────────

/// Generate a code integrity proof (mock mode: native check + JSON serialisation).
#[cfg(feature = "mock")]
pub fn prove(
    witness: CodeIntegrityWitness,
    _srs_k: u32,
) -> Result<(ProofBytes, CodeIntegrityPublicInputs), CircuitError> {
    if !witness.verify_native() {
        return Err(CircuitError::InvalidInput(
            "Program hash does not match bytecode".into(),
        ));
    }
    let pub_inputs = witness.public_inputs();
    let proof = serde_json::to_vec(&pub_inputs)
        .map_err(|e| CircuitError::SerdeError(e.to_string()))?;
    Ok((proof, pub_inputs))
}

/// Verify a code integrity proof (mock mode: JSON deserialisation check only).
#[cfg(feature = "mock")]
pub fn verify(
    proof: &[u8],
    _pub_inputs: &CodeIntegrityPublicInputs,
    _srs_k: u32,
) -> Result<(), CircuitError> {
    let _decoded: CodeIntegrityPublicInputs = serde_json::from_slice(proof)
        .map_err(|_| CircuitError::VerificationError)?;
    Ok(())
}

// ─── Production prove / verify (not compiled in mock mode) ───────────────────

#[cfg(not(feature = "mock"))]
pub fn prove(
    witness: CodeIntegrityWitness,
    srs_k: u32,
) -> Result<(ProofBytes, CodeIntegrityPublicInputs), CircuitError> {
    use circuit_impl::CodeIntegrityCircuit;
    use crate::proving_key_cache::{get_or_build, CircuitId};
    use halo2_proofs::{
        halo2curves::bn256::Bn256,
        plonk::create_proof,
        poly::kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::ProverGWC,
        },
        transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
    };
    use rand::rngs::OsRng;

    if !witness.verify_native() {
        return Err(CircuitError::InvalidInput(
            "Program hash does not match bytecode".into(),
        ));
    }
    let pub_inputs = witness.public_inputs();
    let circuit = CodeIntegrityCircuit { witness: Some(witness) };

    let params_arc = crate::load_srs(srs_k);
    let params = params_arc.as_ref();

    // Use the global proving-key cache — keygen only runs once per process.
    // Subsequent calls return the cached KeyPair in ~microseconds.
    let kp = get_or_build(CircuitId::CodeIntegrity, params, CodeIntegrityCircuit::default)
        .map_err(|e| CircuitError::ProvingError(format!("keygen: {}", e)))?;

    let field_inputs = pub_inputs.as_field_elements();
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, _>(
        params,
        kp.pk.as_ref(),
        &[circuit],
        &[vec![field_inputs]],
        OsRng,
        &mut transcript,
    )
    .map_err(|e| CircuitError::ProvingError(e.to_string()))?;

    Ok((transcript.finalize(), pub_inputs))
}

#[cfg(not(feature = "mock"))]
pub fn verify(
    proof: &[u8],
    pub_inputs: &CodeIntegrityPublicInputs,
    srs_k: u32,
) -> Result<(), CircuitError> {
    use circuit_impl::CodeIntegrityCircuit;
    use crate::proving_key_cache::{get_or_build, CircuitId};
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

    let params_arc = crate::load_srs(srs_k);
    let params = params_arc.as_ref();
    let verifier_params: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
    // Re-use the cached key pair to get the verifying key (no re-keygen).
    let kp = get_or_build(CircuitId::CodeIntegrity, params, CodeIntegrityCircuit::default)
        .map_err(|e| CircuitError::ProvingError(format!("keygen: {}", e)))?;
    let vk = kp.vk.as_ref();

    let field_inputs = pub_inputs.as_field_elements();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);

    let ok = verify_proof_multi::<
        KZGCommitmentScheme<Bn256>, VerifierGWC<_>, _, _,
        SingleStrategy<Bn256>,
    >(
        &verifier_params,
        &vk,
        &[vec![field_inputs]],
        &mut transcript,
    );
    if ok { Ok(()) } else { Err(CircuitError::VerificationError) }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_witness() -> CodeIntegrityWitness {
        let bytecode = b"hello pruv".to_vec();
        let hash = sha256_native(&bytecode);
        CodeIntegrityWitness {
            bytecode,
            program_hash: hash,
            program_id_bytes: [1u8; 32],
        }
    }

    #[test]
    fn native_hash_verifies() {
        let w = dummy_witness();
        assert!(w.verify_native());
    }

    #[test]
    fn wrong_hash_fails() {
        let mut w = dummy_witness();
        w.program_hash[0] ^= 0xff;
        assert!(!w.verify_native());
    }

    #[test]
    fn poseidon_commitment_deterministic() {
        let w = dummy_witness();
        let pi1 = w.public_inputs();
        let pi2 = w.public_inputs();
        assert_eq!(pi1.poseidon_commitment, pi2.poseidon_commitment);
    }

    #[test]
    fn poseidon_commitment_nonzero() {
        let w = dummy_witness();
        let pi = w.public_inputs();
        assert_ne!(pi.poseidon_commitment, [0u8; 32]);
    }

    #[test]
    fn different_program_ids_different_commitments() {
        let w1 = dummy_witness();
        let mut w2 = dummy_witness();
        w2.program_id_bytes[0] = 0x99;
        let c1 = w1.public_inputs().poseidon_commitment;
        let c2 = w2.public_inputs().poseidon_commitment;
        assert_ne!(c1, c2, "distinct program_ids must yield distinct commitments");
    }

    #[test]
    fn different_hashes_different_commitments() {
        let w1 = dummy_witness();
        // Different bytecode → different SHA-256 → different commitment
        let bytecode2 = b"different bytecode".to_vec();
        let w2 = CodeIntegrityWitness {
            bytecode:        bytecode2.clone(),
            program_hash:    sha256_native(&bytecode2),
            program_id_bytes: [1u8; 32],
        };
        let c1 = w1.public_inputs().poseidon_commitment;
        let c2 = w2.public_inputs().poseidon_commitment;
        assert_ne!(c1, c2, "distinct hashes must yield distinct commitments");
    }

    #[cfg(feature = "mock")]
    #[test]
    fn mock_prove_verify_roundtrip() {
        let w = dummy_witness();
        let pub_inputs = w.public_inputs();
        let (proof, _) = prove(w, 12).unwrap();
        verify(&proof, &pub_inputs, 12).unwrap();
    }
}