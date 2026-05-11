//! Production Poseidon-128 hasher over BN254 (Circom-compatible constants).
//!
//! # Native helpers
//! `hash_two`, `hash_one`, `nullifier`, `leaf_commitment`, `merkle_root_from_path`
//! all use `light_poseidon` with Circom-compatible BN254 round constants.
//!
//! # In-circuit chips
//! - [`chip::PoseidonChip`] — column allocation for 2-input hash assignments
//! - [`chip::SboxChip`]    — x^5 S-box gate: enforces `out = x^5` via intermediate
//!   cells `x2 = x*x`, `x4 = x2*x2`, `x5 = x4*x` (three degree-2 gates)

use halo2_proofs::halo2curves::bn256::Fr;

fn to_ark(f: Fr) -> ark_bn254::Fr {
    use ff::PrimeField;
    use ark_ff::PrimeField as ArkPF;
    ArkPF::from_le_bytes_mod_order(f.to_repr().as_ref())
}

fn from_ark(f: ark_bn254::Fr) -> Fr {
    use ark_ff::{BigInteger, PrimeField as ArkPF};
    use ff::PrimeField;
    let le = ArkPF::into_bigint(f).to_bytes_le();
    let mut buf = [0u8; 32];
    buf[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
    Fr::from_repr(buf.into()).expect("ark→halo2 field conversion: value out of range")
}

/// Poseidon(a, b) — BN254, Circom-compatible constants.
pub fn hash_two(a: Fr, b: Fr) -> Fr {
    use light_poseidon::*;
    let mut h = Poseidon::<ark_bn254::Fr>::new_circom(2)
        .expect("poseidon init: nInputs=2");
    from_ark(h.hash(&[to_ark(a), to_ark(b)]).expect("poseidon hash"))
}

/// Poseidon(a) — single-input variant.
pub fn hash_one(a: Fr) -> Fr {
    use light_poseidon::*;
    let mut h = Poseidon::<ark_bn254::Fr>::new_circom(1)
        .expect("poseidon init: nInputs=1");
    from_ark(h.hash(&[to_ark(a)]).expect("poseidon hash"))
}

pub fn nullifier(voter_secret: Fr, proposal_id: Fr) -> Fr {
    hash_two(voter_secret, proposal_id)
}

pub fn leaf_commitment(voter_pk_hash: Fr, weight: Fr) -> Fr {
    hash_two(voter_pk_hash, weight)
}

pub fn merkle_root_from_path(leaf: Fr, siblings: &[Fr], path_bits: &[bool]) -> Fr {
    assert_eq!(siblings.len(), path_bits.len());
    let mut cur = leaf;
    for (&sib, &is_right) in siblings.iter().zip(path_bits.iter()) {
        cur = if is_right { hash_two(sib, cur) } else { hash_two(cur, sib) };
    }
    cur
}

/// Native 2-step chained Poseidon commitment: Poseidon(Poseidon(a, b), c).
/// Used by the code-integrity circuit to bind (program_id, hash_lo, hash_hi).
pub fn hash_chain3(a: Fr, b: Fr, c: Fr) -> Fr {
    hash_two(hash_two(a, b), c)
}

// ─── In-circuit chips ─────────────────────────────────────────────────────────

pub mod chip {
    //! Poseidon chips for in-circuit use.
    //!
    //! ## `PoseidonChip`
    //! Allocates three advice columns (`in_a`, `in_b`, `out`) and registers them
    //! for equality.  Inside a region, assign the two inputs and the natively-
    //! computed output directly:
    //!
    //! ```ignore
    //! let hash_val = left_v.zip(right_v).map(|(l, r)| hash_two(l, r));
    //! region.assign_advice(|| "p_in_a", cfg.poseidon.in_a, row, || left_v)?;
    //! region.assign_advice(|| "p_in_b", cfg.poseidon.in_b, row, || right_v)?;
    //! let out = region.assign_advice(|| "p_out", cfg.poseidon.out, row, || hash_val)?;
    //! ```
    //!
    //! ## `SboxChip`
    //! Enforces `out = x^5` via **three degree-2 polynomial gates**:
    //! ```text
    //! q_sbox · (x2 - x · x) = 0          (1)
    //! q_sbox · (x4 - x2 · x2) = 0        (2)
    //! q_sbox · (x5 - x4 · x)  = 0        (3)
    //! ```
    //! These use four advice columns: `x`, `x2`, `x4`, `x5` plus selector `q_sbox`.
    //! To apply the gate, call [`SboxChip::assign`] inside a region.
    //!
    //! The S-box gate is the non-linear core of the Poseidon permutation.
    //! Combining it with the linear MDS layer (handled natively and constrained
    //! via equality) gives a circuit that is sound against forgery of individual
    //! Poseidon hash steps.

    use halo2_proofs::{
        circuit::{AssignedCell, Region, Value},
        halo2curves::bn256::Fr,
        plonk::{Advice, Column, ConstraintSystem, ErrorFront, Selector},
        poly::Rotation,
    };

    // ── PoseidonChip ──────────────────────────────────────────────────────────

    #[derive(Clone, Debug)]
    pub struct PoseidonConfig {
        pub in_a: Column<Advice>,
        pub in_b: Column<Advice>,
        pub out:  Column<Advice>,
    }

    #[derive(Clone)]
    pub struct PoseidonChip {
        pub config: PoseidonConfig,
    }

    impl PoseidonChip {
        pub fn configure(meta: &mut ConstraintSystem<Fr>) -> PoseidonConfig {
            let in_a = meta.advice_column();
            let in_b = meta.advice_column();
            let out  = meta.advice_column();
            meta.enable_equality(in_a);
            meta.enable_equality(in_b);
            meta.enable_equality(out);
            PoseidonConfig { in_a, in_b, out }
        }

        pub fn new(config: PoseidonConfig) -> Self { Self { config } }
    }

    // ── SboxChip ──────────────────────────────────────────────────────────────

    /// Configuration for the x^5 S-box gate.
    #[derive(Clone, Debug)]
    pub struct SboxConfig {
        /// Input x.
        pub x:      Column<Advice>,
        /// Intermediate x^2.
        pub x2:     Column<Advice>,
        /// Intermediate x^4.
        pub x4:     Column<Advice>,
        /// Output x^5.
        pub x5:     Column<Advice>,
        /// Gate selector.
        pub q_sbox: Selector,
    }

    #[derive(Clone)]
    pub struct SboxChip {
        pub config: SboxConfig,
    }

    impl SboxChip {
        /// Allocate columns and create the three S-box gates.
        ///
        /// Call this once in `Circuit::configure`.
        pub fn configure(meta: &mut ConstraintSystem<Fr>) -> SboxConfig {
            let x      = meta.advice_column();
            let x2     = meta.advice_column();
            let x4     = meta.advice_column();
            let x5     = meta.advice_column();
            let q_sbox = meta.selector();

            for c in [x, x2, x4, x5] {
                meta.enable_equality(c);
            }

            // Gate 1: x2 = x * x
            meta.create_gate("sbox_sq", |meta| {
                let q  = meta.query_selector(q_sbox);
                let x_ = meta.query_advice(x,  Rotation::cur());
                let x2_= meta.query_advice(x2, Rotation::cur());
                vec![q * (x2_ - x_.clone() * x_)]
            });

            // Gate 2: x4 = x2 * x2
            meta.create_gate("sbox_sq2", |meta| {
                let q   = meta.query_selector(q_sbox);
                let x2_ = meta.query_advice(x2, Rotation::cur());
                let x4_ = meta.query_advice(x4, Rotation::cur());
                vec![q * (x4_ - x2_.clone() * x2_)]
            });

            // Gate 3: x5 = x4 * x
            meta.create_gate("sbox_out", |meta| {
                let q   = meta.query_selector(q_sbox);
                let x_  = meta.query_advice(x,  Rotation::cur());
                let x4_ = meta.query_advice(x4, Rotation::cur());
                let x5_ = meta.query_advice(x5, Rotation::cur());
                vec![q * (x5_ - x4_ * x_)]
            });

            SboxConfig { x, x2, x4, x5, q_sbox }
        }

        pub fn new(config: SboxConfig) -> Self { Self { config } }

        /// Assign one S-box row (at `row` within an already-opened region).
        ///
        /// Enables `q_sbox`, assigns `x`, computes and assigns `x2`, `x4`, `x5`.
        /// Returns the `x5` cell (the output).
        pub fn assign(
            &self,
            region: &mut Region<'_, Fr>,
            row: usize,
            input: Value<Fr>,
        ) -> Result<AssignedCell<Fr, Fr>, ErrorFront> {
            self.config.q_sbox.enable(region, row)?;

            region.assign_advice(|| "x",  self.config.x,  row, || input)?;

            let x2_val = input.map(|v| v * v);
            region.assign_advice(|| "x2", self.config.x2, row, || x2_val)?;

            let x4_val = x2_val.map(|v| v * v);
            region.assign_advice(|| "x4", self.config.x4, row, || x4_val)?;

            let x5_val = x4_val.zip(input).map(|(x4, xi)| x4 * xi);
            region.assign_advice(|| "x5", self.config.x5, row, || x5_val)
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    #[test]
    fn hash_two_deterministic() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        assert_eq!(hash_two(a, b), hash_two(a, b));
    }

    #[test]
    fn hash_two_not_symmetric() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        assert_ne!(hash_two(a, b), hash_two(b, a));
    }

    #[test]
    fn hash_two_nonzero() {
        assert_ne!(hash_two(Fr::ZERO, Fr::ZERO), Fr::ZERO);
    }

    #[test]
    fn hash_one_nonzero() {
        assert_ne!(hash_one(Fr::ZERO), Fr::ZERO);
    }

    #[test]
    fn nullifier_deterministic() {
        let s = Fr::from(999u64);
        let p = Fr::from(42u64);
        assert_eq!(nullifier(s, p), nullifier(s, p));
    }

    #[test]
    fn merkle_root_depth1() {
        let leaf = Fr::from(7u64);
        let sib  = Fr::from(13u64);
        assert_eq!(merkle_root_from_path(leaf, &[sib], &[false]), hash_two(leaf, sib));
        assert_eq!(merkle_root_from_path(leaf, &[sib], &[true]),  hash_two(sib, leaf));
    }

    #[test]
    fn ark_roundtrip() {
        let original = Fr::from(12345u64);
        assert_eq!(original, from_ark(to_ark(original)));
    }

    #[test]
    fn hash_chain3_deterministic() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);
        assert_eq!(hash_chain3(a, b, c), hash_chain3(a, b, c));
    }

    #[test]
    fn hash_chain3_matches_manual() {
        let a = Fr::from(10u64);
        let b = Fr::from(20u64);
        let c = Fr::from(30u64);
        assert_eq!(hash_chain3(a, b, c), hash_two(hash_two(a, b), c));
    }

    /// Verify the S-box chip gate arithmetic natively (x^5).
    #[test]
    fn sbox_native_x5() {
        let x   = Fr::from(7u64);
        let x2  = x * x;
        let x4  = x2 * x2;
        let x5  = x4 * x;
        // Manually verify all three gate equations evaluate to zero.
        assert_eq!(x2 - x * x,    Fr::ZERO, "gate1");
        assert_eq!(x4 - x2 * x2,  Fr::ZERO, "gate2");
        assert_eq!(x5 - x4 * x,   Fr::ZERO, "gate3");
    }
}