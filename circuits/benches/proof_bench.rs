//! Criterion benchmarks for pruv circuit proof generation and verification.
//!
//! # Running
//!
//! ```bash
//! # All benchmarks (slow — each prove benchmark ~10–30 s each)
//! cargo bench -p pruv-circuits
//!
//! # Single group
//! cargo bench -p pruv-circuits -- merkle/prove
//! cargo bench -p pruv-circuits -- governance/verify
//! cargo bench -p pruv-circuits -- keygen
//! cargo bench -p pruv-circuits -- batch
//!
//! # Quick smoke-test (assert mode — no measurement, just runs once)
//! cargo test -p pruv-circuits --benches
//!
//! # HTML report: target/criterion/report/index.html
//! ```
//!
//! # Benchmark groups
//!
//! | Group               | What is measured                                     |
//! |---------------------|------------------------------------------------------|
//! | `keygen/merkle`     | Raw VK + PK generation for Merkle circuit            |
//! | `keygen/governance` | Raw VK + PK generation for governance circuit        |
//! | `prove/merkle`      | Full KZG prove (warm PK cache)                       |
//! | `prove/governance`  | Full KZG prove (warm PK cache)                       |
//! | `prove/code_integrity` | Full KZG prove (warm PK cache)                    |
//! | `verify/merkle`     | KZG verify from raw proof bytes                      |
//! | `verify/governance` | KZG verify from raw proof bytes                      |
//! | `verify/code_integrity` | KZG verify from raw proof bytes                  |
//! | `batch/vote_4`      | 4 governance witnesses proved in parallel (Rayon)    |
//! | `batch/vote_8`      | 8 governance witnesses proved in parallel (Rayon)    |

use std::time::Duration;

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkGroup, Criterion,
};
use halo2_proofs::halo2curves::bn256::Fr;

use pruv_circuits::{
    batch_prover::{batch_merkle, batch_vote},
    circuit_params::{fr_to_bytes, CODE_INTEGRITY_K, GOVERNANCE_K, MERKLE_K},
    code_integrity::{
        prove as prove_code, verify as verify_code, CodeIntegrityWitness,
        sha256_native,
    },
    governance_vote::{prove as prove_vote, verify as verify_vote, VoteWitness},
    merkle::{prove as prove_merkle, verify as verify_merkle, MerkleWitness, DEPTH},
    poseidon_hasher::{hash_two, leaf_commitment},
    srs,
};

// ─── Witness builders ─────────────────────────────────────────────────────────

fn make_merkle_witness() -> MerkleWitness {
    let leaf_fr = leaf_commitment(Fr::from(123u64), Fr::from(10u64));
    let mut siblings  = vec![];
    let mut path_bits = vec![];
    let mut current   = leaf_fr;
    for i in 0..DEPTH {
        let sib      = Fr::from((i as u64 + 100) * 7);
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

fn make_vote_witness(seed: u64) -> VoteWitness {
    let voter_secret_fr  = Fr::from(0xdeadbeefu64.wrapping_add(seed));
    let voter_pk_hash_fr = Fr::from(0xcafebabeu64.wrapping_add(seed));
    let weight_fr        = Fr::from(100u64 + seed);
    let proposal_id_fr   = Fr::from(42u64 + seed);

    let leaf_fr = leaf_commitment(voter_pk_hash_fr, weight_fr);
    let mut siblings  = vec![];
    let mut path_bits = vec![];
    let mut current   = leaf_fr;
    for i in 0..DEPTH {
        let sib      = Fr::from((i as u64 + 200 + seed) * 3);
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
        vote_value:    1,
    }
}

fn make_code_witness() -> CodeIntegrityWitness {
    let bytecode: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let hash = sha256_native(&bytecode);
    CodeIntegrityWitness {
        bytecode,
        program_hash: hash,
        program_id_bytes: [0xabu8; 32],
    }
}

// ─── Warmup helpers ───────────────────────────────────────────────────────────

/// Pre-warm SRS and proving-key cache for all three circuits.
/// Called once before any benchmark group to avoid amortising cold-start cost
/// into the first sample.
fn warmup_all() {
    use pruv_circuits::{
        governance_vote::GovernanceCircuit,
        merkle::MerkleCircuit,
        proving_key_cache::{get_or_build, CircuitId},
    };

    rayon::scope(|s| {
        s.spawn(|_| {
            let p = srs::get(MERKLE_K).expect("SRS");
            get_or_build(CircuitId::Merkle, &p, MerkleCircuit::empty).expect("keygen");
        });
        s.spawn(|_| {
            let p = srs::get(GOVERNANCE_K).expect("SRS");
            get_or_build(CircuitId::GovernanceVote, &p, GovernanceCircuit::empty)
                .expect("keygen");
        });
        s.spawn(|_| {
            // SRS warm for code integrity
            let _p = srs::get(CODE_INTEGRITY_K).expect("SRS");
        });
    });
}

// ─── Keygen benchmarks ────────────────────────────────────────────────────────
//
// Measures raw VK + PK generation time, bypassing the OnceLock cache.
// This is the one-time setup cost incurred at node startup.

fn bench_keygen(c: &mut Criterion) {
    use halo2_proofs::plonk::{keygen_pk, keygen_vk};
    use pruv_circuits::{
        governance_vote::GovernanceCircuit,
        merkle::MerkleCircuit,
    };

    let mut group = c.benchmark_group("keygen");
    // Keygen is slow but deterministic — 3 samples is enough for mean ± stddev.
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(120));
    group.warm_up_time(Duration::from_secs(1));

    // --- Merkle ---
    let merkle_params = srs::get(MERKLE_K).expect("Merkle SRS");
    group.bench_function("merkle", |b| {
        b.iter_batched(
            || MerkleCircuit::empty(),
            |circuit| {
                let vk = keygen_vk(merkle_params.as_ref(), &circuit)
                    .expect("keygen_vk");
                let pk = keygen_pk(merkle_params.as_ref(), vk, &circuit)
                    .expect("keygen_pk");
                black_box(pk)
            },
            BatchSize::SmallInput,
        )
    });

    // --- Governance ---
    let gov_params = srs::get(GOVERNANCE_K).expect("Governance SRS");
    group.bench_function("governance", |b| {
        b.iter_batched(
            || GovernanceCircuit::empty(),
            |circuit| {
                let vk = keygen_vk(gov_params.as_ref(), &circuit)
                    .expect("keygen_vk");
                let pk = keygen_pk(gov_params.as_ref(), vk, &circuit)
                    .expect("keygen_pk");
                black_box(pk)
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

// ─── Prove benchmarks ─────────────────────────────────────────────────────────
//
// Measures steady-state proof generation with a warm PK cache.
// `iter_batched` ensures witness allocation is excluded from timing.

fn prove_group_settings(group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(120));
    group.warm_up_time(Duration::from_secs(5));
}

fn bench_prove(c: &mut Criterion) {
    warmup_all(); // ensure PK cache is hot before first sample

    let mut group = c.benchmark_group("prove");
    prove_group_settings(&mut group);

    // Merkle prove
    group.bench_function("merkle", |b| {
        b.iter_batched(
            make_merkle_witness,
            |w| prove_merkle(black_box(&w)).expect("merkle prove"),
            BatchSize::SmallInput,
        )
    });

    // Governance vote prove
    group.bench_function("governance", |b| {
        b.iter_batched(
            || make_vote_witness(0),
            |w| prove_vote(black_box(&w)).expect("governance prove"),
            BatchSize::SmallInput,
        )
    });

    // Code integrity prove
    group.bench_function("code_integrity", |b| {
        b.iter_batched(
            make_code_witness,
            |w| prove_code(black_box(w), CODE_INTEGRITY_K).expect("code_integrity prove"),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

// ─── Verify benchmarks ────────────────────────────────────────────────────────
//
// Proof bytes are generated once in the setup closure; only verify() is timed.
// Verify is ~100× faster than prove — use larger sample size.

fn verify_group_settings(group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(30));
    group.warm_up_time(Duration::from_secs(3));
}

fn bench_verify(c: &mut Criterion) {
    warmup_all();

    let mut group = c.benchmark_group("verify");
    verify_group_settings(&mut group);

    // Merkle verify
    {
        let w     = make_merkle_witness();
        let proof = prove_merkle(&w).expect("merkle prove for verify bench");
        group.bench_function("merkle", |b| {
            b.iter(|| verify_merkle(black_box(&proof)).expect("merkle verify"))
        });
    }

    // Governance vote verify
    {
        let w     = make_vote_witness(1);
        let proof = prove_vote(&w).expect("governance prove for verify bench");
        group.bench_function("governance", |b| {
            b.iter(|| verify_vote(black_box(&proof)).expect("governance verify"))
        });
    }

    // Code integrity verify
    {
        let w = make_code_witness();
        let pub_inputs = w.public_inputs();
        let (proof, _) =
            prove_code(w, CODE_INTEGRITY_K).expect("code_integrity prove for verify bench");
        group.bench_function("code_integrity", |b| {
            b.iter(|| {
                verify_code(
                    black_box(&proof),
                    black_box(&pub_inputs),
                    CODE_INTEGRITY_K,
                )
                .expect("code_integrity verify")
            })
        });
    }

    group.finish();
}

// ─── Batch benchmarks ─────────────────────────────────────────────────────────
//
// Tests Rayon-parallel proof generation.
// Throughput metric: proofs / second = N / wall_time

fn bench_batch(c: &mut Criterion) {
    warmup_all();

    let mut group = c.benchmark_group("batch");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(180));
    group.warm_up_time(Duration::from_secs(5));

    // 4 governance votes in parallel
    group.bench_function("vote_4", |b| {
        b.iter_batched(
            || (0u64..4).map(make_vote_witness).collect::<Vec<_>>(),
            |witnesses| {
                let results = batch_vote(black_box(&witnesses));
                for r in &results {
                    r.as_ref().expect("batch vote proof");
                }
                black_box(results)
            },
            BatchSize::SmallInput,
        )
    });

    // 8 governance votes in parallel
    group.bench_function("vote_8", |b| {
        b.iter_batched(
            || (0u64..8).map(make_vote_witness).collect::<Vec<_>>(),
            |witnesses| {
                let results = batch_vote(black_box(&witnesses));
                for r in &results {
                    r.as_ref().expect("batch vote proof");
                }
                black_box(results)
            },
            BatchSize::SmallInput,
        )
    });

    // 4 Merkle proofs in parallel (baseline for batch overhead)
    group.bench_function("merkle_4", |b| {
        b.iter_batched(
            || (0u64..4).map(|i| {
                let leaf = leaf_commitment(Fr::from(i + 1), Fr::from(i + 2));
                let mut sibs = vec![];
                let mut bits = vec![];
                let mut cur = leaf;
                for j in 0..DEPTH {
                    let sib = Fr::from((j as u64 + 10 + i) * 13 + 1);
                    let bit = (j + i as usize) % 2 == 0;
                    bits.push(bit);
                    sibs.push(sib);
                    cur = if bit { hash_two(sib, cur) } else { hash_two(cur, sib) };
                }
                MerkleWitness {
                    leaf:      fr_to_bytes(leaf),
                    siblings:  sibs.iter().map(|&s| fr_to_bytes(s)).collect(),
                    path_bits: bits,
                    root:      fr_to_bytes(cur),
                }
            }).collect::<Vec<_>>(),
            |witnesses| {
                let results = batch_merkle(black_box(&witnesses));
                for r in &results {
                    r.as_ref().expect("batch merkle proof");
                }
                black_box(results)
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

// ─── Registration ─────────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_keygen,
    bench_prove,
    bench_verify,
    bench_batch,
);
criterion_main!(benches);