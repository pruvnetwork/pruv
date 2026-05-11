# PRUV

**Solana-native verifiable allocation protocol for airdrops, whitelists, and DAO selections.**

PRUV turns allocation into a deterministic and independently verifiable computation path. Instead of trusting an operator, users can verify the eligible set, ordering rules, seed derivation, allocation result, and on-chain receipt.

---

## The Problem

Airdrops, whitelists, grants, and DAO selections usually depend on trusted operators.

Most systems require users to trust that:

- the eligible list was not changed,
- the ordering was not manipulated,
- the selection logic was applied correctly,
- the final winners were not manually adjusted,
- the randomness source actually proves fairness.

Randomness alone is not enough. A VRF can prove that a number was generated honestly, but it does not prove that the participant set, ordering, and allocation logic were fair.

PRUV focuses on the full allocation path.

---

## What PRUV Does

PRUV provides a verifiable allocation flow:

1. Participants commit inputs before the allocation seed is known.
2. Inputs are ordered canonically.
3. A deterministic seed is derived.
4. Allocation is computed from fixed rules.
5. The result is recomputable by anyone.
6. A receipt is anchored on Solana devnet.
7. The full proof trace can be inspected.

The goal is simple:

> **No hidden list. No manual override. No trusted winner selection.**

---

## Demo Flow

The current demo shows a verifiable allocation round:

- 100 wallets
- 10 winners
- commitment collection
- deterministic seed derivation
- verified allocation output
- Solana devnet receipt
- connected wallet commit-reveal round
- finalized Explorer transaction
- cryptographic trace

The technical demo also demonstrates:

- SHA-256 commitments
- secret generation
- nullifiers
- Merkle inclusion
- eligibility checks
- proof verification flow
- Solana devnet anchoring

---

## Why Solana

PRUV uses Solana as the public verification and receipt layer.

The allocation logic is deterministic and recomputable, while Solana provides a public, timestamped, immutable receipt for the generated seed and allocation round metadata.

This makes each allocation round independently auditable without requiring users to trust the application operator.

---

## Use Cases

PRUV can be used for:

- token airdrops
- whitelist allocation
- DAO committee selection
- ecosystem grants
- allowlists
- high-demand mints
- community reward distribution
- any scarce resource allocation where fairness must be verifiable

---

## Core Thesis

Allocation is not only a randomness problem.

It is a verification problem.

PRUV verifies the complete path:

```txt
Committed inputs
      ↓
Canonical ordering
      ↓
Deterministic seed
      ↓
Fixed allocation logic
      ↓
Verifiable output
      ↓
On-chain receipt
