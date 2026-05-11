# Pruv — Zero-Knowledge Trust Infrastructure for Solana dApps

**Version 0.2 — April 2026**

---

## Abstract

Solana's open deployment model allows any actor to deploy arbitrary bytecode under any program ID. Users have no verifiable guarantee that a dApp they interact with today is the same binary they audited last week. Pruv rebuilds trust at the infrastructure level without requiring users to trust any single party.

Pruv is a decentralised network of operator nodes that:

1. **Attest** dApp program bytecode on-chain using Halo2 zero-knowledge proofs.
2. **Govern** membership and parameter changes through ZK private voting.
3. **Monetise** the resulting trust signal by running a trust-aware JSON-RPC proxy for which dApp developers and end-users pay per-request credits.

> **Development status (April 2026):** ZK circuit layer (Halo2/KZG, BN254) is production-ready with 18/18 tests passing. Node daemon, Anchor programs, RPC proxy, and SDK are in active development and not yet deployed to any public network.

---

## 1. Problem

### 1.1 Bytecode Substitution Attacks

Solana programs can be upgraded by their upgrade authority at any time. There is no native mechanism for users to verify that a program they interact with matches an audited snapshot. High-profile rug-pulls and drainer programs exploit this gap.

### 1.2 Fake Front-ends and Phishing

Even if the on-chain program is honest, malicious front-ends connect wallets to un-audited programs. There is no registry that a wallet can query to distinguish between "audited and attested" and "unknown."

### 1.3 DAO Governance Privacy

Existing Solana DAO frameworks (SPL Governance, Realms) record votes publicly on-chain. This exposes voter preferences to bribery and coercion.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Pruv Network                             │
│                                                                  │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐                    │
│  │  Node 1  │   │  Node 2  │   │  Node N  │  ← Operator Nodes  │
│  │          │   │          │   │          │                     │
│  │ Monitor  │   │ Monitor  │   │ Monitor  │  ← Watch Solana     │
│  │ Prover   │   │ Prover   │   │ Prover   │  ← Generate ZK      │
│  │ Attestor │   │ Attestor │   │ Attestor │  ← Sign & Submit    │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘                   │
│       └──────────────┴──────────────┘                           │
│                     libp2p gossipsub                             │
└──────────────────────────────────────────────────────────────────┘
           │ submit_attestation (Anchor tx)
           ▼
┌──────────────────────────────────────────────────────────────────┐
│                       Solana Blockchain                          │
│  pruv-registry  │  pruv-node  │  pruv-governance  │  pruv-  │
│  (dApp registry) │  (operators) │  (proposals/votes) │  attest. │
└──────────────────────────────────────────────────────────────────┘
           ▲ JSON-RPC (trust-gated)
┌──────────┴───────────────────────────────────────────────────────┐
│               Pruv RPC Proxy  (:8899)                           │
│   Trust middleware → rejects calls to un-attested programs       │
│   Billing middleware → per-method credit metering                │
└──────────────────────────────────────────────────────────────────┘
           ▲
    dApp / Wallet (using @pruv/sdk)
```

---

## 3. On-Chain Programs

> **Status:** Anchor program scaffolds exist in the repository. On-chain deployment to devnet/mainnet has not yet occurred. Program IDs shown elsewhere in documentation are placeholders.

### 3.1 pruv-registry

Stores the canonical list of registered dApps. Each `DappRecord` account contains:

| Field           | Type       | Description                              |
|-----------------|------------|------------------------------------------|
| `program_id`    | Pubkey     | Solana program address                   |
| `program_hash`  | [u8; 32]   | SHA-256 of the current ELF bytecode      |
| `name`          | String     | Human-readable dApp name                 |
| `registered_at` | i64        | Unix timestamp of initial registration   |
| `is_active`     | bool       | False if deregistered or deprecated      |

### 3.2 pruv-node

Tracks registered node operators. Each `NodeEntry` account stores:

| Field                  | Type         | Description                                        |
|------------------------|--------------|----------------------------------------------------|
| `operator`             | Pubkey       | Node operator's wallet                             |
| `stake_amount`         | u64          | Staked PRUV tokens (minimum 1 000 PRUV)          |
| `reputation_score`     | u32          | 0–1 000 cumulative reputation                      |
| `attestations_signed`  | u64          | Lifetime co-signed attestation count               |
| `slash_count`          | u32          | Number of times slashed                            |
| `status`               | NodeStatus   | Active / Jailed / Exiting / Exited                 |
| `joined_at`            | i64          | Unix timestamp of registration                     |
| `exit_requested_at`    | i64          | Timestamp of unbonding request (0 if not exiting)  |
| `pending_rewards`      | u64          | Unclaimed PRUV rewards                            |

Operators must stake a minimum of **1 000 PRUV** tokens (SPL token, 9 decimals). Staked tokens are held in an escrow vault PDA and subject to a **7-day unbonding period** on exit. Slashed tokens are redirected to the reward pool, benefiting honest nodes.

### 3.3 pruv-attestation

Records proof of bytecode integrity for a dApp at a point in time. Each `Attestation` account is a PDA with seeds `["attestation", dapp_program_id]` owned by the **pruv-attestation program** (`AttsPruv…`).

| Field               | Type             | Description                                       |
|---------------------|------------------|---------------------------------------------------|
| `dapp_program_id`   | Pubkey           | The dApp program being attested                   |
| `attestation_type`  | AttestationType  | `CodeIntegrity`, `CustodyProof`, or `GovernanceExecution` |
| `program_hash`      | [u8; 32]         | SHA-256 hash proven in the ZK proof               |
| `slot`              | u64              | Solana slot at time of attestation                |
| `created_at`        | i64              | Unix timestamp of submission                      |
| `expires_at`        | i64              | Expiry timestamp (`created_at + 86 400` s)        |
| `signer_count`      | u8               | Number of nodes that co-signed                    |
| `valid`             | bool             | False if invalidated by hash-mismatch quorum      |
| `zk_proof`          | Vec<u8>          | Serialised Halo2 KZG proof (max 1 024 bytes)      |

Attestations have a **24-hour TTL** (`ATTESTATION_TTL_SECS = 86 400`). Nodes must re-attest each epoch. An invalidation requires a simple majority (>50%) of active nodes to flag a hash mismatch. On-chain byte layout (Borsh, little-endian): `disc(8) | dapp_program_id(32) | attestation_type(1) | program_hash(32) | slot(8) | created_at(8) | expires_at(8) | signer_count(1) | valid(1)` — offsets used by the SDK and RPC middleware to decode attestation state without IDL deserialization.

### 3.4 pruv-governance

Private voting using ZK nullifiers.

| Field              | Type       | Description                              |
|--------------------|------------|------------------------------------------|
| `proposal_id`      | u64        | Monotonically increasing ID              |
| `title`            | String     | Proposal title                           |
| `vote_deadline`    | i64        | Voting window close timestamp            |
| `votes_for`        | u64        | Count of ZK-verified "for" votes         |
| `votes_against`    | u64        | Count of ZK-verified "against" votes     |
| `member_tree_root` | [u8; 32]   | Merkle root of eligible member set       |
| `executed`         | bool       | Whether the proposal was enacted         |

---

## 4. ZK Circuits

All circuits use **Halo2** with a **KZG polynomial commitment** over **BN254**. The circuit crate (`circuits/`) is production-ready: all three circuits compile, generate real proofs, and pass their test suites.

### 4.1 Code Integrity Circuit

**Statement:** I know a bytecode `B` such that `SHA256(B) = h` and `h` is the registered hash for program `P`.

- **Public inputs:** `program_id_lo` (u128), `program_id_hi` (u128), `program_hash_lo` (u128), `program_hash_hi` (u128) — the two 32-byte values each split into low/high 128-bit halves to fit BN254 field elements
- **Private inputs:** `bytecode[]`
- **Constraint:** SHA-256 gadget (BN254 field)
- **Circuit size:** k=12 (4 096 rows)

### 4.2 Governance Vote Circuit

**Statement:** I am a DAO member (proven by Merkle path) and I vote `v ∈ {0,1}` on proposal `P` without revealing my identity.

- **Public inputs:** `merkle_root`, `nullifier`, `proposal_id`, `vote_value`
- **Private inputs:** `voter_secret`, `voter_pk_hash`, `weight`, `merkle_path[20]`
- **Constraints:**
  - `nullifier = Poseidon(voter_secret, proposal_id)` — prevents double-voting
  - `leaf = Poseidon(voter_pk_hash, weight)` — membership commitment
  - `root = MerkleRoot(leaf, path)` — Merkle inclusion
  - `vote * (vote - 1) = 0` — Boolean constraint
- **Circuit size:** k=14 (16 384 rows)

### 4.3 Merkle Inclusion Circuit

Reusable sub-circuit. Proves `leaf ∈ tree(root)` for depth-20 Poseidon Merkle trees (up to 1M members).

- **Public inputs:** `root` ([u8; 32]), `leaf` ([u8; 32])
- **Hash function:** Poseidon-128, BN254, Circom-compatible constants
- **Circuit size:** k=13 (8 192 rows)

---

## 5. Trust Score

Each attested dApp receives a composite trust score (0–100):

```
trust_score = min(100, node_count × 20)
```

| Score  | Meaning                          |
|--------|----------------------------------|
| 0      | No attestation                   |
| 20     | Attested by 1 node (provisional) |
| 60     | Attested by 3 nodes (standard)   |
| 100    | Attested by 5+ nodes (verified)  |

---

## 6. Economics

> **Note:** The economics model below describes the intended design. The credit system and on-chain billing are not yet implemented.

### 6.1 Credit System

- RPC consumers purchase credits (SOL/USDC → credits on-chain).
- Per-method costs: `sendTransaction = 10 credits`, `getAccountInfo = 1 credit`, etc.
- Revenue split: 70% to node operators (pro-rated by attestations), 20% to DAO treasury, 10% burn.

### 6.2 Node Operator Rewards

Operators earn credits for each:
- Valid attestation submitted (+50 credits)
- Unique dApp first-time attestation (+200 credits)
- Governance vote participation (+10 credits)

### 6.3 Slashing

Operators lose stake for:
- Submitting a false attestation (hash mismatch detected) → 10% slash
- Going offline for >24h → 1% slash per day
- Double-signing a governance vote nullifier → 100% slash + ban

---

## 7. Security Model

- **ZK soundness:** Relies on the hardness of the discrete log problem on BN254 and the KZG polynomial commitment trusted setup.
- **Trusted setup:** Development builds use an insecure random SRS. Production requires a KZG ceremony file (e.g. Hermez `ptau`) set via `PRUV_SRS_PATH`.
- **Threshold:** A 2/3 majority of active nodes must co-sign for an attestation to be valid on-chain.
- **Censorship resistance:** Any node can independently generate and submit a proof; the on-chain program accepts the first valid threshold set.
- **Privacy:** Governance votes reveal nothing about the voter beyond membership in the DAO Merkle tree. Nullifiers prevent double-voting without identity linkage.

---

## 8. Lottery

Pruv includes a verifiable on-chain lottery system (`pruv-lottery` Anchor program) that provides a fair, censorship-resistant incentive mechanism for node operators and token holders.

### 8.1 Mechanics

- Each **epoch** (configurable, default 24 hours) a new lottery round opens.
- Participants purchase tickets by transferring PRUV tokens to the prize pool at a fixed `ticket_price`.
- A **winner** is drawn at epoch close using verifiable randomness derived from `Poseidon(recent_blockhash, epoch)`, preventing manipulation by any single party.
- The winner receives the prize pool minus a protocol fee; fees are split to the DAO treasury.

### 8.2 Randomness

The lottery uses the Poseidon hash function (the same BN254-friendly hash used in ZK circuits) to combine the Solana recent blockhash with the epoch counter. This provides verifiable randomness without a VRF oracle while remaining deterministic and auditable by any observer.

### 8.3 Node Participation

Node daemon threads (`node-software/src/lottery.rs`) watch for `LotteryDraw` on-chain events and automatically participate on behalf of the operator. Winning a lottery draw earns an operator a reputation bonus in addition to the token prize.

---

## 9. Roadmap

| Phase | Milestone                                                        | Status / Target |
|-------|------------------------------------------------------------------|-----------------|
| 1     | ZK circuit layer: Halo2/KZG, Merkle, governance, code integrity | ✅ Done (Apr 2026) |
| 2     | Node daemon + P2P gossip + proof cache + lottery                 | 🔧 In progress  |
| 3     | Anchor programs deployed to devnet, 3-node testnet               | Q3 2026         |
| 4     | Public node onboarding, credit marketplace, SDK release          | Q4 2026         |
| 5     | Wallet integrations (Phantom, Backpack, Solflare)                | Q1 2027         |
| 6     | Cross-chain expansion (EVM L2s via bridge)                       | Q2 2027         |

---

*© 2026 Pruv Contributors — Apache 2.0 License*