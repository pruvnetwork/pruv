# Pruv Node Setup Guide

> **Status:** This guide describes local development setup. The Pruv network has **not yet launched** on devnet or mainnet. On-chain program IDs, bootstrap peer addresses, and billing infrastructure shown below are placeholders.

---

## Prerequisites

| Tool        | Version   | Install                          |
|-------------|-----------|----------------------------------|
| Rust        | ≥ 1.77    | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Solana CLI  | ≥ 1.18    | `sh -c "$(curl -sSfL https://release.solana.com/v1.18.0/install)"` |
| Anchor CLI  | ≥ 0.29    | `cargo install --git https://github.com/coral-xyz/anchor anchor-cli` |
| Node.js     | ≥ 20 LTS  | `nvm install 20`                 |
| pnpm        | ≥ 9       | `npm i -g pnpm`                  |

---

## 1. Clone & Build

```bash
git clone https://github.com/nzengi/pruv-solana.git
cd pruv-solana

# Install JS dependencies
pnpm install

# Build Anchor programs
anchor build

# Build node daemon
cd node-software
cargo build --release
cd ..
```

---

## 2. Generate Operator Keypair

```bash
# Generate a new Solana keypair for your node operator identity.
solana-keygen new --outfile ~/.config/pruv/operator-keypair.json

# Fund it with at least 2 SOL for staking + rent.
# Devnet:
solana airdrop 5 $(solana-keygen pubkey ~/.config/pruv/operator-keypair.json) --url devnet
```

---

## 3. Configure Environment

Copy the example and fill in your values:

```bash
cp .env.example .env
```

`.env` variables:

```bash
# Required
OPERATOR_KEYPAIR=<base58 or JSON array from operator-keypair.json>

# Solana cluster
SOLANA_RPC_URL=https://api.devnet.solana.com
SOLANA_WS_URL=wss://api.devnet.solana.com
CLUSTER=devnet

# On-chain program IDs
# NOTE: These are placeholder values. Real program IDs will be published
# after devnet deployment (planned Q3 2026).
REGISTRY_PROGRAM_ID=RegPruv111111111111111111111111111111111111
NODE_PROGRAM_ID=NodePruv11111111111111111111111111111111111
GOVERNANCE_PROGRAM_ID=GovPruv111111111111111111111111111111111111
ATTESTATION_PROGRAM_ID=AttsPruv11111111111111111111111111111111111

# P2P networking
P2P_LISTEN_ADDR=/ip4/0.0.0.0/tcp/6000
# NOTE: No public bootstrap nodes are running yet.
# For local multi-node testing see local-test/run-3node.sh
BOOTSTRAP_PEERS=

# ZK proving — SRS (Structured Reference String)
# Leave unset for development: an insecure random SRS is generated automatically.
# For production set this to a BN254 KZG ceremony file (e.g. Hermez ptau).
# PRUV_SRS_PATH=/path/to/hermez-raw-14

# Attestation interval
ATTESTATION_INTERVAL_SECS=3600

# HTTP metrics
METRICS_PORT=9090
```

---

## 4. Register Your Node On-Chain

> **Not yet available.** On-chain program deployment is planned for Q3 2026. The commands below are the intended interface and will work once programs are deployed to devnet.

```bash
# Register operator node (stakes minimum 1 SOL)
# anchor run register-node -- \
#   --keypair ~/.config/pruv/operator-keypair.json \
#   --cluster devnet \
#   --stake 1000000000
```

---

## 5. Run the Node

```bash
cd node-software

# Development / local testing (insecure random SRS, no real network)
RUST_LOG=info cargo run --release

# Production (set PRUV_SRS_PATH to a real KZG ceremony file)
# Proof generation requires ~8 GB RAM and 4+ cores for k=14 circuits.
PRUV_SRS_PATH=/path/to/hermez-raw-14 RUST_LOG=info cargo run --release
```

The node daemon starts all subsystems:

```
[INFO] Pruv Node starting…
[INFO] Operator keypair: <pubkey>
[INFO] RPC endpoint    : https://api.devnet.solana.com
[INFO] P2P layer starting on /ip4/0.0.0.0/tcp/6000
[INFO] Block monitor started
[INFO] ZK Prover started
[INFO] Attestor started
[INFO] Metrics server listening on 0.0.0.0:9090
```

---

## 6. Local Multi-Node Test

To run a 3-node local cluster for integration testing (no real Solana network needed):

```bash
bash local-test/run-3node.sh
```

---

## 7. Run the RPC Proxy

```bash
cd rpc-client
pnpm install
cp .env.example .env
# Set UPSTREAM_RPC_URL=https://api.devnet.solana.com

pnpm dev       # development
pnpm start     # production (after pnpm build)
```

The proxy listens on port `8899` (same as a local Solana validator) so existing dApps can point to `http://localhost:8899` with zero code changes.

---

## 8. Health Check

```bash
# Node metrics
curl http://localhost:9090/health

# RPC proxy
curl http://localhost:8899/health

# Test a proxied RPC call
curl -X POST http://localhost:8899/ \
  -H "X-API-Key: dev-api-key-000" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getSlot","params":[]}'
```

---

## 9. Monitoring

The metrics endpoint at `:9090/metrics` exposes Prometheus-compatible metrics:

| Metric                          | Description                       |
|---------------------------------|-----------------------------------|
| `pruv_proofs_generated_total`  | ZK proofs generated               |
| `pruv_attestations_submitted`  | On-chain attestations submitted   |
| `pruv_p2p_peers_connected`     | Active libp2p peer connections    |
| `pruv_rpc_requests_total`      | RPC proxy requests (by method)    |
| `pruv_credits_consumed_total`  | Credits billed                    |

---

## 10. Troubleshooting

**`OPERATOR_KEYPAIR env var required`** — Ensure your `.env` file is present and `OPERATOR_KEYPAIR` is set.

**`Proof generation failed`** — The default dev build generates an insecure random SRS automatically. If you see SRS-related errors, ensure `PRUV_SRS_PATH` either points to a valid ptau file or is left unset entirely.

**`P2P: 0 bootstrap peers configured`** — No public bootstrap nodes are running yet. For local testing, start a second node instance and pass its multiaddr via `BOOTSTRAP_PEERS`.

**`Insufficient credits`** — The billing system is not yet deployed. Set `BYPASS_AUTH=true` for local development to skip credit checks.