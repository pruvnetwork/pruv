#!/opt/homebrew/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Pruv — Production-grade 2-node local test
#
# What this does:
#   1. Builds the release binary (if needed).
#   2. Checks ports are free before starting.
#   3. Starts 2 nodes (Node 1 = seed, Node 2 = peer).
#   4. Scrapes Prometheus metrics every 10 s for the full duration.
#   5. Polls RSS memory of both processes every 5 s.
#   6. On exit: runs log analysis and prints a summary table.
#
# Usage:
#   chmod +x local-test/run-2node-prod.sh
#   ./local-test/run-2node-prod.sh [DURATION_SECS]   # default 300 (5 min)
#
# Environment overrides:
#   SOLANA_RPC_URL   — upstream Solana RPC  (default: devnet)
#   SRS_K            — Halo2 SRS k value    (default: 10)
#   SKIP_BUILD       — set to 1 to skip cargo build
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$ROOT/node-software/target/release/pruv-node"
LOG_DIR="$SCRIPT_DIR/logs"
METRICS_DIR="$SCRIPT_DIR/metrics"
DURATION="${1:-300}"

mkdir -p "$LOG_DIR" "$METRICS_DIR"

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

pass() { echo -e "${GREEN}✓${RESET} $*"; }
fail() { echo -e "${RED}✗${RESET} $*"; }
info() { echo -e "${CYAN}→${RESET} $*"; }
header() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

# ── Build ──────────────────────────────────────────────────────────────────────
if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  header "Building pruv-node (release)"
  cargo build --manifest-path "$ROOT/node-software/Cargo.toml" --release 2>&1 \
    | tail -5
  pass "Build complete"
fi

if [[ ! -f "$BIN" ]]; then
  fail "Binary not found: $BIN"
  echo "Run: cargo build --manifest-path node-software/Cargo.toml --release"
  exit 1
fi

# ── Port availability check ────────────────────────────────────────────────────
header "Checking port availability"
for PORT in 9000 9001 9090 9091; do
  if lsof -ti:"$PORT" &>/dev/null; then
    OCCUPANT=$(lsof -ti:"$PORT" | head -1)
    fail "Port $PORT is already in use by PID $OCCUPANT"
    echo "  Kill it with: kill $OCCUPANT"
    exit 1
  fi
  pass "Port $PORT free"
done

# ── Keypairs ───────────────────────────────────────────────────────────────────
NODE1_KP='[177,102,130,1,251,55,111,70,40,58,25,130,66,138,107,185,24,121,120,231,212,166,128,211,107,37,76,54,230,76,139,144,32,101,214,96,142,151,65,230,100,179,182,230,158,103,43,62,232,40,234,118,98,142,86,205,173,89,188,1,6,232,179,163]'
NODE2_KP='[179,230,202,221,163,192,29,92,156,209,229,52,188,0,17,247,112,44,118,147,58,55,18,191,19,205,145,25,231,16,3,110,177,239,110,104,234,61,139,219,251,91,132,190,155,150,170,190,237,242,170,220,126,85,244,216,95,240,212,127,117,39,73,2]'
NODE1_PEER_ID="12D3KooWBzqHEQ1QjzRSmHVoSrQxVa4JXqJqQPFB6DUFww4JXuvr"
BOOTSTRAP="/ip4/127.0.0.1/tcp/9000/p2p/${NODE1_PEER_ID}"

# ── Common env ─────────────────────────────────────────────────────────────────
COMMON_ENV=(
  "SOLANA_RPC_URL=${SOLANA_RPC_URL:-https://api.devnet.solana.com}"
  "REGISTRY_PROGRAM_ID=Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS"
  "ATTESTATION_PROGRAM_ID=Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnT"
  "GOVERNANCE_PROGRAM_ID=Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnU"
  "NODE_PROGRAM_ID=Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnV"
  "SRS_K=${SRS_K:-10}"
  "ATTESTATION_INTERVAL_SECS=30"
  "RUST_LOG=info,pruv_node=debug,libp2p=warn"
)

PIDS=()
TAIL_PID=""
METRICS_PID=""
MEMORY_PID=""
TEST_START=$(date +%s)

# ── Cleanup ────────────────────────────────────────────────────────────────────
cleanup() {
  echo ""
  header "Shutting down"

  [[ -n "$TAIL_PID" ]]    && kill "$TAIL_PID"    2>/dev/null || true
  [[ -n "$METRICS_PID" ]] && kill "$METRICS_PID" 2>/dev/null || true
  [[ -n "$MEMORY_PID" ]]  && kill "$MEMORY_PID"  2>/dev/null || true

  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait "${PIDS[@]}" 2>/dev/null || true

  local elapsed=$(( $(date +%s) - TEST_START ))
  echo ""
  header "Test complete — ran ${elapsed}s"
  echo ""

  # Run log analysis
  /opt/homebrew/bin/bash "$SCRIPT_DIR/analyze-logs.sh" \
    "$LOG_DIR/node1.log" \
    "$LOG_DIR/node2.log" 2>/dev/null || true

  echo ""
  info "Raw logs:    $LOG_DIR/"
  info "Metrics:     $METRICS_DIR/"
  echo ""
}
trap cleanup INT TERM EXIT

# ── Start Node 1 (seed) ────────────────────────────────────────────────────────
header "Starting Node 1 (seed)"
env "${COMMON_ENV[@]}" \
  OPERATOR_KEYPAIR="$NODE1_KP" \
  P2P_PORT=9000 \
  METRICS_PORT=9090 \
  PROOF_CACHE_PATH="$LOG_DIR/proof_cache_node1.db" \
  "$BIN" > "$LOG_DIR/node1.log" 2>&1 &
PIDS+=($!)
info "Node 1 PID=${PIDS[${#PIDS[@]}-1]}  P2P=:9000  Metrics=:9090"

sleep 2

# ── Start Node 2 ───────────────────────────────────────────────────────────────
header "Starting Node 2"
env "${COMMON_ENV[@]}" \
  OPERATOR_KEYPAIR="$NODE2_KP" \
  P2P_PORT=9001 \
  METRICS_PORT=9091 \
  BOOTSTRAP_PEERS="$BOOTSTRAP" \
  PROOF_CACHE_PATH="$LOG_DIR/proof_cache_node2.db" \
  "$BIN" > "$LOG_DIR/node2.log" 2>&1 &
PIDS+=($!)
info "Node 2 PID=${PIDS[${#PIDS[@]}-1]}  P2P=:9001  Metrics=:9091  bootstrap→Node1"

sleep 3

# ── Verify both nodes started ──────────────────────────────────────────────────
header "Smoke check"
for i in 1 2; do
  LOG="$LOG_DIR/node${i}.log"
  if grep -q "P2P layer listening" "$LOG" 2>/dev/null; then
    pass "Node $i: P2P listening"
  else
    fail "Node $i: P2P not yet listening (check $LOG)"
  fi
done

# ── Background: metrics scraper ────────────────────────────────────────────────
(
  SNAP=0
  while true; do
    sleep 10
    TS=$(date +%s)
    for NODE_IDX in 1 2; do
      PORT=$(( 9089 + NODE_IDX ))
      OUTFILE="$METRICS_DIR/node${NODE_IDX}_snap${SNAP}_${TS}.txt"
      curl -sf "http://localhost:${PORT}/metrics" -o "$OUTFILE" 2>/dev/null \
        || echo "# metrics unavailable at ${TS}" > "$OUTFILE"
    done
    SNAP=$(( SNAP + 1 ))
  done
) &
METRICS_PID=$!

# ── Background: memory tracker ─────────────────────────────────────────────────
MEMORY_LOG="$METRICS_DIR/memory.csv"
echo "timestamp,pid,node,rss_kb" > "$MEMORY_LOG"
(
  N1_PID="${PIDS[0]}"
  N2_PID="${PIDS[1]}"
  while true; do
    sleep 5
    TS=$(date +%s)
    N1_RSS=$(ps -o rss= -p "$N1_PID" 2>/dev/null | tr -d ' ' || echo 0)
    N2_RSS=$(ps -o rss= -p "$N2_PID" 2>/dev/null | tr -d ' ' || echo 0)
    echo "$TS,$N1_PID,node1,$N1_RSS" >> "$MEMORY_LOG"
    echo "$TS,$N2_PID,node2,$N2_RSS" >> "$MEMORY_LOG"
  done
) &
MEMORY_PID=$!

# ── Tail merged logs ───────────────────────────────────────────────────────────
header "Live logs (${DURATION}s test window)"
echo "  Node1: $LOG_DIR/node1.log"
echo "  Node2: $LOG_DIR/node2.log"
echo ""

tail -F "$LOG_DIR/node1.log" "$LOG_DIR/node2.log" 2>/dev/null \
  | sed 's|^==>.*node1.log.*<==|[N1]|; s|^==>.*node2.log.*<==|[N2]|' &
TAIL_PID=$!

# ── Wait for test duration ─────────────────────────────────────────────────────
sleep "$DURATION"
# cleanup is called by EXIT trap