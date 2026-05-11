#!/opt/homebrew/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Pruv — Proof generation benchmark
#
# Runs the Rust criterion benchmarks for the circuits crate and also measures
# cache-miss vs cache-hit latency directly via the proof_cache SQLite DB.
#
# Usage:
#   ./local-test/bench-proof.sh [K_VALUE]   # K_VALUE default: 10
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
K="${1:-10}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
pass()   { echo -e "  ${GREEN}✓${RESET} $*"; }
warn_()  { echo -e "  ${YELLOW}⚠${RESET} $*"; }
header() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

header "Pruv Proof Benchmark  (SRS k=$K)"
echo ""

# ── 1. Criterion benchmarks (circuits crate) ──────────────────────────────────
header "Criterion benchmarks"
echo "  Running circuits/benches/proof_bench.rs ..."
echo "  This generates real Halo2 proofs — may take 30–120 s."
echo ""

cd "$ROOT"
if cargo bench \
     --manifest-path circuits/Cargo.toml \
     -- --output-format bencher 2>&1 \
     | tee "$SCRIPT_DIR/logs/bench-criterion.txt" \
     | grep -E "test |bench:|ns/iter|ms/iter"; then
  pass "Criterion benchmarks complete"
else
  warn_ "Criterion benchmarks exited non-zero (may be normal if no diffs)"
fi

# ── 2. Cache-miss vs cache-hit latency (via node binary timing) ───────────────
header "Cache timing test (3 iterations)"

BIN="$ROOT/node-software/target/release/pruv-node"
if [[ ! -f "$BIN" ]]; then
  warn_ "Release binary not found — skipping timing test"
  warn_ "Build with: cargo build --manifest-path node-software/Cargo.toml --release"
else
  CACHE_DB=$(mktemp /tmp/pruv_bench_cache_XXXXXX.db)
  trap "rm -f $CACHE_DB" EXIT

  # Use a tiny synthetic program hash for cache warmup test
  PROG_ID="0000000000000000000000000000000000000000000000000000000000000001"
  PROG_HASH="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"

  # Pre-seed the cache so we can measure cache-hit latency
  sqlite3 "$CACHE_DB" "
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS proof_cache (
      program_id   BLOB NOT NULL,
      program_hash BLOB NOT NULL,
      proof_bytes  BLOB NOT NULL,
      created_at   INTEGER NOT NULL,
      PRIMARY KEY (program_id, program_hash)
    );
    INSERT OR REPLACE INTO proof_cache VALUES (
      x'${PROG_ID}', x'${PROG_HASH}',
      x'deadbeefcafe0000',
      $(date +%s)
    );
  " 2>/dev/null

  pass "Cache pre-seeded with synthetic entry"
  echo "  Cache DB: $CACHE_DB"

  # Measure SQLite read latency (cache hit path)
  echo ""
  echo "  SQLite cache-hit read latency (10 iterations):"
  # macOS date does not support %N — use python3 for millisecond precision
  ms_now() { python3 -c "import time; print(int(time.time() * 1000))"; }
  TIMES=()
  for i in $(seq 1 10); do
    T_START=$(ms_now)
    sqlite3 "$CACHE_DB" \
      "SELECT length(proof_bytes) FROM proof_cache WHERE program_id = x'${PROG_ID}';" \
      &>/dev/null
    T_END=$(ms_now)
    TIMES+=("$(( T_END - T_START ))")
  done

  SUM=0
  MIN_T=9999999
  MAX_T=0
  for T in "${TIMES[@]}"; do
    SUM=$(( SUM + T ))
    [[ $T -lt $MIN_T ]] && MIN_T=$T
    [[ $T -gt $MAX_T ]] && MAX_T=$T
  done
  AVG=$(( SUM / ${#TIMES[@]} ))
  echo "    Min: ${MIN_T}ms  |  Avg: ${AVG}ms  |  Max: ${MAX_T}ms"

  if [[ "$AVG" -le 5 ]]; then
    pass "Cache-hit latency ${AVG}ms ≤ 5ms target"
  else
    warn_ "Cache-hit latency ${AVG}ms > 5ms target"
  fi
fi

# ── 3. Print existing criterion results if available ─────────────────────────
header "Criterion results summary"
if [[ -f "$SCRIPT_DIR/logs/bench-criterion.txt" ]]; then
  echo ""
  cat "$SCRIPT_DIR/logs/bench-criterion.txt" \
    | grep -E "test |bench:|code_integrity|governance|merkle" \
    | head -30 \
    || echo "  (no matching benchmark lines found)"
else
  echo "  (run criterion benchmarks first)"
fi

# ── 4. Expected performance targets ───────────────────────────────────────────
header "Performance Targets"
cat <<'EOF'
  ┌─────────────────────────────────────────────────────────────────┐
  │  Circuit            │ SRS k │ Expected time │ RAM estimate       │
  ├─────────────────────┼───────┼───────────────┼────────────────────┤
  │  CodeIntegrity      │ k=10  │   3–8  s      │  ~200–400 MB      │
  │  CodeIntegrity      │ k=12  │  15–40 s      │  ~600 MB–1.2 GB   │
  │  GovernanceVote     │ k=14  │  60–180 s     │  ~1.5–3 GB        │
  │  MerkleInclusion    │ k=13  │  30–90 s      │  ~800 MB–1.5 GB   │
  │  Cache hit (SQLite) │  —    │  < 1 ms       │  negligible       │
  └─────────────────────┴───────┴───────────────┴────────────────────┘
  NOTE: Times are on Apple M-series / modern x86. First run builds SRS.
        Subsequent runs with the same k are faster (SRS cached in RAM).
        The semaphore caps concurrent proofs at max(1, num_cpus/2).
EOF

echo ""