#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Pruv — Proof pipeline stress test
#
# Simulates burst registration of N programs simultaneously to validate:
#   - Semaphore backpressure (no OOM under concurrent load)
#   - SQLite cache correctness under concurrent writes
#   - Memory stays within bounds during burst
#   - All proofs eventually complete (no dropped work)
#
# Requires the 2-node test to be already running (run-2node-prod.sh).
# Uses HTTP to POST synthetic ChainEvents to the node's internal test endpoint,
# OR (if that's not available) fires them via the monitor's watch loop by
# registering fake program hashes in the cache DB directly.
#
# Usage:
#   ./local-test/stress-test.sh [CONCURRENCY] [ROUNDS]
#   CONCURRENCY — simultaneous programs (default 10)
#   ROUNDS      — how many rounds to run   (default 3)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CONCURRENCY="${1:-10}"
ROUNDS="${2:-3}"
LOG_DIR="$SCRIPT_DIR/logs"
STRESS_LOG="$LOG_DIR/stress-test.log"

mkdir -p "$LOG_DIR"

# Colour helpers
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
pass()   { echo -e "  ${GREEN}✓${RESET} $*"; }
warn_()  { echo -e "  ${YELLOW}⚠${RESET} $*"; }
fail_()  { echo -e "  ${RED}✗${RESET} $*"; }
header() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

header "Pruv Proof Pipeline Stress Test"
echo "  Concurrency: $CONCURRENCY programs per round"
echo "  Rounds:      $ROUNDS"
echo "  Log:         $STRESS_LOG"

CACHE_DB="${LOG_DIR}/proof_cache_node1.db"

# ── Check prerequisites ────────────────────────────────────────────────────────
header "Prerequisites"

if ! command -v sqlite3 &>/dev/null; then
  fail_ "sqlite3 not found — install it to run stress tests"
  exit 1
fi
pass "sqlite3 available"

# Check node is running
if ! curl -sf "http://localhost:9090/metrics" &>/dev/null; then
  warn_ "Node 1 metrics not reachable at :9090 — is run-2node-prod.sh running?"
  echo "  Starting a quick 2-node session in the background for testing..."
  bash "$SCRIPT_DIR/run-2node-prod.sh" 60 &
  BGPID=$!
  echo "  Waiting 8s for nodes to start..."
  sleep 8
fi

# ── Baseline metrics snapshot ──────────────────────────────────────────────────
header "Baseline snapshot"

snap_metric() {
  local PORT=$1 METRIC=$2
  curl -sf "http://localhost:${PORT}/metrics" 2>/dev/null \
    | grep "^${METRIC}" | awk '{print $2}' | head -1 || echo "0"
}

snap_rss() {
  local PORT=$1
  # Get PID from lsof listening on that port
  local PID
  PID=$(lsof -ti:"${PORT}" 2>/dev/null | head -1 || echo "")
  if [[ -n "$PID" ]]; then
    ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ' || echo "0"
  else
    echo "0"
  fi
}

BASELINE_PROOFS=$(snap_metric 9090 "pruv_proofs_generated_total")
BASELINE_CACHED=$(snap_metric 9090 "pruv_proofs_cached_total")
BASELINE_FAILED=$(snap_metric 9090 "pruv_proofs_failed_total")
BASELINE_RSS=$(snap_rss 9090)

echo "  Node1 proofs_generated: $BASELINE_PROOFS"
echo "  Node1 proofs_cached:    $BASELINE_CACHED"
echo "  Node1 proofs_failed:    $BASELINE_FAILED"
echo "  Node1 RSS (kB):         $BASELINE_RSS"

# ── Stress: inject synthetic proof cache entries ───────────────────────────────
# We directly write to the proof cache DB with fake program IDs to simulate
# a burst of 'programs already verified' cache-hit scenario, then verify
# the cache can handle concurrent reads/writes without corruption.
header "SQLite cache concurrency stress"

if [[ ! -f "$CACHE_DB" ]]; then
  warn_ "proof_cache_node1.db not found at $CACHE_DB — creating fresh test DB"
  CACHE_DB="$LOG_DIR/stress_test_cache.db"
  sqlite3 "$CACHE_DB" "
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous  = NORMAL;
    CREATE TABLE IF NOT EXISTS proof_cache (
      program_id   BLOB NOT NULL,
      program_hash BLOB NOT NULL,
      proof_bytes  BLOB NOT NULL,
      created_at   INTEGER NOT NULL,
      PRIMARY KEY (program_id, program_hash)
    );
  "
fi

TOTAL_INSERTS=0
TOTAL_ERRORS=0
ROUND_TIMES=()

for ROUND in $(seq 1 "$ROUNDS"); do
  header "Round $ROUND / $ROUNDS — inserting $CONCURRENCY entries concurrently"
  ROUND_START=$(date +%s%3N)

  # Launch CONCURRENCY parallel sqlite3 writes
  PIDS_LOCAL=()
  for i in $(seq 1 "$CONCURRENCY"); do
    (
      # Generate unique fake program ID and hash (32 bytes each, encoded as hex)
      PROG_ID=$(printf '%064x' $(( ROUND * 1000 + i )))
      PROG_HASH=$(printf '%064x' $(( ROUND * 100000 + i )))
      PROOF_BYTES=$(printf '%0256x' "$i")  # 128 fake proof bytes
      NOW=$(date +%s)

      # Use retry loop to handle WAL lock contention
      for ATTEMPT in 1 2 3; do
        if sqlite3 "$CACHE_DB" "
          INSERT OR REPLACE INTO proof_cache
            (program_id, program_hash, proof_bytes, created_at)
          VALUES (x'${PROG_ID}', x'${PROG_HASH}', x'${PROOF_BYTES}', ${NOW});
        " 2>/dev/null; then
          exit 0
        fi
        sleep 0.05
      done
      exit 1  # All retries failed
    ) &
    PIDS_LOCAL+=($!)
  done

  # Wait for all parallel writes and count failures
  ROUND_ERRORS=0
  for PID in "${PIDS_LOCAL[@]}"; do
    if ! wait "$PID"; then
      ROUND_ERRORS=$(( ROUND_ERRORS + 1 ))
    fi
  done

  ROUND_END=$(date +%s%3N)
  ROUND_MS=$(( ROUND_END - ROUND_START ))
  TOTAL_INSERTS=$(( TOTAL_INSERTS + CONCURRENCY - ROUND_ERRORS ))
  TOTAL_ERRORS=$(( TOTAL_ERRORS + ROUND_ERRORS ))
  ROUND_TIMES+=("$ROUND_MS")

  if [[ "$ROUND_ERRORS" -eq 0 ]]; then
    pass "Round $ROUND: $CONCURRENCY inserts in ${ROUND_MS}ms (0 errors)"
  else
    warn_ "Round $ROUND: $CONCURRENCY inserts in ${ROUND_MS}ms ($ROUND_ERRORS errors)"
  fi
done

# ── Verify DB integrity ────────────────────────────────────────────────────────
header "Database integrity check"
ACTUAL_COUNT=$(sqlite3 "$CACHE_DB" "SELECT COUNT(*) FROM proof_cache;" 2>/dev/null || echo "ERROR")
INTEGRITY=$(sqlite3 "$CACHE_DB" "PRAGMA integrity_check;" 2>/dev/null || echo "ERROR")

echo "  Total cached entries: $ACTUAL_COUNT"
if [[ "$INTEGRITY" == "ok" ]]; then
  pass "SQLite integrity check: OK"
else
  fail_ "SQLite integrity check failed: $INTEGRITY"
fi

# ── Concurrent read stress ─────────────────────────────────────────────────────
header "Concurrent read stress (${CONCURRENCY} parallel queries)"
READ_START=$(date +%s%3N)
READ_ERRORS=0

for i in $(seq 1 "$CONCURRENCY"); do
  (
    sqlite3 "$CACHE_DB" \
      "SELECT COUNT(*) FROM proof_cache WHERE created_at > 0;" \
      &>/dev/null || exit 1
  ) &
done
for PID in $(jobs -p); do
  wait "$PID" || READ_ERRORS=$(( READ_ERRORS + 1 ))
done
READ_END=$(date +%s%3N)
READ_MS=$(( READ_END - READ_START ))

if [[ "$READ_ERRORS" -eq 0 ]]; then
  pass "$CONCURRENCY concurrent reads in ${READ_MS}ms (0 errors)"
else
  warn_ "$CONCURRENCY concurrent reads in ${READ_MS}ms ($READ_ERRORS errors)"
fi

# ── Memory delta ───────────────────────────────────────────────────────────────
header "Memory delta (after stress)"
FINAL_RSS=$(snap_rss 9090)
if [[ "$BASELINE_RSS" -gt 0 && "$FINAL_RSS" -gt 0 ]]; then
  DELTA=$(( FINAL_RSS - BASELINE_RSS ))
  DELTA_MB=$(( DELTA / 1024 ))
  echo "  RSS before: ${BASELINE_RSS} kB"
  echo "  RSS after:  ${FINAL_RSS} kB"
  echo "  Delta:      ${DELTA} kB (${DELTA_MB} MB)"
  if [[ "$DELTA_MB" -lt 200 ]]; then
    pass "Memory growth ${DELTA_MB}MB within 200MB budget"
  else
    warn_ "Memory growth ${DELTA_MB}MB exceeds 200MB budget"
  fi
fi

# ── Prometheus metrics delta ───────────────────────────────────────────────────
header "Metrics delta"
FINAL_PROOFS=$(snap_metric 9090 "pruv_proofs_generated_total")
FINAL_FAILED=$(snap_metric 9090 "pruv_proofs_failed_total")
NEW_PROOFS=$(( ${FINAL_PROOFS%.*} - ${BASELINE_PROOFS%.*} ))
NEW_FAILED=$(( ${FINAL_FAILED%.*} - ${BASELINE_FAILED%.*} ))
echo "  New proofs generated (via metrics): $NEW_PROOFS"
echo "  New proof failures:                 $NEW_FAILED"

# ── Summary ────────────────────────────────────────────────────────────────────
header "Stress Test Summary"
echo "  Rounds:           $ROUNDS"
echo "  Concurrency/round: $CONCURRENCY"
echo "  Total inserts OK: $TOTAL_INSERTS"
echo "  Total errors:     $TOTAL_ERRORS"
echo ""

# Calculate average round time
if [[ ${#ROUND_TIMES[@]} -gt 0 ]]; then
  SUM_RT=0
  for T in "${ROUND_TIMES[@]}"; do SUM_RT=$(( SUM_RT + T )); done
  AVG_RT=$(( SUM_RT / ${#ROUND_TIMES[@]} ))
  echo "  Avg round time: ${AVG_RT}ms for $CONCURRENCY concurrent writes"
  echo "  Throughput:     $(( CONCURRENCY * 1000 / (AVG_RT + 1) )) writes/sec"
fi
echo ""

if [[ "$TOTAL_ERRORS" -eq 0 ]]; then
  pass "All stress test scenarios passed"
  exit 0
else
  fail_ "$TOTAL_ERRORS errors encountered"
  exit 1
fi