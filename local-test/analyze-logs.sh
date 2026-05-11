#!/opt/homebrew/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Pruv — Log analyser  (bash 5 + macOS BSD grep compatible)
#
# Usage:
#   ./local-test/analyze-logs.sh [log_file1] [log_file2] ...
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Colour helpers
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

pass()   { echo -e "  ${GREEN}✓${RESET} $*"; }
warn_()  { echo -e "  ${YELLOW}⚠${RESET} $*"; }
fail_()  { echo -e "  ${RED}✗${RESET} $*"; }
header() { echo -e "\n${BOLD}${CYAN}── $* ──${RESET}"; }

# grep -c exits 1 when 0 matches — don't use || echo 0 with it
gcount() { grep -c "$1" "$2" 2>/dev/null || true; }
gicount() { grep -ci "$1" "$2" 2>/dev/null || true; }

LOG_FILES=("$@")
if [[ ${#LOG_FILES[@]} -eq 0 ]]; then
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  mapfile -t LOG_FILES < <(ls "$SCRIPT_DIR/logs/"*.log 2>/dev/null || true)
fi

if [[ ${#LOG_FILES[@]} -eq 0 ]]; then
  echo "No log files found. Pass log file paths as arguments."
  exit 0
fi

echo ""
echo -e "${BOLD}Pruv Log Analysis Report${RESET}"
echo -e "Files: ${LOG_FILES[*]}"
echo "Generated: $(date)"
echo ""

# ── Merge all logs ─────────────────────────────────────────────────────────────
TMP_MERGED=$(mktemp)
trap "rm -f $TMP_MERGED" EXIT
cat "${LOG_FILES[@]}" > "$TMP_MERGED" 2>/dev/null || true
TOTAL_LINES=$(wc -l < "$TMP_MERGED" | tr -d ' ')

# ── 1. Error / Warning counts ─────────────────────────────────────────────────
header "Errors & Warnings"
ERROR_COUNT=$(gcount " ERROR " "$TMP_MERGED")
WARN_COUNT=$(gcount " WARN " "$TMP_MERGED")
PANIC_COUNT=$(gicount "panic\|thread.*panicked\|SIGABRT" "$TMP_MERGED")

if [[ "$PANIC_COUNT" -gt 0 ]]; then
  fail_  "PANICS: $PANIC_COUNT"
  grep -i "panic\|thread.*panicked" "$TMP_MERGED" | head -5 | sed 's/^/    /'
elif [[ "$ERROR_COUNT" -gt 0 ]]; then
  warn_ "Errors: $ERROR_COUNT (no panics)"
  grep " ERROR " "$TMP_MERGED" | head -10 | sed 's/^/    /'
else
  pass "No errors or panics"
fi
echo "  Warnings: $WARN_COUNT  |  Total log lines: $TOTAL_LINES"

# ── 2. P2P connectivity ────────────────────────────────────────────────────────
header "P2P Connectivity"
P2P_CONNECTED=$(gcount "P2P: connected to" "$TMP_MERGED")
P2P_DISCONNECTED=$(gcount "P2P: disconnected from" "$TMP_MERGED")
P2P_LISTENING=$(gcount "P2P layer listening" "$TMP_MERGED")
P2P_MDNS=$(gcount "mDNS discovered" "$TMP_MERGED")
P2P_SUBSCRIBED=$(gcount "subscribed to" "$TMP_MERGED")

if [[ "$P2P_LISTENING" -ge 1 ]]; then
  pass "P2P listeners started: $P2P_LISTENING"
else
  fail_ "No P2P listeners detected!"
fi

if [[ "$P2P_CONNECTED" -ge 1 ]]; then
  pass "Peer connections established: $P2P_CONNECTED"
else
  warn_ "No peer connections detected (check bootstrap config)"
fi
echo "  Disconnects: $P2P_DISCONNECTED  |  mDNS discovered: $P2P_MDNS  |  Topic subscriptions: $P2P_SUBSCRIBED"

# ── 3. Heartbeat liveness ─────────────────────────────────────────────────────
header "Heartbeat Liveness"
HB_SENT=$(gcount "P2P heartbeat tick" "$TMP_MERGED")
HB_RECV=$(gcount "P2P ♥ heartbeat from" "$TMP_MERGED")

if [[ "$HB_SENT" -ge 1 ]] && [[ "$HB_RECV" -ge 1 ]]; then
  pass "Heartbeats sent: $HB_SENT  |  received: $HB_RECV"
elif [[ "$HB_SENT" -ge 1 ]]; then
  warn_ "Heartbeats sent: $HB_SENT but none received from peers (single node?)"
else
  warn_ "No heartbeats detected — gossip may not be running"
fi

# Last connection count from heartbeat tick line (BSD grep compatible — no -P)
LAST_MESH=$(grep "mesh peers:" "$TMP_MERGED" | tail -1 \
  | grep -oE 'connections=[0-9]+' | grep -oE '[0-9]+' || echo "?")
echo "  Last seen connection count: $LAST_MESH"

# ── 4. Proof pipeline ─────────────────────────────────────────────────────────
header "Proof Pipeline"
PROOFS_STARTED=$(gcount "Proving program" "$TMP_MERGED")
PROOFS_DONE=$(gcount "Proof ready in" "$TMP_MERGED")
PROOFS_CACHED=$(gcount "Proof cache hit" "$TMP_MERGED")
PROOFS_STORED=$(gcount "Proof cached for" "$TMP_MERGED")
PROOFS_FAILED=$(gcount "Proof generation failed" "$TMP_MERGED")
HASH_MISMATCH=$(gcount "Hash mismatch" "$TMP_MERGED")

echo "  Started:       $PROOFS_STARTED"
echo "  Completed:     $PROOFS_DONE"
echo "  Cache hits:    $PROOFS_CACHED"
echo "  Stored to DB:  $PROOFS_STORED"
echo "  Failed:        $PROOFS_FAILED"
echo "  Hash mismatch: $HASH_MISMATCH"

if [[ "$PROOFS_STARTED" -gt 0 ]]; then
  CACHE_RATE=$(echo "scale=1; $PROOFS_CACHED * 100 / $PROOFS_STARTED" | bc 2>/dev/null || echo "?")
  echo "  Cache hit rate: ${CACHE_RATE}%"
fi

# ── 5. Proof latency (parse "Proof ready in XXXms" lines) ─────────────────────
header "Proof Latency"
# Extract ms values — BSD grep compatible: -oE + second pass
mapfile -t LATENCIES < <(
  grep -oE 'Proof ready in [0-9]+ms' "$TMP_MERGED" 2>/dev/null \
    | grep -oE '[0-9]+' || true
)

if [[ ${#LATENCIES[@]} -eq 0 ]]; then
  warn_ "No completed proofs found in logs — latency stats unavailable"
else
  IFS=$'\n' read -r -d '' -a SORTED < <(printf '%s\n' "${LATENCIES[@]}" | sort -n && printf '\0') || true
  COUNT=${#SORTED[@]}
  MIN=${SORTED[0]}
  MAX=${SORTED[$((COUNT - 1))]}

  P50_IDX=$(( COUNT * 50 / 100 ))
  P95_IDX=$(( COUNT * 95 / 100 ))
  P99_IDX=$(( COUNT * 99 / 100 ))
  [[ $P50_IDX -ge $COUNT ]] && P50_IDX=$(( COUNT - 1 ))
  [[ $P95_IDX -ge $COUNT ]] && P95_IDX=$(( COUNT - 1 ))
  [[ $P99_IDX -ge $COUNT ]] && P99_IDX=$(( COUNT - 1 ))

  P50=${SORTED[$P50_IDX]}
  P95=${SORTED[$P95_IDX]}
  P99=${SORTED[$P99_IDX]}

  SUM=0
  for V in "${SORTED[@]}"; do SUM=$(( SUM + V )); done
  AVG=$(( SUM / COUNT ))

  echo "  Samples:  $COUNT"
  echo "  Min:      ${MIN}ms"
  echo "  Avg:      ${AVG}ms"
  echo "  P50:      ${P50}ms"
  echo "  P95:      ${P95}ms"
  echo "  P99:      ${P99}ms"
  echo "  Max:      ${MAX}ms"

  if [[ "$P95" -gt 30000 ]]; then
    warn_ "P95 proof latency ${P95}ms exceeds 30s target"
  else
    pass "P95 latency ${P95}ms within 30s budget"
  fi
fi

# ── 6. Attestation pipeline ────────────────────────────────────────────────────
header "Attestation Pipeline"
ATTS_SUBMITTED=$(gcount "Attestation submitted" "$TMP_MERGED")
ATTS_FAILED=$(gcount "Attestation.*failed\|Failed to submit attestation" "$TMP_MERGED")
ATTS_EXPIRING=$(gcount "AttestationExpiring" "$TMP_MERGED")

echo "  Submitted:          $ATTS_SUBMITTED"
echo "  Failed:             $ATTS_FAILED"
echo "  Re-attest triggers: $ATTS_EXPIRING"

if [[ "$ATTS_FAILED" -gt 0 ]]; then
  warn_ "Attestation failures detected"
  grep -i "Attestation.*failed\|Failed to submit attestation" "$TMP_MERGED" | head -5 | sed 's/^/    /'
fi

# ── 7. Semaphore / backpressure ────────────────────────────────────────────────
header "Backpressure & Resource Limits"
SEM_INFO=$(grep "Prover semaphore" "$TMP_MERGED" | head -1 || echo "")
if [[ -n "$SEM_INFO" ]]; then
  pass "$SEM_INFO"
else
  warn_ "Semaphore init log not found"
fi

SHUTDOWN_INFO=$(grep "Prover shutting down" "$TMP_MERGED" | head -1 || echo "")
if [[ -n "$SHUTDOWN_INFO" ]]; then
  echo "  $SHUTDOWN_INFO"
fi

# ── 8. Lottery ────────────────────────────────────────────────────────────────
header "Lottery Module"
LOTTERY_STARTED=$(gcount "lottery_voter: started" "$TMP_MERGED")
LOTTERY_FAIL=$(gcount "lottery_voter: config fetch failed" "$TMP_MERGED")
LOTTERY_VOTE=$(gcount "lottery_voter: submitted" "$TMP_MERGED")
echo "  Lottery voters started: $LOTTERY_STARTED"
echo "  Config fetch failures:  $LOTTERY_FAIL  (expected when LotteryConfig not deployed)"
echo "  Votes submitted:        $LOTTERY_VOTE"

# ── 9. Memory summary from CSV ────────────────────────────────────────────────
header "Memory Usage (RSS)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MEM_CSV="$SCRIPT_DIR/metrics/memory.csv"
if [[ -f "$MEM_CSV" ]]; then
  N1_MAX=$(awk -F, '/node1/{print $4}' "$MEM_CSV" | sort -n | tail -1)
  N2_MAX=$(awk -F, '/node2/{print $4}' "$MEM_CSV" | sort -n | tail -1)
  N1_MIN=$(awk -F, '/node1/{print $4}' "$MEM_CSV" | sort -n | head -1)
  N2_MIN=$(awk -F, '/node2/{print $4}' "$MEM_CSV" | sort -n | head -1)
  echo "  Node 1 RSS: min=${N1_MIN}KB  max=${N1_MAX}KB  (~$(( N1_MAX / 1024 ))MB peak)"
  echo "  Node 2 RSS: min=${N2_MIN}KB  max=${N2_MAX}KB  (~$(( N2_MAX / 1024 ))MB peak)"
  if [[ "$N1_MAX" -lt 524288 ]] && [[ "$N2_MAX" -lt 524288 ]]; then
    pass "Both nodes under 512 MB RSS"
  else
    warn_ "Peak RSS exceeds 512 MB — consider tuning SRS_K or proof batch size"
  fi
else
  warn_ "memory.csv not found at $MEM_CSV"
fi

# ── 10. Prometheus snapshot summary ───────────────────────────────────────────
header "Prometheus Metrics (latest snapshot)"
for NODE_IDX in 1 2; do
  LATEST_SNAP=$(ls "$SCRIPT_DIR/metrics/node${NODE_IDX}_snap"*.txt 2>/dev/null | sort | tail -1 || echo "")
  if [[ -n "$LATEST_SNAP" ]]; then
    echo "  Node $NODE_IDX ($(basename "$LATEST_SNAP")):"
    grep -E "^pruv_" "$LATEST_SNAP" | grep -v "^#" | sed 's/^/    /' || true
  fi
done

# ── 11. Per-file summary ──────────────────────────────────────────────────────
header "Per-node Summary"
for LOG in "${LOG_FILES[@]}"; do
  NAME=$(basename "$LOG" .log)
  LINES=$(wc -l < "$LOG" 2>/dev/null | tr -d ' ')
  ERRORS=$(gcount " ERROR " "$LOG")
  WARNS=$(gcount " WARN " "$LOG")
  CONNS=$(gcount "P2P: connected to" "$LOG")
  PROOF_D=$(gcount "Proof ready in" "$LOG")
  HBS=$(gcount "P2P heartbeat tick" "$LOG")
  HBR=$(gcount "P2P ♥ heartbeat from" "$LOG")
  printf "  %-20s  lines=%-5s  errors=%-3s  warns=%-4s  p2p_conns=%-3s  proofs=%-3s  hb_sent=%-3s  hb_recv=%s\n" \
    "$NAME" "$LINES" "$ERRORS" "$WARNS" "$CONNS" "$PROOF_D" "$HBS" "$HBR"
done

echo ""