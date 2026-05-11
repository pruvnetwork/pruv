#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Pruv — Continuous metrics + memory monitor
#
# Polls Prometheus endpoints and RSS memory every INTERVAL seconds and prints
# a live dashboard. Writes a CSV summary to logs/monitor.csv for post analysis.
#
# Usage:
#   ./local-test/monitor.sh [INTERVAL_SECS]   # default: 5
#   Ctrl-C to stop and print final summary.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTERVAL="${1:-5}"
LOG_DIR="$SCRIPT_DIR/logs"
CSV="$LOG_DIR/monitor.csv"
mkdir -p "$LOG_DIR"

# Colour helpers
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# CSV header
echo "ts,node,rss_kb,proofs_total,proofs_cached,proofs_failed,proof_queue,peers_connected,mesh_size,heartbeats_sent,sigs_published" \
  > "$CSV"

# ── helpers ────────────────────────────────────────────────────────────────────
metric() {
  # metric <port> <metric_name>
  curl -sf "http://localhost:$1/metrics" 2>/dev/null \
    | grep "^$2 " | awk '{print $2}' | head -1 \
    || echo "0"
}

rss_for_port() {
  local PID
  PID=$(lsof -ti:"$1" 2>/dev/null | head -1 || echo "")
  [[ -z "$PID" ]] && echo "?" && return
  ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ' || echo "?"
}

# Print table header
print_header() {
  echo ""
  printf "${BOLD}${CYAN}%-8s  %-6s  %-8s  %-9s  %-8s  %-7s  %-6s  %-8s  %-6s  %-6s  %-6s${RESET}\n" \
    "TIME" "NODE" "RSS(KB)" "PROOFS" "CACHED" "FAILED" "QUEUE" "PEERS" "MESH" "HB_TX" "SIG_TX"
  echo "──────────────────────────────────────────────────────────────────────────────────────"
}

ROWS_SINCE_HEADER=0
START_TS=$(date +%s)

cleanup() {
  echo ""
  echo ""
  echo -e "${BOLD}${CYAN}══ Monitor Summary ══${RESET}"
  ELAPSED=$(( $(date +%s) - START_TS ))
  echo "  Ran for ${ELAPSED}s  (interval=${INTERVAL}s)"
  echo "  CSV written to: $CSV"
  echo ""
  # Print tail of CSV as final snapshot
  echo "  Final snapshots:"
  tail -6 "$CSV" | column -t -s,
  echo ""
}
trap cleanup INT TERM EXIT

echo ""
echo -e "${BOLD}Pruv Live Monitor${RESET}  (interval=${INTERVAL}s, Ctrl-C to stop)"
echo "CSV: $CSV"

while true; do
  TS=$(date +%s)
  TIME_FMT=$(date +%H:%M:%S)

  if [[ $ROWS_SINCE_HEADER -eq 0 ]] || [[ $(( ROWS_SINCE_HEADER % 20 )) -eq 0 ]]; then
    print_header
  fi

  for NODE_IDX in 1 2; do
    METRICS_PORT=$(( 9089 + NODE_IDX ))
    RSS=$(rss_for_port "$METRICS_PORT")
    PROOFS=$(metric "$METRICS_PORT" "pruv_proofs_generated_total")
    CACHED=$(metric "$METRICS_PORT" "pruv_proofs_cached_total")
    FAILED=$(metric "$METRICS_PORT" "pruv_proofs_failed_total")
    QUEUE=$(metric  "$METRICS_PORT" "pruv_proof_queue_depth")
    PEERS=$(metric  "$METRICS_PORT" "pruv_p2p_peers_connected")
    MESH=$(metric   "$METRICS_PORT" "pruv_p2p_gossip_mesh_size")
    HB_TX=$(metric  "$METRICS_PORT" "pruv_p2p_heartbeats_total")
    SIG_TX=$(metric "$METRICS_PORT" "pruv_p2p_sigs_published_total")

    # Coloured status: red if failed > 0, yellow if queue > 0
    PROOFS_COL="${GREEN}${PROOFS}${RESET}"
    FAILED_COL="${GREEN}${FAILED}${RESET}"
    [[ "${FAILED:-0}" != "0" ]] && FAILED_COL="${RED}${FAILED}${RESET}"
    [[ "${QUEUE:-0}" != "0" ]]  && PROOFS_COL="${YELLOW}${PROOFS}${RESET}"

    printf "%-8s  %-6s  %-8s  " "$TIME_FMT" "node${NODE_IDX}" "${RSS}"
    printf "${GREEN}%-9s${RESET}  " "${PROOFS}"
    printf "%-8s  " "${CACHED}"
    printf "${FAILED_COL}%-7s${RESET}  " "${FAILED}"
    printf "%-6s  %-8s  %-6s  %-6s  %-6s\n" \
      "${QUEUE}" "${PEERS}" "${MESH}" "${HB_TX}" "${SIG_TX}"

    # Append to CSV
    echo "${TS},node${NODE_IDX},${RSS},${PROOFS},${CACHED},${FAILED},${QUEUE},${PEERS},${MESH},${HB_TX},${SIG_TX}" \
      >> "$CSV"
  done

  ROWS_SINCE_HEADER=$(( ROWS_SINCE_HEADER + 2 ))
  sleep "$INTERVAL"
done