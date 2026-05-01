#!/usr/bin/env bash
# Delimiters defense benchmark runner.
#
# Wraps tool outputs in <tool_output> tags so the agent can distinguish
# trusted instructions from untrusted external content.
#
# Usage (from repo root):
#   ./benchmark/defenses/run_delimiters.sh
#
# Optional env overrides:
#   RESULTS_DIR  — output directory (default: benchmark/results_gpt4o_delimiters)
#   SUITE        — run a single suite only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

RESULTS_DIR="${RESULTS_DIR:-benchmark/results_gpt4o_delimiters}"

set -a
# shellcheck disable=SC1090
source "${REPO_ROOT}/mini-swe-agent/.env" 2>/dev/null || true
set +a

echo "=== Running Delimiters defense benchmark ==="
echo "  RESULTS_DIR=${RESULTS_DIR}"
echo "  MODEL=${MODEL:-unset}"

SKIP_DAEMON=1 \
DEFENSE=delimiters \
RESULTS_DIR="${RESULTS_DIR}" \
  "${REPO_ROOT}/benchmark/scripts/run_benchmark.sh"

echo "=== Delimiters benchmark complete ==="
echo "  Results: ${RESULTS_DIR}"
