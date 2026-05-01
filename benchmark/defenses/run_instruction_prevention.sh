#!/usr/bin/env bash
# Instruction Prevention defense benchmark runner.
#
# Prepends a security notice to the agent's system prompt instructing it
# to ignore injected instructions in tool outputs.
#
# Usage (from repo root):
#   ./benchmark/defenses/run_instruction_prevention.sh
#
# Optional env overrides:
#   RESULTS_DIR  — output directory (default: benchmark/results_gpt4o_instruction_prevention)
#   SUITE        — run a single suite only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

RESULTS_DIR="${RESULTS_DIR:-benchmark/results_gpt4o_instruction_prevention}"

set -a
# shellcheck disable=SC1090
source "${REPO_ROOT}/mini-swe-agent/.env" 2>/dev/null || true
set +a

echo "=== Running Instruction Prevention defense benchmark ==="
echo "  RESULTS_DIR=${RESULTS_DIR}"
echo "  MODEL=${MODEL:-unset}"

SKIP_DAEMON=1 \
DEFENSE=instruction_prevention \
RESULTS_DIR="${RESULTS_DIR}" \
  "${REPO_ROOT}/benchmark/scripts/run_benchmark.sh"

echo "=== Instruction Prevention benchmark complete ==="
echo "  Results: ${RESULTS_DIR}"
