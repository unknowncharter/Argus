#!/usr/bin/env bash
# Llama Guard defense benchmark runner (v2 — environment-class approach, no proxy).
#
# Each bash tool output is classified by Llama Guard 4 (NVIDIA NIM) inside
# mini's own execution environment before being returned to the agent.
# No proxy server is needed.
#
# Usage (from repo root):
#   ./benchmark/defenses/run_llama_guard_v2.sh
#
# Optional env overrides:
#   RESULTS_DIR  — output directory (default: benchmark/results_gpt4o_llama_guard)
#   SUITE        — run a single suite only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

RESULTS_DIR="${RESULTS_DIR:-benchmark/results_gpt4o_llama_guard}"

# Load project .env so NVIDIA_NIM_API_KEY / OPENAI_API_KEY / MODEL are set.
set -a
# shellcheck disable=SC1090
source "${REPO_ROOT}/mini-swe-agent/.env" 2>/dev/null || true
set +a

echo "=== Running Llama Guard defense benchmark (environment-class approach) ==="
echo "  RESULTS_DIR=${RESULTS_DIR}"
echo "  MODEL=${MODEL:-unset}"

SKIP_DAEMON=1 \
DEFENSE=llama_guard \
RESULTS_DIR="${RESULTS_DIR}" \
  "${REPO_ROOT}/benchmark/scripts/run_benchmark.sh"

echo "=== Llama Guard benchmark complete ==="
echo "  Results: ${RESULTS_DIR}"
