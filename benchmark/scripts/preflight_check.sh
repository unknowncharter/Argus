#!/usr/bin/env bash
# Argus benchmark prerequisites.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

# Load API keys from mini-swe-agent/.env so OPENAI_API_KEY is set without ``set -a`` manually.
if [[ -f "${REPO_ROOT}/mini-swe-agent/.env" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "${REPO_ROOT}/mini-swe-agent/.env"
  set +a
fi

PASS=0
FAIL=0
WARN=0

check() {
    local label="$1"
    local cmd="$2"
    # Run each check from repo root (e.g. ``cd daemon && go build`` must not leave cwd in daemon/).
    if ( cd "$REPO_ROOT" && eval "$cmd" ) >/dev/null 2>&1; then
        echo "  [PASS] $label"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $label"
        FAIL=$((FAIL + 1))
    fi
}

warn() {
    local label="$1"
    local path="$2"
    if [[ -e "$path" ]]; then
        echo "  [WARN] $label: $path exists — review before benchmarking"
        WARN=$((WARN + 1))
    fi
}

echo "=== Argus Benchmark Preflight Check ==="

PYTHON="${REPO_ROOT}/.venv/bin/python3"
if [[ ! -f "$PYTHON" ]]; then
  PYTHON="${REPO_ROOT}/mini-swe-agent/.venv/bin/python3"
fi
if [[ ! -f "$PYTHON" ]]; then
  echo "[FAIL] No project venv found at .venv or mini-swe-agent/.venv"
  exit 1
fi

KVER=$(uname -r)
KMAJ=$(echo "$KVER" | cut -d. -f1)
KMIN=$(echo "$KVER" | cut -d. -f2)
if [[ "$KMAJ" -gt 5 ]] || [[ "$KMAJ" -eq 5 && "$KMIN" -ge 15 ]]; then
    echo "  [PASS] Kernel version ${KVER} (>= 5.15 required)"
    PASS=$((PASS + 1))
else
    echo "  [FAIL] Kernel version ${KVER} is below 5.15 — Argus requires kernel >= 5.15 with BTF"
    FAIL=$((FAIL + 1))
fi
check "BTF enabled (/sys/kernel/btf/vmlinux)" "test -f /sys/kernel/btf/vmlinux"
check "Daemon binary exists" "test -f ./daemon/daemon"
check "Daemon builds cleanly" "cd daemon && go build -o daemon ."
check "Sudo passwordless for daemon" "sudo -n ./daemon/daemon --help"
check "BPF object exists" "test -f ./bpf/agent_observer.bpf.o"
check "API key set (OpenAI, NVIDIA NIM, or Anthropic)" "test -n \"\${OPENAI_API_KEY:-}\" || test -n \"\${NVIDIA_NIM_API_KEY:-}\" || test -n \"\${ANTHROPIC_API_KEY:-}\""
check "Mini-swe-agent available" "test -f mini-swe-agent/.venv/bin/mini"
check "AgentDojo installed" "\"${PYTHON}\" -c 'import agentdojo'"
check "Mock server port 8888 free" "! ss -tlnp 2>/dev/null | grep -q ':8888'"
FREE_GB=$(df -BG . | awk 'NR==2 {gsub("G",""); print $4}')
if [[ "${FREE_GB}" =~ ^[0-9]+$ ]] && [[ "${FREE_GB}" -ge 5 ]]; then
    echo "  [PASS] At least 5GB free disk (${FREE_GB}GB available)"
    PASS=$((PASS + 1))
else
    echo "  [FAIL] Disk space: only ${FREE_GB:-?}GB free — need at least 5GB"
    FAIL=$((FAIL + 1))
fi
check "All six suites load" "./benchmark/scripts/run_all_suites_check.sh"
check "Results directory writable" "mkdir -p benchmark/results && touch benchmark/results/.write_test && rm benchmark/results/.write_test"

warn "Real SSH keys found" "${HOME}/.ssh/id_rsa"
warn "AWS credentials found" "${HOME}/.aws/credentials"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed, ${WARN} warnings"
if [[ "${FAIL}" -eq 0 ]]; then
    echo "All checks passed. Ready to benchmark."
    exit 0
fi
echo "Fix failed checks before running the benchmark."
exit 1
