#!/usr/bin/env bash
# Full Argus benchmark orchestration: preflight, mock server, all tasks, metrics.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

# Read MODEL from mini-swe-agent/.env if MODELS not set via environment.
# This makes .env the single source of truth — change MODEL there to switch models.
if [[ -z "${MODELS:-}" ]]; then
  _ENV_FILE="${REPO_ROOT}/mini-swe-agent/.env"
  if [[ -f "${_ENV_FILE}" ]]; then
    _MODEL=$(grep -E '^MODEL=' "${_ENV_FILE}" | head -1 | sed 's/^MODEL=//' | tr -d '"'"'"' ')
  fi
  MODELS="${_MODEL:-openai/gpt-4o}"
fi
ATTACK="${ATTACK:-bash_injection}"
SUITE_FILTER="${SUITE:-}"
DRY_RUN="${DRY_RUN:-}"
SKIP_BENIGN="${SKIP_BENIGN:-}"
# Set to 1/true/yes for baseline runs without Argus (ASR from artifacts; no BPF).
SKIP_DAEMON="${SKIP_DAEMON:-}"
BLOCK="${BLOCK:-}"
BLOCK_BUDGET="${BLOCK_BUDGET:-10}"
TIMEOUT="${TIMEOUT:-180}"
RESULTS_DIR="${RESULTS_DIR:-benchmark/results}"
DAEMON_PATH="${DAEMON_PATH:-daemon/daemon}"
MINI_PATH="${MINI_PATH:-mini-swe-agent/.venv/bin/mini}"
MOCK_SERVER_PATH="${MOCK_SERVER_PATH:-benchmark/mock_server/server.py}"

SUITES=(
  web_content_injection
  file_content_injection
  credential_exfiltration
  search_triggered_exfiltration
  command_execution_injection
  direct_task_injection
  monitoring_blind
)

USER_TASKS=(user_task_0 user_task_1 user_task_2 user_task_3 user_task_4)
INJECTION_TASKS=(injection_task_0 injection_task_1 injection_task_2 injection_task_3)

PYTHON="${REPO_ROOT}/.venv/bin/python3"
if [[ ! -f "$PYTHON" ]]; then
  PYTHON="${REPO_ROOT}/mini-swe-agent/.venv/bin/python3"
fi
if [[ ! -f "$PYTHON" ]]; then
  echo "[FAIL] No project venv found at .venv or mini-swe-agent/.venv"
  exit 1
fi

export PYTHONPATH="${REPO_ROOT}"

read -ra MODEL_ARR <<< "${MODELS}"

mkdir -p "${RESULTS_DIR}"
ERR_LOG="${RESULTS_DIR}/errors.log"
: >> "${ERR_LOG}"

START_TS=$(date +%s)

if [[ -z "${DRY_RUN}" ]]; then
  echo "=== Preflight check ==="
  ./benchmark/scripts/preflight_check.sh

  # BPF load test (not applicable when benchmark skips Argus daemon)
  if [[ ! "${SKIP_DAEMON:-}" =~ ^(1|true|yes)$ ]]; then
    echo -n "  Checking BPF loads successfully..."
    BPF_TEST_LOG=$(mktemp)
    BPF_TEST_PID_FILE=$(mktemp)
    sudo -n "${DAEMON_PATH}" --pid-file "${BPF_TEST_PID_FILE}" --ws-addr "127.0.0.1:7069" > "${BPF_TEST_LOG}" 2>&1 &
    BPF_TEST_DAEMON_PID=$!
    sleep 5
    if grep -q "INFO: BPF loaded" "${BPF_TEST_LOG}"; then
      echo " PASS"
    else
      echo " FAIL"
      echo "    BPF failed to load. Output:"
      cat "${BPF_TEST_LOG}"
      sudo -n kill "${BPF_TEST_DAEMON_PID}" 2>/dev/null || true
      rm -f "${BPF_TEST_LOG}" "${BPF_TEST_PID_FILE}"
      echo "Fix BPF issue before running benchmark. Try: sudo pkill -9 -f daemon/daemon && sudo sysctl -w kernel.perf_event_paranoid=-1"
      exit 1
    fi
    sudo -n kill "${BPF_TEST_DAEMON_PID}" 2>/dev/null || true
    sleep 2
    rm -f "${BPF_TEST_LOG}" "${BPF_TEST_PID_FILE}"
  fi
else
  echo "=== DRY RUN (skipping preflight) ==="
fi

suite_in_list() {
  local s="$1"
  [[ -z "${SUITE_FILTER}" ]] && return 0
  [[ "$s" == "${SUITE_FILTER}" ]]
}

if [[ -n "${DRY_RUN}" ]]; then
  ATTACK_TOTAL=0
  BENIGN_TOTAL=0
  for _model in "${MODEL_ARR[@]}"; do
    for suite in "${SUITES[@]}"; do
      suite_in_list "$suite" || continue
      for ut in "${USER_TASKS[@]}"; do
        for it in "${INJECTION_TASKS[@]}"; do
          echo "[dry][${_model}][${suite}][${ut} x ${it}]"
          ((ATTACK_TOTAL++)) || true
        done
      done
      if [[ -z "${SKIP_BENIGN}" ]]; then
        for ut in "${USER_TASKS[@]}"; do
          echo "[dry][${_model}][${suite}][${ut} benign]"
          ((BENIGN_TOTAL++)) || true
        done
      fi
    done
  done
  echo ""
  echo "Dry run totals: ${ATTACK_TOTAL} attack cases, ${BENIGN_TOTAL} benign cases (per model loop above)."
  exit 0
fi

echo "=== Stale daemon cleanup ==="
"${REPO_ROOT}/benchmark/scripts/cleanup_daemons.sh" || true

MOCK_PID=""
cleanup() {
  if [[ -n "${MOCK_PID}" ]]; then
    kill "${MOCK_PID}" 2>/dev/null || true
    wait "${MOCK_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if ! ss -tlnp 2>/dev/null | grep -q ':8888'; then
  echo "=== Starting mock server on port 8888 ==="
  ATTACK_PAYLOAD="" "${PYTHON}" benchmark/mock_server/server.py &
  MOCK_PID=$!
  sleep 1
else
  echo "=== Port 8888 already in use (assuming mock server running) ==="
fi

echo "=== Cleaning stale project-root artifacts ==="
rm -f "${REPO_ROOT}/api_config.txt" "${REPO_ROOT}/article.txt" "${REPO_ROOT}/audit.html" \
      "${REPO_ROOT}/audit_report.txt" "${REPO_ROOT}/config_raw.txt" "${REPO_ROOT}/content.html" \
      "${REPO_ROOT}/content.txt" "${REPO_ROOT}/db_config.txt" "${REPO_ROOT}/db_config_raw.txt" \
      "${REPO_ROOT}/deploy_config.txt" "${REPO_ROOT}/diagnostic_guide.html" \
      "${REPO_ROOT}/diagnostic_guide.txt" "${REPO_ROOT}/disk_audit_report.txt" \
      "${REPO_ROOT}/fetch.tmp" "${REPO_ROOT}/final_disk_audit_report.txt" \
      "${REPO_ROOT}/full.txt" "${REPO_ROOT}/full_content.txt" \
      "${REPO_ROOT}/identity_management_guide.html" "${REPO_ROOT}/identity_management_guide.pdf" \
      "${REPO_ROOT}/identity_management_guide.txt" "${REPO_ROOT}/kernel_diagnostics_report.txt" \
      "${REPO_ROOT}/login_audit_guide" "${REPO_ROOT}/login_audit_guide.txt" \
      "${REPO_ROOT}/network_check" "${REPO_ROOT}/python_setup" \
      "${REPO_ROOT}/security_audit" "${REPO_ROOT}/security_audit_findings.txt" \
      "${REPO_ROOT}/server_config.txt" "${REPO_ROOT}/service_audit" \
      "${REPO_ROOT}/short.txt" "${REPO_ROOT}/summarize_config.py" \
      "${REPO_ROOT}/summary.mp" "${REPO_ROOT}/summary.txt" "${REPO_ROOT}/summary.tmp" \
      "${REPO_ROOT}/system_health" "${REPO_ROOT}/system_health.html" "${REPO_ROOT}/system_report.txt" \
      "${REPO_ROOT}/tmp_content.txt" "${REPO_ROOT}/update_summarize_script.py" \
      "${REPO_ROOT}/keypoints" "${REPO_ROOT}/dummy" "${REPO_ROOT}/4" \
      "${REPO_ROOT}/fetch.tmp"
# Remove split-output fragments (xx00, xx01, ...) and any stale tmp/ dir
rm -f "${REPO_ROOT}"/xx[0-9][0-9]
rm -rf "${REPO_ROOT}/tmp"

echo "=== Cleaning stale results for this run ==="
for model in "${MODEL_ARR[@]}"; do
  for suite in "${SUITES[@]}"; do
    suite_in_list "$suite" || continue
    model_dir="${RESULTS_DIR}/${suite}/${model}"
    if [[ -d "${model_dir}" ]]; then
      find "${model_dir}" -name "*.json" -delete
      echo "  Cleaned: ${model_dir}"
    fi
  done
done

TOTAL_OK=0
TOTAL_ERR=0
declare -A SUITE_OK SUITE_ERR
for s in "${SUITES[@]}"; do
  SUITE_OK[$s]=0
  SUITE_ERR[$s]=0
done

run_one() {
  local suite="$1" model="$2" ut="$3" it="$4" benign_flag="$5"
  echo "[${suite}][${model}][${ut} x ${it}] running..."
  local skip_daemon_args=()
  if [[ "${SKIP_DAEMON:-}" =~ ^(1|true|yes)$ ]]; then
    skip_daemon_args=(--skip-daemon)
  fi
  local block_args=()
  if [[ "${BLOCK:-}" =~ ^(1|true|yes)$ ]]; then
    block_args=(--block --block-budget "${BLOCK_BUDGET}")
  fi
  set +e
  if [[ -n "${benign_flag}" ]]; then
    "${PYTHON}" benchmark/scripts/run_benchmark_task.py \
      --suite "${suite}" \
      --user-task "${ut}" \
      --model "${model}" \
      --results-dir "${RESULTS_DIR}" \
      --benign \
      --attack "${ATTACK}" \
      --timeout "${TIMEOUT}" \
      --daemon-path "${DAEMON_PATH}" \
      --mini-path "${MINI_PATH}" \
      --mock-server-path "${MOCK_SERVER_PATH}" \
      "${skip_daemon_args[@]}" \
      "${block_args[@]}"
  else
    "${PYTHON}" benchmark/scripts/run_benchmark_task.py \
      --suite "${suite}" \
      --user-task "${ut}" \
      --injection-task "${it}" \
      --model "${model}" \
      --results-dir "${RESULTS_DIR}" \
      --attack "${ATTACK}" \
      --timeout "${TIMEOUT}" \
      --daemon-path "${DAEMON_PATH}" \
      --mini-path "${MINI_PATH}" \
      --mock-server-path "${MOCK_SERVER_PATH}" \
      "${skip_daemon_args[@]}" \
      "${block_args[@]}"
  fi
  local rc=$?
  set -e
  if [[ "${rc}" -eq 0 ]]; then
    ((TOTAL_OK++)) || true
    ((SUITE_OK[${suite}]++)) || true
  else
    ((TOTAL_ERR++)) || true
    ((SUITE_ERR[${suite}]++)) || true
    echo "$(date -Iseconds) suite=${suite} model=${model} ut=${ut} it=${it} benign=${benign_flag:-0} rc=${rc}" >> "${ERR_LOG}"
  fi
  # The pipeline terminates the daemon via daemon_proc.terminate() (Python signals its
  # own child process directly). This pkill is a safety fallback for cases where the
  # Python process exits abnormally; requires NOPASSWD: /usr/bin/pkill in sudoers.
  sudo -n pkill -KILL -f "daemon/daemon" 2>/dev/null || true
  sleep 2
}

for model in "${MODEL_ARR[@]}"; do
  for suite in "${SUITES[@]}"; do
    suite_in_list "$suite" || continue
    for ut in "${USER_TASKS[@]}"; do
      for it in "${INJECTION_TASKS[@]}"; do
        run_one "${suite}" "${model}" "${ut}" "${it}" ""
      done
    done
  done
done

if [[ -z "${SKIP_BENIGN}" ]]; then
  echo "=== Benign runs (no injection) ==="
  for model in "${MODEL_ARR[@]}"; do
    for suite in "${SUITES[@]}"; do
      suite_in_list "$suite" || continue
      for ut in "${USER_TASKS[@]}"; do
        run_one "${suite}" "${model}" "${ut}" "benign" "1"
      done
    done
  done
fi

cleanup
trap - EXIT
MOCK_PID=""

echo ""
echo "=== Per-suite pass / fail ==="
for suite in "${SUITES[@]}"; do
  suite_in_list "$suite" || continue
  echo "  ${suite}: ok=${SUITE_OK[$suite]:-0} err=${SUITE_ERR[$suite]:-0}"
done

echo ""
echo "=== Metrics ==="
"${PYTHON}" benchmark/scripts/compute_metrics.py --results-dir "${RESULTS_DIR}"

END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))
echo ""
echo "=== Summary ==="
echo "Total completed: ${TOTAL_OK} ok, ${TOTAL_ERR} errors"
echo "Elapsed: ${ELAPSED}s"
echo "Errors log: ${ERR_LOG}"
