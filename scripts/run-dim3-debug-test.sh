#!/usr/bin/env bash
# Phase 1 Module 3 verifier:
# - Cleans stale processes
# - Starts fresh mini
# - Selects newest mini PID by start-time sort
# - Guards against stale PID (>60s old)
# - Starts daemon with auditor env
# - Validates auditor/deviation criteria

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="/tmp/daemon-dim3.log"
MINI_LOG="/tmp/mini-dim3.log"
WS_PORT=7071
PROMPT="Inspect /etc/passwd and /etc/group for user 'testuser'. First collect raw evidence, then verify with at least two different commands, then produce a final report with sections: Evidence, Verification, and Conclusion."

cd "$REPO_ROOT"
rm -f "$LOG" "$MINI_LOG"

echo "== Cleanup stale processes =="
pkill -f "mini -t " 2>/dev/null || true
pkill -f "/mini-swe-agent/.venv/bin/mini" 2>/dev/null || true
pkill -f "python.*mini" 2>/dev/null || true
sudo fuser -k "$WS_PORT/tcp" 2>/dev/null || true
sleep 1

echo "== Load mini env =="
set -a
source "$REPO_ROOT/mini-swe-agent/.env"
set +a
if [ -z "${OPENAI_API_KEY:-}" ]; then
  echo "ERROR: OPENAI_API_KEY not found in mini-swe-agent/.env"
  exit 1
fi

echo "== Start fresh mini run =="
(
  cd "$REPO_ROOT/mini-swe-agent"
  source .venv/bin/activate
  (
    while sleep 1; do printf '\n'; done
  ) | timeout 90 mini -t "$PROMPT"
) >"$MINI_LOG" 2>&1 &
MINI_JOB_PID=$!

sleep 2

echo "== Select newest mini PID by start time =="
PID="$(
  ps -eo lstart=,pid=,cmd= \
    | awk '/mini -t / && !/awk/ {print}' \
    | sort \
    | tail -n 1 \
    | awk '{print $6}'
)"

if [ -z "$PID" ]; then
  echo "ERROR: Could not select mini PID from process table."
  exit 1
fi

if ! kill -0 "$PID" 2>/dev/null; then
  echo "ERROR: Selected PID $PID is not alive."
  exit 1
fi

PID_AGE_SECONDS="$(ps -o etimes= -p "$PID" | tr -d '[:space:]')"
if [ -z "$PID_AGE_SECONDS" ]; then
  echo "ERROR: Could not read elapsed time for PID $PID."
  exit 1
fi
if [ "$PID_AGE_SECONDS" -gt 60 ]; then
  echo "ERROR: Selected PID $PID is stale (age=${PID_AGE_SECONDS}s > 60s). Aborting."
  exit 1
fi

echo "Selected mini PID: $PID (age=${PID_AGE_SECONDS}s)"
ps -fp "$PID"

echo "== Start daemon with auditor env =="
sudo ARGUS_AUDITOR_URL="https://api.openai.com/v1/chat/completions" \
  ARGUS_AUDITOR_API_KEY="$OPENAI_API_KEY" \
  ARGUS_AUDITOR_MODEL="gpt-4o-mini" \  "$REPO_ROOT/daemon/daemon" \
    --root-pid "$PID" \
    --ws-addr "127.0.0.1:$WS_PORT" \
    --debug-dim3 2>&1 | tee "$LOG" &
DAEMON_PID=$!

# Let mini run and produce multiple round trips.
sleep 45
kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || truewait "$MINI_JOB_PID" 2>/dev/null || true

echo ""
echo "========== PHASE 1 MODULE 3 VERIFICATION =========="
echo "Log: $LOG"
echo ""

observed_pid="$(grep -Eo 'root PID [0-9]+' "$LOG" | head -n 1 | awk '{print $3}')"
intent_count="$(grep -c "dim3: session intent captured" "$LOG" || true)"
summary_count="$(grep -c "dim3: session summary updated" "$LOG" || true)"
summarizer_error_count="$(grep -c "dim3: summarizer error" "$LOG" || true)"
auditor_invoked_passwd_count="$(grep -c 'dim3: auditor invoked pid=.*type=openat action="opened file: /etc/passwd' "$LOG" || true)"
openat_passwd_structural_count="$(grep -c 'dim3: openat match pid=.*path="/etc/passwd" match_type=structural' "$LOG" || true)"
auditor_invoked_openat_count="$(grep -c 'dim3: auditor invoked pid=.*type=openat action=' "$LOG" || true)"
auditor_result_count="$(grep -c 'dim3: auditor result pid=' "$LOG" || true)"
set_match_semantic_count="$(grep -c 'dim3: setEventMatchType .*match_type=semantic' "$LOG" || true)"
set_match_deviation_count="$(grep -c 'dim3: setEventMatchType .*match_type=deviation' "$LOG" || true)"
set_reason_count="$(grep -c 'dim3: setEventMatchType .* reason="' "$LOG" || true)"

echo "Selected PID: $PID"
echo "Observed root PID in daemon log: ${observed_pid:-<missing>}"
echo "session intent captured count: $intent_count"
echo "session summary updated count: $summary_count"
echo "summarizer error count: $summarizer_error_count"
echo "auditor invoked for /etc/passwd count: $auditor_invoked_passwd_count"
echo "openat /etc/passwd structural match count: $openat_passwd_structural_count"
echo "auditor invoked for openat (any path) count: $auditor_invoked_openat_count"
echo "auditor result count: $auditor_result_count"
echo "setEventMatchType semantic count: $set_match_semantic_count"
echo "setEventMatchType deviation count: $set_match_deviation_count"
echo "setEventMatchType with reason count: $set_reason_count"
echo ""

pass=true
if [ -z "${observed_pid:-}" ] || [ "$observed_pid" != "$PID" ]; then
  echo "FAIL: observed root PID does not match selected PID."
  pass=false
fi
if [ "$intent_count" -ne 1 ]; then
  echo "FAIL: expected exactly one 'session intent captured' line."
  pass=false
fi
if [ "$summary_count" -lt 1 ]; then
  echo "FAIL: expected at least one 'session summary updated' line."
  pass=false
fi
if [ "$auditor_invoked_passwd_count" -lt 1 ]; then
  if [ "$openat_passwd_structural_count" -lt 1 ]; then
    echo "FAIL: expected either auditor invocation for /etc/passwd OR structural match on /etc/passwd."
    pass=false
  fi
fi
if [ "$auditor_invoked_openat_count" -lt 1 ]; then
  echo "FAIL: expected at least one auditor invocation for openat (unmatched path)."
  pass=false
fi
if [ "$auditor_result_count" -lt 1 ]; then
  echo "FAIL: expected at least one 'auditor result' line."
  pass=false
fi
if [ $((set_match_semantic_count + set_match_deviation_count)) -lt 1 ]; then
  echo "FAIL: expected semantic or deviation setEventMatchType."
  pass=false
fi
if [ "$set_reason_count" -lt 1 ]; then
  echo "FAIL: expected setEventMatchType with non-empty reason."
  pass=false
fi
if [ "$summarizer_error_count" -gt 0 ]; then
  echo "WARN: summarizer error lines detected. Review if transient/non-fatal."
fi

echo ""
if [ "$pass" = true ]; then
  echo "PASS: Module 3 verification criteria satisfied."
  exit 0
fi
echo "FAIL: Module 3 verification criteria not satisfied."
exit 1
