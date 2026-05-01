#!/usr/bin/env bash
# Core benchmark launcher: attach daemon via --pid-file before mini starts (no root-PID race).
#
# Run from the Argus repo root:
#   ./benchmark/scripts/run_task.sh --task "..." --daemon-log /tmp/d.log --mini-log /tmp/m.log
# Or from anywhere (use the absolute path to this script):
#   /path/to/Argus/benchmark/scripts/run_task.sh ...
#
# Important: run `sudo -v` once first, OR let this script prompt for sudo in the foreground
# before the daemon is backgrounded (otherwise sudo stops with SIGTSTP waiting for a password).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TASK=""
DAEMON_LOG=""
MINI_LOG=""
TIMEOUT=120
DAEMON_EXTRA=()

usage() {
  echo "Usage: $0 --task <string> --daemon-log <path> --mini-log <path> [--timeout <seconds>] [--debug-dim3]" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --task)
      TASK="${2:-}"; shift 2 ;;
    --daemon-log)
      DAEMON_LOG="${2:-}"; shift 2 ;;
    --mini-log)
      MINI_LOG="${2:-}"; shift 2 ;;
    --timeout)
      TIMEOUT="${2:-120}"; shift 2 ;;
    --debug-dim3)
      DAEMON_EXTRA+=(--debug-dim3); shift ;;
    *)
      usage ;;
  esac
done

[[ -n "$TASK" && -n "$DAEMON_LOG" && -n "$MINI_LOG" ]] || usage

MINI_BIN="$REPO_ROOT/mini-swe-agent/.venv/bin/mini"
DAEMON_BIN="$REPO_ROOT/daemon/daemon"
if [[ ! -x "$MINI_BIN" ]]; then
  echo "ERROR: mini not found or not executable: $MINI_BIN" >&2
  exit 1
fi
if [[ ! -x "$DAEMON_BIN" ]]; then
  echo "ERROR: daemon binary not found: $DAEMON_BIN (run: cd $REPO_ROOT/daemon && go build -o daemon .)" >&2
  exit 1
fi

# Step 1 - PID file for the wrapper to write its PID (same PID after exec mini).
PIDFILE="$(mktemp /tmp/mini-pid-XXXXXX)"

# Step 2 - wrapper: write $$ then exec mini (atomic from observer POV: one PID for shell then agent).
WRAPPER="$(mktemp /tmp/mini-wrap-XXXXXX.sh)"
cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
echo \$\$ > "$PIDFILE"
exec "$MINI_BIN" "\$@"
EOF
chmod +x "$WRAPPER"

DAEMON_PID=""
cleanup() {
  if [[ -n "${DAEMON_PID:-}" ]]; then
    sudo kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -f "$WRAPPER" "$PIDFILE"
}
trap cleanup EXIT

# Refresh sudo credentials in the foreground so background sudo does not stop (SIGTSTP) on password prompt.
sudo -v

# Step 3 - daemon waits on pid-file (BPF already loaded inside daemon before poll returns).
sudo "$DAEMON_BIN" "${DAEMON_EXTRA[@]}" --pid-file "$PIDFILE" --ws-addr "127.0.0.1:7071" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

# Step 4 - wait until BPF is loaded and daemon is polling pid-file.
for _ in $(seq 1 300); do
  if [[ -f "$DAEMON_LOG" ]] && grep -q "BPF loaded" "$DAEMON_LOG" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if ! grep -q "BPF loaded" "$DAEMON_LOG" 2>/dev/null; then
  echo "ERROR: daemon did not log INFO: BPF loaded within 30s" >&2
  exit 1
fi

# Step 5 - run mini via wrapper; wait up to TIMEOUT seconds.
set +e
timeout "$TIMEOUT" "$WRAPPER" --exit-immediately -t "$TASK" >"$MINI_LOG" 2>&1
MINI_EXIT=$?
set -e

# Step 6 - stop daemon
sudo kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

exit "${MINI_EXIT:-0}"
