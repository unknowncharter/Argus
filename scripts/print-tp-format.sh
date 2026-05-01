#!/bin/bash
# Print sched tracepoint format (for BPF offset checks). Run with sudo.

BASE="${1:-/sys/kernel/debug/tracing}"
for name in sched_process_fork sched_process_exec sched_process_exit; do
  echo "=== sched/$name ==="
  [ -f "$BASE/events/sched/$name/format" ] && cat "$BASE/events/sched/$name/format" || echo "(cannot read; try sudo)"
  echo
done
