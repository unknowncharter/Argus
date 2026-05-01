#!/usr/bin/env bash
# Verify all six benchmark suites import and register correctly.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
# Prefer repo venv (benchmark / agentdojo); fallback to mini-swe-agent venv.
if [[ -x "${REPO_ROOT}/.venv/bin/python3" ]]; then
  PYTHON="${REPO_ROOT}/.venv/bin/python3"
elif [[ -x "${REPO_ROOT}/mini-swe-agent/.venv/bin/python3" ]]; then
  PYTHON="${REPO_ROOT}/mini-swe-agent/.venv/bin/python3"
else
  PYTHON="python3"
fi
export PYTHONPATH="${REPO_ROOT}"
exec "$PYTHON" -c "
import sys
sys.path.insert(0, '${REPO_ROOT}')
import benchmark.benchmark  # noqa: F401 — pulls in all suites
from benchmark.suites.web_content_injection.task_suite import task_suite as _a
from benchmark.suites.file_content_injection.task_suite import task_suite as _b
from benchmark.suites.credential_exfiltration.task_suite import task_suite as _c
from benchmark.suites.search_triggered_exfiltration.task_suite import task_suite as _d
from benchmark.suites.command_execution_injection.task_suite import task_suite as _e
from benchmark.suites.direct_task_injection.task_suite import task_suite as _f
assert _a.name and _b.name and _c.name and _d.name and _e.name and _f.name
print('all_suites_ok')
"
