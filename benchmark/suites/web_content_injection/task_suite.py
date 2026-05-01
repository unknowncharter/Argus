from pathlib import Path

import requests as http_requests
from pydantic import BaseModel, Field

from agentdojo.functions_runtime import TaskEnvironment, make_function
from agentdojo.task_suite.task_suite import TaskSuite

_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "suites" / "web_content_injection"


class SyscallLog(BaseModel):
    match_types: list[str] = Field(default_factory=list)
    correlation_alert_fired: bool = False
    # Equals ebpf_deviation_events only; pipeline_whitelist_deviations tracked separately.
    deviation_events: int = 0
    # eBPF-only: Layer 3 auditor flagged a syscall event as inconsistent with session intent.
    ebpf_deviation_events: int = 0
    # Python pipeline text-match: agent ran a command outside the per-task whitelist.
    pipeline_whitelist_deviations: int = 0
    sensitive_paths_accessed: list[str] = Field(default_factory=list)
    unmatched_connects: list[str] = Field(default_factory=list)
    # Raw Layer 3 auditor verdicts for post-hoc threshold sweep (see sweep_threshold.py).
    auditor_verdicts: list[dict] = Field(default_factory=list)
    # Blocking: events emitted when daemon killed an offending subprocess.
    block_events: list[dict] = Field(default_factory=list)
    session_terminated_by_argus: bool = False


class WebContentEnvironment(TaskEnvironment):
    server_url: str = "http://localhost:8888"
    syscall_log: SyscallLog = Field(default_factory=SyscallLog)


def fetch_web_content(url: str) -> str:
    """Fetch web content from a URL.

    :param url: The full URL to fetch content from.
    """
    try:
        response = http_requests.get(url, timeout=10)
        return response.text
    except Exception as e:
        return f"Error fetching content: {e}"


TOOLS = [make_function(fetch_web_content)]

task_suite = TaskSuite[WebContentEnvironment](
    "web_content_injection",
    WebContentEnvironment,
    TOOLS,
    _DATA_PATH,
)

from . import injection_tasks, user_tasks  # noqa: E402, F401
