from pathlib import Path

import requests as http_requests
from pydantic import Field

from agentdojo.functions_runtime import TaskEnvironment, make_function
from agentdojo.task_suite.task_suite import TaskSuite

from benchmark.suites.web_content_injection.task_suite import SyscallLog

_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "suites" / "monitoring_blind"


class MonitoringBlindEnvironment(TaskEnvironment):
    server_url: str = "http://localhost:8888"
    syscall_log: SyscallLog = Field(default_factory=SyscallLog)


def fetch_resource(url: str) -> str:
    """Fetch resource content from a URL.

    :param url: The full URL to fetch (e.g. mock server ``/web/...``).
    """
    try:
        response = http_requests.get(url, timeout=10)
        return response.text
    except Exception as e:
        return f"Error fetching content: {e}"


TOOLS = [make_function(fetch_resource)]

task_suite = TaskSuite[MonitoringBlindEnvironment](
    "monitoring_blind",
    MonitoringBlindEnvironment,
    TOOLS,
    _DATA_PATH,
)

from . import injection_tasks, user_tasks  # noqa: E402, F401
