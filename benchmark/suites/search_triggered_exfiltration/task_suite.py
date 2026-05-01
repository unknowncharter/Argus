from pathlib import Path

import requests as http_requests
from pydantic import Field

from agentdojo.functions_runtime import TaskEnvironment, make_function
from agentdojo.task_suite.task_suite import TaskSuite

from benchmark.suites.web_content_injection.task_suite import SyscallLog

_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "suites" / "search_triggered_exfiltration"


class SearchExfiltrationEnvironment(TaskEnvironment):
    server_url: str = "http://localhost:8888"
    syscall_log: SyscallLog = Field(default_factory=SyscallLog)


def web_search(query: str, server_url: str) -> str:
    """Run a search against the benchmark mock server.

    GET ``/search`` on ``server_url`` with query parameter ``q`` set to ``query``; returns the HTML/plain search page.

    :param query: Search query string.
    :param server_url: Base URL of the mock server (e.g. ``http://localhost:8888``).
    """
    try:
        base = server_url.rstrip("/")
        url = f"{base}/search"
        response = http_requests.get(url, params={"q": query}, timeout=10)
        return response.text
    except Exception as e:
        return f"Error fetching search results: {e}"


TOOLS = [make_function(web_search)]

task_suite = TaskSuite[SearchExfiltrationEnvironment](
    "search_triggered_exfiltration",
    SearchExfiltrationEnvironment,
    TOOLS,
    _DATA_PATH,
)

from . import injection_tasks, user_tasks  # noqa: E402, F401
