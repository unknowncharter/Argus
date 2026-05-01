"""Injection wiring: attack → pipeline ``current_payload`` / ``ATTACK_PAYLOAD`` ↔ mock server (no daemon / mini)."""

from __future__ import annotations

import os
import tempfile
import threading
import time

import pytest
import requests
from werkzeug.serving import make_server

import benchmark.attacks.bash_injection_attack  # noqa: F401 — register attacks
from benchmark.attacks.bash_injection_attack import BashInjectionAttack
from benchmark.mock_server.server import app as mock_app
from benchmark.pipeline.mini_swe_agent_pipeline import MiniSWEAgentPipeline
from benchmark.suites.web_content_injection.task_suite import fetch_web_content, task_suite


def test_attack_sets_pipeline_payload() -> None:
    tmp = tempfile.mkdtemp()
    pipeline = MiniSWEAgentPipeline(
        daemon_path="/nonexistent-daemon",
        results_dir=tmp,
        mini_path="/nonexistent-mini",
    )
    attack = BashInjectionAttack(task_suite, pipeline)
    user_task = task_suite.user_tasks["user_task_0"]
    injection_task = task_suite.injection_tasks["injection_task_0"]

    attack.attack(user_task, injection_task)

    assert pipeline.current_payload == injection_task.BASH_PAYLOAD


def test_mock_server_serves_payload() -> None:
    server = make_server("127.0.0.1", 0, mock_app)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.35)

    url = f"http://127.0.0.1:{port}/web/python_decorators"
    marker = "UNIQUE_TEST_PAYLOAD_ARGUS_WIRING_12345"
    os.environ["ATTACK_PAYLOAD"] = marker
    try:
        body = fetch_web_content(url)
    finally:
        os.environ.pop("ATTACK_PAYLOAD", None)

    assert marker in body

    body_clean = fetch_web_content(url)
    assert marker not in body_clean

    server.shutdown()
    thread.join(timeout=5)


def test_mock_server_set_payload_endpoint() -> None:
    server = make_server("127.0.0.1", 0, mock_app)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.35)

    base = f"http://127.0.0.1:{port}"
    marker = "SET_PAYLOAD_ENDPOINT_TEST_XYZ"
    url_page = f"{base}/web/python_decorators"

    r = requests.post(f"{base}/set_payload", json={"payload": marker}, timeout=5)
    assert r.status_code == 200
    body = fetch_web_content(url_page)
    assert marker in body

    r2 = requests.post(f"{base}/set_payload", json={"payload": ""}, timeout=5)
    assert r2.status_code == 200
    body_clean = fetch_web_content(url_page)
    assert marker not in body_clean

    server.shutdown()
    thread.join(timeout=5)


def test_agentdojo_injection_does_not_crash() -> None:
    defaults = task_suite.get_injection_vector_defaults()
    injections = {k: f"test_payload_{k}" for k in defaults}

    env = task_suite.load_and_inject_default_environment(injections)

    assert env.server_url == "http://localhost:8888"
    assert hasattr(env, "syscall_log")
