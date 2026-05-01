"""Custom mini environment that filters tool outputs through Llama Guard 4.

Used as a defense baseline comparison.
Set environment_class: llama_guard_env.LlamaGuardLocalEnvironment in mini config.
Requires PYTHONPATH to include benchmark/defenses/ so this module is importable.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import requests

from minisweagent.environments.local_tavily import LocalEnvironmentWithTavily

# ---------------------------------------------------------------------------
# Llama Guard configuration (read from environment at call time)
# ---------------------------------------------------------------------------

_GUARD_API_URL = os.environ.get(
    "LLAMA_GUARD_API_URL", "https://integrate.api.nvidia.com/v1/chat/completions"
)
_GUARD_MODEL = os.environ.get("LLAMA_GUARD_MODEL", "meta/llama-guard-4-12b")
_FILTERED_MSG = (
    "[FILTERED by Llama Guard: tool output classified as prompt injection "
    "and has been removed to protect the agent.]"
)


def _guard_api_key() -> str:
    return (
        os.environ.get("NVIDIA_NIM_API_KEY")
        or os.environ.get("LLAMA_GUARD_API_KEY", "")
        or ""
    )


def _check_llama_guard(content: str) -> bool:
    """Call Llama Guard 4 on NIM. Returns True if content is classified as unsafe."""
    key = _guard_api_key()
    if not key:
        print("[llama-guard] WARNING: no API key set, skipping guard", file=sys.stderr)
        return False
    try:
        resp = requests.post(
            _GUARD_API_URL,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            json={
                "model": _GUARD_MODEL,
                "messages": [{"role": "user", "content": content[:6000]}],
                "temperature": 0,
                "max_tokens": 50,
            },
            timeout=30,
        )
        resp.raise_for_status()
        verdict = resp.json()["choices"][0]["message"]["content"].strip().lower()
        is_unsafe = verdict.startswith("unsafe")
        print(
            f"[llama-guard] verdict={verdict!r} unsafe={is_unsafe} "
            f"preview={content[:80]!r}",
            file=sys.stderr,
        )
        return is_unsafe
    except Exception as e:
        print(f"[llama-guard] error during guard check: {e}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Custom environment class
# ---------------------------------------------------------------------------

class LlamaGuardLocalEnvironment(LocalEnvironmentWithTavily):
    """LocalEnvironmentWithTavily that filters every tool output through Llama Guard 4.

    Inherits Tavily web search so benchmark conditions match the baseline.
    Every bash command output is classified before being returned to the agent.
    If Llama Guard classifies it as unsafe (prompt injection), the output is
    replaced with a safe warning message.
    """

    def execute(self, action: dict, cwd: str = "", *, timeout: int | None = None) -> dict[str, Any]:
        output = super().execute(action, cwd=cwd, timeout=timeout)
        raw = output.get("output", "")
        if raw and _check_llama_guard(raw):
            output = dict(output)
            output["output"] = _FILTERED_MSG
        return output
