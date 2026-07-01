"""OpenAI-compatible tier-suggester backend (data tier — external call).

# tested-by: tests/unit/test_openai_suggester.py

One adapter for every interchangeable local server that speaks ``/chat/completions``:
Ollama (`llama3.1`), OMLX (Apple-GPU MLX), llama.cpp, or any hosted endpoint. caliper
ships no model dependency — only this thin HTTP call, pointed at a configurable
``base_url``.

The model proposes glob→bucket rules for the ``logic`` residual; the deterministic
:func:`validate_suggestions` boundary (core) is the thing that decides what actually
enters ``.caliper.yaml``. Advisory and fail-soft (DPS-200/204): every transport,
status, or parse failure returns ``[]`` so the residual stays ``logic`` and the cut is
never broken. The decision path — cut, classification, ordering, ``config_digest`` —
never depends on this module.
"""

from __future__ import annotations

import json
import re
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

import structlog

from caliper.core.tier_suggester import SELECTABLE_TIERS, SuggestedRule, SuggestRequest

logger = structlog.get_logger(__name__)

# The model emits ONLY a JSON array of {glob, bucket}; caliper's boundary validates it.
# Constraining the output shape (and pinning the legal bucket enum) keeps a small CPU
# model on-task and makes a malformed flood cheap to reject.
_SYSTEM = (
    "You are a code-file tiering classifier. Given a list of untiered files, propose "
    "glob patterns that group like files into one tier each. Output ONLY a JSON array "
    'of objects {"glob": str, "bucket": str}. The bucket MUST be one of: '
    + ", ".join(SELECTABLE_TIERS)
    + ". Prefer one broad glob per directory of similar files (e.g. 'src/api/**') over "
    "many exact paths. Use '**' to match across directories. No prose, no code fences."
)

# A post is (url, body_bytes, headers, timeout) -> response_bytes. Injected so tests
# never touch the network and the transport stays swappable.
PostFn = Callable[[str, bytes, dict[str, str], float], bytes]

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


@dataclass(frozen=True)
class SuggesterConfig:
    """Where to reach the OpenAI-compatible endpoint and how to call it.

    Sourced from env/CLI at the edge — deliberately NOT part of ``PartingConfig`` so it
    never enters ``config_digest`` (the suggestion is advisory; only the *accepted*
    globs, written to ``.caliper.yaml``, change provenance).
    """

    base_url: str
    model: str
    api_key: str = ""
    timeout: float = 20.0
    num_predict: int = 512  # a JSON array of rules needs more room than a subject line


def build_messages(request: SuggestRequest) -> list[dict[str, str]]:
    """Pure prompt construction: the fixed system rule + the residual file list."""
    lines = ["Untiered files (path — size):"]
    lines += [f"  {f.path} — {f.size}" for f in request.residual]
    return [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": "\n".join(lines)},
    ]


def _extract_json_array(content: str) -> list:
    """Parse a JSON array from model output, tolerating ``` fences. ``[]`` on anything else."""
    text = content.strip()
    fence = _FENCE_RE.search(text)
    if fence:
        text = fence.group(1).strip()
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def _urllib_post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> bytes:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (configured base_url)
        return resp.read()


class OpenAICompatSuggester:
    """Calls an OpenAI-compatible chat endpoint for residual tier proposals."""

    def __init__(self, config: SuggesterConfig, *, post: PostFn | None = None) -> None:
        self._cfg = config
        self._post = post or _urllib_post

    def suggest(self, request: SuggestRequest) -> list[SuggestedRule]:
        """Return raw glob proposals, or ``[]`` on any failure (never raises)."""
        url = self._cfg.base_url.rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self._cfg.api_key:
            headers["Authorization"] = f"Bearer {self._cfg.api_key}"
        body = json.dumps(
            {
                "model": self._cfg.model,
                "stream": False,
                "temperature": 0,
                "max_tokens": self._cfg.num_predict,
                # Ollama reads generation length from `num_predict`; OpenAI/OMLX from
                # `max_tokens`. Send both so one adapter spans every backend.
                "options": {"temperature": 0, "num_predict": self._cfg.num_predict},
                "messages": build_messages(request),
            }
        ).encode()
        try:
            raw = self._post(url, body, headers, self._cfg.timeout)
            content = json.loads(raw)["choices"][0]["message"]["content"]
        except Exception as exc:  # noqa: BLE001 — advisory: any failure falls back to []
            logger.debug("suggester_unavailable", error=str(exc), model=self._cfg.model)
            return []

        out: list[SuggestedRule] = []
        for item in _extract_json_array(content):
            if not isinstance(item, dict):
                continue
            glob, bucket = item.get("glob"), item.get("bucket")
            if isinstance(glob, str) and isinstance(bucket, str):
                out.append(SuggestedRule(glob=glob, bucket=bucket, note=str(item.get("note", ""))))
        return out
