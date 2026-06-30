"""OpenAI-compatible commit-subject backend (data tier — external call).

# tested-by: tests/unit/test_openai_describer.py

One adapter for every interchangeable local server that speaks ``/chat/completions``:
OMLX (Apple-GPU MLX), Ollama and llama.cpp (CPU), or any hosted endpoint. caliper
ships no model dependency — only this thin HTTP call, pointed at a configurable
``base_url``. The model writes ONLY the prose tail; the deterministic ``type(scope): ``
prefix and the :func:`normalize_subject` boundary stay in the core.

Advisory and fail-soft (DPS-200/204): every transport, status, or parse failure
returns ``None`` so the caller keeps the deterministic subject. The decision path —
cut, classification, ordering, ``config_digest`` — never depends on this module.
"""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

import structlog

from caliper.core.commit_describer import DescribeRequest, normalize_subject

logger = structlog.get_logger(__name__)

# The model emits only the phrase after the colon — caliper owns the prefix. Keeping
# the type/scope out of the model's hands makes format leakage structurally impossible
# and shrinks the task enough for a small CPU model to do it well.
_SYSTEM = (
    "You summarize a code change as a short phrase for a git commit subject. "
    "Rules: imperative mood (e.g. 'add', 'wire', 'refactor'), lowercase first word, "
    "6 to 9 words, no trailing period, no type or scope prefix, no quotes. "
    "Output ONLY the phrase."
)

# A post is (url, body_bytes, headers, timeout) -> response_bytes. Injected so tests
# never touch the network and the transport stays swappable.
PostFn = Callable[[str, bytes, dict[str, str], float], bytes]


@dataclass(frozen=True)
class DescriberConfig:
    """Where to reach the OpenAI-compatible endpoint and how to call it.

    Sourced from env/CLI at the edge — deliberately NOT part of ``PartingConfig`` so
    it never enters ``config_digest`` (the subject is advisory, not a cut decision).
    """

    base_url: str
    model: str
    api_key: str = ""
    timeout: float = 20.0
    num_predict: int = 32


def build_messages(request: DescribeRequest) -> list[dict[str, str]]:
    """Pure prompt construction: a fixed system rule + the part's files/context."""
    lines = [f"Files changed ({request.bucket} tier):"]
    lines += [f"  {f}" for f in request.files]
    if request.context:
        lines.append(request.context)
    return [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": "\n".join(lines)},
    ]


def _urllib_post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> bytes:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (configured base_url)
        return resp.read()


class OpenAICompatDescriber:
    """Calls an OpenAI-compatible chat endpoint for one part's subject tail."""

    def __init__(self, config: DescriberConfig, *, post: PostFn | None = None) -> None:
        self._cfg = config
        self._post = post or _urllib_post

    def describe(self, request: DescribeRequest) -> str | None:
        """Return a normalized subject, or ``None`` on any failure (never raises)."""
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
                # Ollama reads max generation length from `num_predict`; OpenAI/OMLX
                # from `max_tokens`. Send both so one adapter spans every backend.
                "options": {"temperature": 0, "num_predict": self._cfg.num_predict},
                "messages": build_messages(request),
            }
        ).encode()
        try:
            raw = self._post(url, body, headers, self._cfg.timeout)
            content = json.loads(raw)["choices"][0]["message"]["content"]
        except Exception as exc:  # noqa: BLE001 — advisory: any failure falls back
            logger.debug("describer_unavailable", error=str(exc), model=self._cfg.model)
            return None
        subject = normalize_subject(request.prefix, content, max_len=request.max_len)
        return subject or None
