"""Describer composition edge — resolve a backend and run it over a cut.

# tested-by: tests/unit/test_part_describe.py

The imperative shell for the advisory commit describer (DPS-101). The pure renderer
stays network-free: this module performs the side-effecting model calls and hands the
renderer a plain ``{part.id: subject}`` map. Everything here is fail-soft — a missing,
disabled, or unreachable backend yields an empty map and the deterministic subjects
stand. The describer config is read from env, deliberately NOT from ``PartingConfig``,
so it never enters ``config_digest``.
"""

from __future__ import annotations

from collections.abc import Mapping

import structlog

from caliper.core.commit_describer import (
    CommitDescriberPort,
    DescribeRequest,
    NullDescriber,
)
from caliper.core.models import CutList
from caliper.core.part_script import _SUMMARY, _peel_prefix
from caliper.data.openai_describer import DescriberConfig, OpenAICompatDescriber

logger = structlog.get_logger(__name__)

# Explicit opt-out values for CALIPER_DESCRIBER.
_DISABLED = {"0", "off", "false", "no"}


def describer_from_env(env: Mapping[str, str], *, force: bool | None = None) -> CommitDescriberPort:
    """Resolve a describer from environment, honouring an optional CLI override.

    ``force`` is the tri-state ``--describe/--no-describe`` flag: ``False`` forces the
    deterministic path, ``True`` forces the model on (still fail-soft), ``None`` follows
    env. A describer is only built when both a model and a base URL resolve — otherwise
    the fail-soft :class:`NullDescriber` keeps the deterministic subjects with zero
    network calls.
    """
    if force is False:
        return NullDescriber()
    if force is None and env.get("CALIPER_DESCRIBER", "").strip().lower() in _DISABLED:
        return NullDescriber()

    model = env.get("CALIPER_DESCRIBER_MODEL", "").strip()
    base_url = _resolve_base_url(env)
    if not model or not base_url:
        return NullDescriber()

    api_key = env.get("CALIPER_DESCRIBER_API_KEY") or env.get("OMLX_API_KEY") or ""
    try:
        timeout = float(env.get("CALIPER_DESCRIBER_TIMEOUT") or 20)
    except ValueError:
        timeout = 20.0
    return OpenAICompatDescriber(
        DescriberConfig(base_url=base_url, model=model, api_key=api_key, timeout=timeout)
    )


def _resolve_base_url(env: Mapping[str, str]) -> str:
    """Prefer an explicit URL, then a bare Ollama host, then a running OMLX server."""
    explicit = env.get("CALIPER_DESCRIBER_BASE_URL", "").strip()
    if explicit:
        return explicit
    ollama = env.get("OLLAMA_HOST", "").strip()
    if ollama:
        return ollama.rstrip("/") + "/v1"
    return env.get("OMLX_BASE_URL", "").strip()


def describe_parts(cut: CutList, describer: CommitDescriberPort) -> dict[str, str]:
    """Run *describer* over each part, returning ``{part.id: subject}`` for the
    parts it could describe. Fail-soft: ``None`` results and any backend exception
    are dropped, so a part simply keeps its deterministic subject."""
    if isinstance(describer, NullDescriber):
        return {}
    subjects: dict[str, str] = {}
    for part in cut.parts:
        request = DescribeRequest(
            prefix=_peel_prefix(part),
            bucket=str(part.bucket),
            files=list(part.files),
            context=_SUMMARY.get(part.bucket, ""),
        )
        try:
            subject = describer.describe(request)
        except Exception as exc:  # noqa: BLE001 — advisory: never break the cut
            logger.debug("describe_part_failed", part=part.id, error=str(exc))
            subject = None
        if subject:
            subjects[part.id] = subject
    return subjects
