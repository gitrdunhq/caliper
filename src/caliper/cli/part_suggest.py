"""Tier-suggester composition edge — resolve a backend and run it over a cut.

# tested-by: tests/unit/test_part_suggest.py

The imperative shell for the advisory tier suggester (DPS-101). The pure boundary
(``core.tier_suggester.validate_suggestions``) decides what survives; this module
performs the side-effecting model call and feeds the boundary. Everything here is
fail-soft — a missing, disabled, or unreachable backend yields ``[]`` and the residual
keeps its ``logic`` label. Suggester config is read from env, deliberately NOT from
``PartingConfig``, so it never enters ``config_digest``; only the *accepted* globs that
a reviewer writes to ``.caliper.yaml`` change provenance.
"""

from __future__ import annotations

from collections.abc import Mapping

import structlog

from caliper.core.models import ChangeType, CutList
from caliper.core.repo_config import OverrideRule
from caliper.core.tier_suggester import (
    NullSuggester,
    ResidualFile,
    SuggestRequest,
    TierSuggesterPort,
    validate_suggestions,
)
from caliper.data.openai_suggester import OpenAICompatSuggester, SuggesterConfig

logger = structlog.get_logger(__name__)

# Explicit opt-out values for CALIPER_SUGGESTER.
_DISABLED = {"0", "off", "false", "no"}


def suggester_from_env(env: Mapping[str, str], *, force: bool | None = None) -> TierSuggesterPort:
    """Resolve a suggester from environment, honouring an optional CLI override.

    ``force`` is the tri-state ``--suggest/--no-suggest`` flag: ``False`` forces the
    deterministic path, ``True`` forces the model on (still fail-soft), ``None`` follows
    env. A backend is only built when both a model and a base URL resolve — otherwise
    the fail-soft :class:`NullSuggester` keeps the residual untiered with zero network
    calls. The model id falls back to the describer's, so one local config drives both.
    """
    if force is False:
        return NullSuggester()
    if force is None and env.get("CALIPER_SUGGESTER", "").strip().lower() in _DISABLED:
        return NullSuggester()

    model = (
        env.get("CALIPER_SUGGESTER_MODEL", "").strip()
        or env.get("CALIPER_DESCRIBER_MODEL", "").strip()
    )
    base_url = _resolve_base_url(env)
    if not model or not base_url:
        return NullSuggester()

    api_key = env.get("CALIPER_SUGGESTER_API_KEY") or env.get("OMLX_API_KEY") or ""
    try:
        timeout = float(env.get("CALIPER_SUGGESTER_TIMEOUT") or 30)
    except ValueError:
        timeout = 30.0
    return OpenAICompatSuggester(
        SuggesterConfig(base_url=base_url, model=model, api_key=api_key, timeout=timeout)
    )


def _resolve_base_url(env: Mapping[str, str]) -> str:
    """Prefer an explicit URL, then a bare Ollama host, then a running OMLX server.

    Reuses the describer's env names so a single local-model setup serves both passes.
    """
    explicit = (
        env.get("CALIPER_SUGGESTER_BASE_URL", "").strip()
        or env.get("CALIPER_DESCRIBER_BASE_URL", "").strip()
    )
    if explicit:
        return explicit
    ollama = env.get("OLLAMA_HOST", "").strip()
    if ollama:
        return ollama.rstrip("/") + "/v1"
    return env.get("OMLX_BASE_URL", "").strip()


def suggest_overrides(
    cut: CutList,
    suggester: TierSuggesterPort,
    *,
    existing_overrides: list[OverrideRule],
) -> list[OverrideRule]:
    """Propose validated ``OverrideRule`` entries for the cut's ``logic`` residual.

    Pulls the residual (and the already-tiered paths) straight from the cut, asks the
    backend, and runs the proposals through the core boundary — so a surviving glob is
    guaranteed to touch only residual files. Fail-soft: ``NullSuggester`` short-circuits,
    and any backend exception is swallowed to ``[]`` (the cut is never broken).
    """
    if isinstance(suggester, NullSuggester):
        return []

    residual = [f for p in cut.parts if p.bucket is ChangeType.logic for f in p.files]
    if not residual:
        return []
    tiered = [f for p in cut.parts if p.bucket is not ChangeType.logic for f in p.files]

    request = SuggestRequest(residual=[ResidualFile(path=f, size=0) for f in residual])
    try:
        raw = suggester.suggest(request)
    except Exception as exc:  # noqa: BLE001 — advisory: never break the cut
        logger.debug("suggest_overrides_failed", error=str(exc))
        return []

    return validate_suggestions(
        raw,
        residual=residual,
        tiered=tiered,
        existing_globs={o.glob for o in existing_overrides},
    )
