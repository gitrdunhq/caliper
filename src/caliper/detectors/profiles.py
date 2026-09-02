"""Detector profiles — which CAL-NNN detectors run by default.
# tested-by: tests/unit/detectors/test_profiles.py

Two profiles, every detector in exactly one (a drift-guard test enforces this):

* ``default`` — general bug patterns any Python service has: SQL injection,
  error exposure, secrets typed as ``str``, subprocess without timeout, ...
* ``house-rules`` — caliper's own engineering conventions (CAL-013 retired with telemetry) (``# tested-by:``
  annotations, pathlib-only path building, atomic writes, rate-limit decorators
  on every route, ...). Correct for this repo, noise for most others; opt in via
  ``detectors.profiles`` in ``.caliper.yaml``.

``resolve_detector_ids`` is the pure boundary: profiles plus ``enable`` minus
``disable``, validated against the registered detector ids so a typo fails loudly
here and the caller can fail open to the default profile.
"""

from __future__ import annotations

DEFAULT_PROFILE = "default"

PROFILES: dict[str, frozenset[str]] = {
    "default": frozenset(
        {
            "CAL-001",  # JWT missing audience claim
            "CAL-002",  # error information exposure
            "CAL-004",  # secret should use SecretStr
            "CAL-005",  # SQL injection via string formatting
            "CAL-006",  # unbounded cache without eviction
            "CAL-010",  # batch insert without rollback handling
            "CAL-012",  # subprocess call without timeout
            "CAL-015",  # high-cardinality metric labels
            "CAL-016",  # CI verification gate bypass
            "CAL-018",  # Dockerfile pin drift
            "CAL-020",  # fixed heredoc delimiter with GITHUB_OUTPUT/GITHUB_ENV
            "CAL-022",  # architecture tier boundary (opt-in by config, fail-open)
            "CAL-023",  # Lambda handler swallows exceptions
            "CAL-024",  # destructive AWS call without dry-run guard
            "CAL-025",  # AWS API call missing required-in-practice argument
            "CAL-026",  # event field guard omits field passed to AWS call
            "CAL-027",  # committed build artifact beside source
        }
    ),
    "house-rules": frozenset(
        {
            "CAL-003",  # API endpoint missing rate limiting
            "CAL-007",  # circuit breaker missing half-open state
            "CAL-008",  # path string concatenation
            "CAL-009",  # cache lookup without freshness check
            "CAL-011",  # health check without database verification
            "CAL-014",  # missing tested-by annotation
            "CAL-017",  # presentation tier imports data tier directly
            "CAL-019",  # nullable advisory_id in dedup key
            "CAL-021",  # non-atomic file write
        }
    ),
}


def resolve_detector_ids(
    profiles: list[str],
    *,
    enable: list[str],
    disable: list[str],
    known: set[str],
) -> list[str]:
    """Return the sorted detector ids selected by *profiles* + *enable* - *disable*.

    Raises ``ValueError`` for an unknown profile or detector id; callers decide
    whether to fail open to :data:`DEFAULT_PROFILE`.
    """
    selected: set[str] = set()
    for name in profiles:
        if name not in PROFILES:
            raise ValueError(f"unknown detector profile {name!r} (known: {sorted(PROFILES)})")
        selected |= PROFILES[name]
    for did in [*enable, *disable]:
        if did not in known:
            raise ValueError(f"unknown detector id {did!r}")
    selected |= set(enable)
    selected -= set(disable)
    return sorted(selected & known)
