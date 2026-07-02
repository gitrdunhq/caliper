"""Distribution-name → import-name resolution (ADR-009).

# tested-by: tests/unit/test_import_resolution.py

A vulnerability finding's ``package`` field holds a distribution name (PyPI/npm/etc.),
but the code graph indexes import statements, which use the *import* name — frequently
a different string (``PyYAML`` → ``yaml``, ``beautifulsoup4`` → ``bs4``). Resolution is
three-step and deterministic: a small curated map for the well-known divergent cases,
an ``importlib.metadata`` lookup (best-effort — only useful when the scanned
dependency happens to also be installed in caliper's own venv), then a mechanical
lowercase/underscore heuristic that covers the common case. Returns ``None`` only when
none of the three produce a valid identifier — the caller must treat that as "unknown,"
never as evidence of absence.
"""

from __future__ import annotations

import importlib.metadata

_CURATED_MAP = {
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "pillow": "PIL",
    "python-dateutil": "dateutil",
    "protobuf": "google",
    "scikit-learn": "sklearn",
    "opencv-python": "cv2",
    "opencv-python-headless": "cv2",
    "msgpack-python": "msgpack",
    "python-jose": "jose",
    "python-multipart": "multipart",
    "python-dotenv": "dotenv",
    "pyjwt": "jwt",
    "pycryptodome": "Crypto",
    "grpcio": "grpc",
    "attrs": "attr",
    "django-rest-framework": "rest_framework",
    "djangorestframework": "rest_framework",
}


def _from_metadata(distribution_name: str) -> str | None:
    try:
        dist = importlib.metadata.distribution(distribution_name)
        top_level = dist.read_text("top_level.txt")
    except Exception:
        return None
    if not top_level:
        return None
    first = top_level.strip().splitlines()[0].strip()
    return first or None


def resolve_import_name(package_name: str) -> str | None:
    """Best-effort distribution-name -> import-name resolution. None means unknown."""
    if not package_name:
        return None
    normalized = package_name.strip().lower()
    if not normalized:
        return None

    if normalized in _CURATED_MAP:
        return _CURATED_MAP[normalized]

    from_metadata = _from_metadata(package_name)
    if from_metadata:
        return from_metadata

    heuristic = normalized.replace("-", "_").replace(".", "_")
    if heuristic.isidentifier():
        return heuristic

    return None
