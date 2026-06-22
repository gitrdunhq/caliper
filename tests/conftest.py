"""Global test configuration.
# tested-by: (self — pytest infrastructure)

Enforces that tests run inside a container (Docker/Podman).
Set CALIPER_ALLOW_HOST_TESTS=1 to bypass (not recommended).
"""

from __future__ import annotations

import os
from pathlib import Path


def pytest_configure(config: object) -> None:
    in_container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    bypass = os.environ.get("CALIPER_ALLOW_HOST_TESTS") == "1"
    if not in_container and not bypass:
        raise SystemExit(
            "\n\nERROR: caliper tests must run inside a container.\n"
            "\n"
            "  make test                            # uses podman/docker\n"
            "  podman run --rm -v .:/workspace:ro caliper:latest pytest tests/ -v\n"
            "\n"
            "Set CALIPER_ALLOW_HOST_TESTS=1 to override (not recommended).\n"
        )
