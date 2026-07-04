"""Global test configuration.
# tested-by: (self — pytest infrastructure)

Enforces that tests run inside a container (Docker/Podman).

Maintainer-only escape hatch (#216): bypassing the container requirement takes
BOTH env vars — CALIPER_ALLOW_HOST_TESTS=1 and CALIPER_I_KNOW_HOST_TESTS_LIE=1
— and prints a loud warning. Host runs cannot guarantee parity with CI or other
contributors; a single env var must never be enough to skip that guarantee.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def pytest_configure(config: object) -> None:
    in_container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    if in_container:
        return

    bypass = (
        os.environ.get("CALIPER_ALLOW_HOST_TESTS") == "1"
        and os.environ.get("CALIPER_I_KNOW_HOST_TESTS_LIE") == "1"
    )
    if not bypass:
        raise SystemExit(
            "\n\nERROR: caliper tests must run inside a container.\n"
            "\n"
            "  make test                            # uses podman/docker\n"
            "  bash scripts/build-test.sh -- tests/unit/ -q   # targeted run\n"
            "\n"
            "Maintainer-only escape hatch (results are NOT authoritative):\n"
            "  CALIPER_ALLOW_HOST_TESTS=1 CALIPER_I_KNOW_HOST_TESTS_LIE=1\n"
        )

    print(
        "\n"
        "!!! WARNING: running caliper tests on the HOST (#216).\n"
        "!!! Host results are NOT authoritative — container parity with CI is\n"
        "!!! not guaranteed. Use `make test` before trusting or committing.\n",
        file=sys.stderr,
    )
