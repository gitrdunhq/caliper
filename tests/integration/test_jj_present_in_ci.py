"""Guard: jj MUST be present in the container / CI test environment.

# tested-by: tests/integration/test_jj_present_in_ci.py

The real-jj parting e2e (``tests/integration/test_part_e2e.py``) is skip-if-absent
so local runs without jj still pass. That convenience must never let CI silently
stop exercising real jj. This guard fails loudly if jj is missing in the mandated
test environment (inside the test container, or when ``CI=true``), so the e2e can
never rot back to "skipped" in CI without turning this test red.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def _in_mandated_test_env() -> bool:
    """True inside the test container (where tests are mandated to run) or under CI."""
    in_container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    is_ci = os.environ.get("CI", "").lower() == "true"
    return in_container or is_ci


def test_jj_installed_in_ci_or_container() -> None:
    if not _in_mandated_test_env():
        import pytest

        pytest.skip("not in the container/CI test environment; jj is optional locally")
    assert shutil.which("jj"), (
        "jj is not installed in the test image. The real-jj parting e2e "
        "(tests/integration/test_part_e2e.py) would silently skip in CI. "
        "Add jj to Dockerfile.test."
    )
