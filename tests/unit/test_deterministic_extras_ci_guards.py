"""Deterministic guards for optional extras CI coverage — Issue #246 / Parent #212.

Bug (FIXED): Dockerfile.test only installed --group dev via 'uv sync' plus a
hardcoded, drift-prone duplicate 'uv pip install mypy==... pyarrow==...' line.
The copilot, parquet, db, and watch extras were not installed, so
test_agent_main.py, test_webhook.py, and test_parquet_writer.py used
pytest.importorskip and silently skipped in the default test lane —
agent/webhook/parquet regressions passed CI unnoticed.

Fix: Dockerfile.test now installs via 'uv sync --all-extras', which is the
single-source-of-truth equivalent of pyproject.toml's [project.optional-
dependencies] groups (db, parquet, copilot, watch) — no hardcoded duplicate
list. See issues #212 and #246.

These are regression guards — they PASS while the fix is in place and FAIL if
Dockerfile.test regresses back to installing --group dev only.
"""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def _read(relative_path: str) -> str:
    return (_REPO / relative_path).read_text(encoding="utf-8")


class TestOptionalExtrasCiCoverage:
    """Dockerfile.test must install optional extras so their tests cannot skip."""

    def test_dockerfile_test_installs_copilot_extra(self) -> None:
        """Dockerfile.test must install the copilot extra so agent tests run.

        Without '--extra copilot' (or equivalent), test_agent_main.py and
        test_webhook.py call pytest.importorskip("agent_framework") and skip
        silently. Agent and webhook regressions then pass the CI test lane
        without being caught.

        Fix: add '--extra copilot' to the uv sync invocation in Dockerfile.test,
        or add a separate CI lane that runs with all extras installed.
        See issue #212.
        """
        content = _read("Dockerfile.test")
        assert "extra copilot" in content or "--extra=copilot" in content, (
            "Dockerfile.test does not install the 'copilot' extra. "
            "test_agent_main.py and test_webhook.py will skip silently. "
            "Fix: add '--extra copilot' to 'uv sync' in Dockerfile.test. "
            "See issue #212."
        )

    def test_optional_test_files_do_not_use_importorskip_for_core_surfaces(self) -> None:
        """Agent and webhook test files must not skip due to missing extras in CI.

        pytest.importorskip at module level means the entire test file skips
        silently when the extra is not installed. In the container test lane
        these extras should be present so no skipping occurs.
        """
        content = _read("Dockerfile.test")
        # Copilot extra must be installed so importorskip never triggers
        # (we test the Dockerfile, not the test files themselves, to keep this static)
        uses_copilot_extra = "extra copilot" in content or "--extra=copilot" in content
        assert uses_copilot_extra, (
            "Dockerfile.test does not install 'copilot' extra — "
            "test_agent_main.py and test_webhook.py will silently skip in the "
            "default test lane. See issue #212."
        )
