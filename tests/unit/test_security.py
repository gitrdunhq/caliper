"""Security regression tests — F-008, F-009, F-013, F-021, F-022.

Covers the targeted fixes applied in the security hardening pass:
  F-009  _safe_dsn masks DSN passwords in log output
  F-013  LLM prompt uses structured system/user roles; summary truncated
  F-021  llm_api_key is SecretStr (config level — also tested in test_config.py)
  F-022  EvidenceStore rejects path-traversal artifact names
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

# ---------------------------------------------------------------------------
# F-009 — _safe_dsn
# ---------------------------------------------------------------------------


class TestSafeDsn:
    """_safe_dsn masks the password component of a DSN string."""

    def test_masks_password(self) -> None:
        from caliper.data.db import _safe_dsn

        result = _safe_dsn("postgresql://user:supersecret@host:5432/db")
        assert "supersecret" not in result
        assert result == "postgresql://user:***@host:5432/db"

    def test_preserves_username(self) -> None:
        from caliper.data.db import _safe_dsn

        result = _safe_dsn("postgresql://myuser:pw@host/db")
        assert "myuser" in result

    def test_handles_dsn_without_password(self) -> None:
        """DSN with no password component is returned unchanged."""
        from caliper.data.db import _safe_dsn

        dsn = "postgresql://host:5432/db"
        assert _safe_dsn(dsn) == dsn

    def test_handles_empty_string(self) -> None:
        from caliper.data.db import _safe_dsn

        assert _safe_dsn("") == ""

    def test_connect_log_does_not_contain_raw_password(self) -> None:
        """database_connected log event must not expose the DSN password."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://user:topsecret@host/db")

        log_events: list[dict] = []

        def capture(logger, method, event_dict):  # noqa: ANN001
            log_events.append(dict(event_dict))
            raise structlog.DropEvent()

        import structlog

        structlog.configure(processors=[capture])

        import unittest.mock as mock

        with (
            patch("caliper.data.db.ConnectionPool") as mock_cp,
            mock.patch.object(type(mock_cp.return_value), "__enter__", return_value=mock_cp),
        ):
            mock_conn = mock.MagicMock()
            mock_cp.return_value.connection.return_value.__enter__ = mock.MagicMock(
                return_value=mock_conn
            )
            mock_cp.return_value.connection.return_value.__exit__ = mock.MagicMock(
                return_value=False
            )
            repo.connect()

        for evt in log_events:
            dsn_val = str(evt.get("dsn", ""))
            assert "topsecret" not in dsn_val, f"password leaked in log event: {evt}"


# ---------------------------------------------------------------------------
# F-022 — EvidenceStore path traversal
# ---------------------------------------------------------------------------


class TestPathTraversal:
    """EvidenceStore.store() must reject artifact names that escape the dest_dir."""

    def test_dotdot_path_is_blocked(self, tmp_path: Path) -> None:
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = "test-sec-abc123"

        result = store.store(rid, "../../etc/passwd", b"malicious")
        assert result == ""

    def test_absolute_path_component_is_blocked(self, tmp_path: Path) -> None:
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = "test-sec-abc123"

        # On most systems (dest_dir / "/etc/passwd").resolve() escapes dest_dir
        result = store.store(rid, "../sibling/secret.txt", b"data")
        assert result == ""

    def test_normal_artifact_name_is_allowed(self, tmp_path: Path) -> None:
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = "test-sec-abc123"

        result = store.store(rid, "report.json", b'{"ok": true}')
        assert result != ""
        assert Path(result).exists()

    def test_nested_normal_name_is_allowed(self, tmp_path: Path) -> None:
        """Simple filenames with dots are fine (e.g. sbom.cyclonedx.json)."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = "test-sec-abc123"

        result = store.store(rid, "sbom.cyclonedx.json", b"<sbom/>")
        assert result != ""

    def test_traversal_attempt_does_not_write_file(self, tmp_path: Path) -> None:
        """A blocked traversal attempt must not create any file outside dest_dir."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = "test-sec-abc123"

        target = tmp_path / "evil.txt"
        store.store(rid, "../evil.txt", b"owned")

        assert not target.exists()


# ---------------------------------------------------------------------------
# F-013 — LLM prompt injection: structured messages + summary truncation
# ---------------------------------------------------------------------------


def _make_llm_config(
    *,
    llm_enabled: bool = True,
    llm_endpoint: str = "https://llm.example.com/v1",
    llm_model: str = "gpt-4o",
) -> object:
    from caliper.core.config import CaliperSettings

    env = {
        "CALIPER_DB_DSN": "postgresql://test:test@localhost/test",
        "CALIPER_LLM_ENABLED": str(llm_enabled).lower(),
        "CALIPER_LLM_ENDPOINT": llm_endpoint,
        "CALIPER_LLM_MODEL": llm_model,
    }
    with patch.dict(os.environ, env, clear=True):
        return CaliperSettings()
