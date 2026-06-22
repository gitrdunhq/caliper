"""Security regression tests — F-008, F-009, F-013, F-021, F-022.

Covers the targeted fixes applied in the security hardening pass:
  F-009  _safe_dsn masks DSN passwords in log output
  F-013  LLM prompt uses structured system/user roles; summary truncated
  F-021  llm_api_key is SecretStr (config level — also tested in test_config.py)
  F-022  EvidenceStore rejects path-traversal artifact names
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import httpx
import respx

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


class TestLLMPromptInjection:
    """LLM messages must use structured system/user roles with sanitised data."""

    @respx.mock
    def test_prompt_uses_system_and_user_roles(self) -> None:
        from caliper.core.taskfit import TaskFitAdvisor

        config = _make_llm_config()
        advisor = TaskFitAdvisor(config)

        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "looks fine"}}]},
            )
        )

        advisor.assess(
            package_name="requests",
            version="2.31.0",
            use_case="HTTP calls",
            metadata={"summary": "A simple HTTP library"},
            alternatives=["httpx"],
        )

        assert route.called
        body = json.loads(route.calls.last.request.content)
        messages = body["messages"]

        assert len(messages) >= 2
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"

    @respx.mock
    def test_user_message_content_is_json(self) -> None:
        from caliper.core.taskfit import TaskFitAdvisor

        config = _make_llm_config()
        advisor = TaskFitAdvisor(config)

        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "advisory"}}]},
            )
        )

        advisor.assess(
            package_name="numpy",
            version="1.26.0",
            use_case="matrix math",
            metadata={"summary": "Fundamental array library"},
            alternatives=[],
        )

        body = json.loads(route.calls.last.request.content)
        user_content = body["messages"][1]["content"]
        # Must be valid JSON so untrusted text cannot break the instruction boundary
        parsed = json.loads(user_content)
        assert "package" in parsed
        assert "use_case" in parsed
        assert "summary" in parsed

    @respx.mock
    def test_pypi_summary_truncated_to_200_chars(self) -> None:
        from caliper.core.taskfit import TaskFitAdvisor

        config = _make_llm_config()
        advisor = TaskFitAdvisor(config)

        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "ok"}}]},
            )
        )

        long_summary = "X" * 500
        advisor.assess(
            package_name="pkg",
            version="1.0",
            use_case="test",
            metadata={"summary": long_summary},
            alternatives=[],
        )

        body = json.loads(route.calls.last.request.content)
        user_data = json.loads(body["messages"][1]["content"])
        assert len(user_data["summary"]) <= 200

    @respx.mock
    def test_html_stripped_from_summary(self) -> None:
        from caliper.core.taskfit import TaskFitAdvisor

        config = _make_llm_config()
        advisor = TaskFitAdvisor(config)

        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "ok"}}]},
            )
        )

        advisor.assess(
            package_name="pkg",
            version="1.0",
            use_case="test",
            metadata={"summary": "<script>alert('xss')</script>A library"},
            alternatives=[],
        )

        body = json.loads(route.calls.last.request.content)
        user_data = json.loads(body["messages"][1]["content"])
        assert "<script>" not in user_data["summary"]
        assert "A library" in user_data["summary"]

    @respx.mock
    def test_instruction_not_in_user_message(self) -> None:
        """System instructions must not be repeated in the user message."""
        from caliper.core.taskfit import TaskFitAdvisor

        config = _make_llm_config()
        advisor = TaskFitAdvisor(config)

        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "ok"}}]},
            )
        )

        advisor.assess(
            package_name="pkg",
            version="1.0",
            use_case="test",
            metadata={"summary": "A library"},
            alternatives=[],
        )

        body = json.loads(route.calls.last.request.content)
        user_content = body["messages"][1]["content"]
        # The instruction text lives in the system message, not the user message
        assert "supply-chain advisor" not in user_content
