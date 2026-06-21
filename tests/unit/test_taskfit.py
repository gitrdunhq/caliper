"""Tests for eedom.core.taskfit -- LLM task-fit advisory."""

from __future__ import annotations

import json
import os
from unittest.mock import Mock, patch

import httpx
import pytest
import respx

from eedom.core.config import EedomSettings
from eedom.core.taskfit import TaskFitAdvisor

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    *,
    llm_enabled: bool = False,
    llm_endpoint: str | None = None,
    llm_model: str | None = None,
    llm_api_key: str | None = None,
    llm_timeout: int = 30,
) -> EedomSettings:
    """Build an EedomSettings with controlled LLM fields."""
    env = {
        "EEDOM_DB_DSN": "postgresql://test:test@localhost/test",
        "EEDOM_LLM_ENABLED": str(llm_enabled).lower(),
        "EEDOM_LLM_TIMEOUT": str(llm_timeout),
    }
    if llm_endpoint:
        env["EEDOM_LLM_ENDPOINT"] = llm_endpoint
    if llm_model:
        env["EEDOM_LLM_MODEL"] = llm_model
    if llm_api_key:
        env["EEDOM_LLM_API_KEY"] = llm_api_key

    with patch.dict(os.environ, env, clear=True):
        return EedomSettings()


SAMPLE_METADATA = {"summary": "A fast HTTP client library"}


class TestTaskFitAdvisorDisabled:
    """Tests for when LLM is disabled."""

    def test_disabled_returns_empty_string(self) -> None:
        """When llm_enabled is False, assess returns empty string immediately."""
        config = _make_config(llm_enabled=False)
        advisor = TaskFitAdvisor(config)

        result = advisor.assess(
            package_name="httpx",
            version="0.27.0",
            use_case="HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=["requests"],
        )

        assert result == ""

    def test_missing_endpoint_returns_empty_string(self) -> None:
        """When endpoint is missing, returns empty string even if enabled."""
        config = _make_config(llm_enabled=True, llm_model="gpt-4o")
        advisor = TaskFitAdvisor(config)

        result = advisor.assess(
            package_name="httpx",
            version="0.27.0",
            use_case="HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=[],
        )

        assert result == ""


class TestTaskFitAdvisorEnabled:
    """Tests for when LLM is enabled and configured."""

    @respx.mock
    def test_successful_api_call_returns_advisory(self) -> None:
        """A successful LLM API call returns the advisory text."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
            llm_api_key="sk-test",
        )
        advisor = TaskFitAdvisor(config)

        advisory_text = (
            "NECESSITY:    PASS — No stdlib alternative for async HTTP.\n"
            "MINIMALITY:   PASS — Focused HTTP client.\n"
            "MAINTENANCE:  PASS — Active development.\n"
            "SECURITY:     PASS — Signed releases.\n"
            "EXPOSURE:     CONCERN — Processes untrusted HTTP input.\n"
            "BLAST_RADIUS: PASS — 5 transitive deps.\n"
            "ALTERNATIVES: CONCERN — requests and aiohttp exist.\n"
            "BEHAVIORAL:   PASS — No install scripts.\n\n"
            "RECOMMENDATION: APPROVE — Solid choice for async HTTP."
        )
        respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": advisory_text}}]},
            )
        )

        result = advisor.assess(
            package_name="httpx",
            version="0.27.0",
            use_case="async HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=["requests", "aiohttp"],
        )

        assert result == advisory_text
        assert "RECOMMENDATION: APPROVE" in result

    @respx.mock
    def test_timeout_returns_empty_string(self) -> None:
        """An LLM timeout returns empty string without raising."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
            llm_timeout=1,
        )
        advisor = TaskFitAdvisor(config)

        respx.post("https://llm.example.com/v1/chat/completions").mock(
            side_effect=httpx.ReadTimeout("timed out")
        )

        result = advisor.assess(
            package_name="httpx",
            version="0.27.0",
            use_case="HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=[],
        )

        assert result == ""

    @respx.mock
    def test_api_error_returns_empty_string(self) -> None:
        """A non-200 response from the LLM returns empty string."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
        advisor = TaskFitAdvisor(config)

        respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        result = advisor.assess(
            package_name="httpx",
            version="0.27.0",
            use_case="HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=[],
        )

        assert result == ""

    @respx.mock
    def test_invalid_response_rejected_returns_empty(self) -> None:
        """LLM response that fails validation is rejected after retries."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
        advisor = TaskFitAdvisor(config)

        invalid_text = "This package looks fine to me. I approve it."
        respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": invalid_text}}]},
            )
        )

        result = advisor.assess(
            package_name="httpx",
            version="0.27.0",
            use_case="HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=[],
        )

        assert result == ""

    @respx.mock
    def test_malformed_response_returns_empty_string(self) -> None:
        """A malformed JSON response from the LLM returns empty string."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
        advisor = TaskFitAdvisor(config)

        respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={"choices": []})
        )

        result = advisor.assess(
            package_name="httpx",
            version="0.27.0",
            use_case="HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=[],
        )

        assert result == ""

    # F-013 structured message tests

    @respx.mock
    def test_request_uses_system_and_user_roles(self) -> None:
        """F-013: LLM request must have a system message and a user message."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
        advisor = TaskFitAdvisor(config)

        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "looks good"}}]},
            )
        )

        advisor.assess(
            package_name="requests",
            version="2.31.0",
            use_case="HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=["httpx"],
        )

        body = json.loads(route.calls.last.request.content)
        messages = body["messages"]
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"

    @respx.mock
    def test_user_message_is_json_encoded_data(self) -> None:
        """F-013: User message content must be JSON — not raw interpolated strings."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
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
            metadata={"summary": "Numerical computing"},
            alternatives=[],
        )

        body = json.loads(route.calls.last.request.content)
        user_content = body["messages"][1]["content"]
        # Content must be parseable as JSON
        parsed = json.loads(user_content)
        assert "package" in parsed
        assert "use_case" in parsed
        assert "summary" in parsed

    @respx.mock
    def test_pypi_summary_truncated_to_200_chars_in_request(self) -> None:
        """F-013: PyPI summary embedded in the prompt must not exceed 200 chars."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
        advisor = TaskFitAdvisor(config)

        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "ok"}}]},
            )
        )

        long_summary = "Z" * 500
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
        """F-013: HTML tags in PyPI summary must be stripped before sending."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
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
            metadata={"summary": "<b>Fast</b> library"},
            alternatives=[],
        )

        body = json.loads(route.calls.last.request.content)
        user_data = json.loads(body["messages"][1]["content"])
        assert "<b>" not in user_data["summary"]
        assert "Fast" in user_data["summary"]


class TestCallLlmResponseParsing:
    """F-022: _call_llm must handle malformed response fields without raising.

    Two real bugs in the current code:
    1. ValueError from response.json() is not in the except tuple → propagates.
    2. len(text) is called OUTSIDE the try-except, so a non-string content
       field (e.g. int 123) causes TypeError to escape _call_llm entirely.
    """

    def _make_advisor(self) -> TaskFitAdvisor:
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
        return TaskFitAdvisor(config)

    def _mock_post(self, advisor: TaskFitAdvisor, json_data):
        """Return a context manager that patches advisor._client.post."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = json_data
        return patch.object(advisor._llm._client, "post", return_value=mock_response)

    def test_call_llm_non_string_content_returns_empty(self) -> None:
        """F-022: When 'content' is a non-string (e.g. int), _call_llm must
        return '' — not raise TypeError from len(text) outside the try block.

        RED before fix: len(123) raises TypeError outside the try-except.
        GREEN after fix: isinstance check guards before len().
        """
        advisor = self._make_advisor()
        malformed = {"choices": [{"message": {"content": 123}}]}
        with self._mock_post(advisor, malformed):
            result = advisor._call_llm([{"role": "user", "content": "test"}])
        assert result == ""
        assert isinstance(result, str)

    def test_call_llm_json_decode_error_returns_empty(self) -> None:
        """F-022: When response.json() raises ValueError, _call_llm must
        return '' — not propagate ValueError to the caller.

        RED before fix: ValueError is not in except (KeyError, IndexError, TypeError).
        GREEN after fix: ValueError added to the except clause.
        """
        advisor = self._make_advisor()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        with patch.object(advisor._llm._client, "post", return_value=mock_response):
            result = advisor._call_llm([{"role": "user", "content": "test"}])
        assert result == ""
        assert isinstance(result, str)


class TestTaskFitPackageNameValidation:
    """Package name validation guards in TaskFitAdvisor.assess()."""

    @respx.mock
    def test_empty_package_name_skips_llm(self) -> None:
        """Empty package name must not trigger an LLM call."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
            llm_api_key="sk-test",
        )
        advisor = TaskFitAdvisor(config)
        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "advisory text"}}]},
            )
        )

        result = advisor.assess(
            package_name="",
            version="1.0.0",
            use_case="test",
            metadata=SAMPLE_METADATA,
            alternatives=[],
        )

        assert result == ""
        assert not route.called  # LLM must NOT be called for empty package name

    @respx.mock
    def test_whitespace_only_package_name_skips_llm(self) -> None:
        """Whitespace-only package name must not trigger an LLM call."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
            llm_api_key="sk-test",
        )
        advisor = TaskFitAdvisor(config)
        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "advisory text"}}]},
            )
        )

        result = advisor.assess(
            package_name="   ",
            version="1.0.0",
            use_case="test",
            metadata=SAMPLE_METADATA,
            alternatives=[],
        )

        assert result == ""
        assert not route.called

    @respx.mock
    @pytest.mark.parametrize(
        "bad_name",
        [
            "package with spaces",
            "pkg;rm -rf /",
            "pkg\nmalicious",
            "pkg\x00null",
            "../../../etc/passwd",
        ],
    )
    def test_invalid_package_name_chars_skip_llm(self, bad_name: str) -> None:
        """Package names with invalid chars must not trigger an LLM call."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
            llm_api_key="sk-test",
        )
        advisor = TaskFitAdvisor(config)
        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "advisory text"}}]},
            )
        )

        result = advisor.assess(
            package_name=bad_name,
            version="1.0.0",
            use_case="test",
            metadata=SAMPLE_METADATA,
            alternatives=[],
        )

        assert result == ""
        assert not route.called

    @respx.mock
    def test_valid_package_name_does_call_llm(self) -> None:
        """A valid package name should proceed to the LLM."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
            llm_api_key="sk-test",
        )
        advisor = TaskFitAdvisor(config)

        advisory_text = (
            "NECESSITY:    PASS — Needed.\n"
            "MINIMALITY:   PASS — Minimal.\n"
            "MAINTENANCE:  PASS — Active.\n"
            "SECURITY:     PASS — Good.\n"
            "EXPOSURE:     PASS — Low.\n"
            "BLAST_RADIUS: PASS — Small.\n"
            "ALTERNATIVES: PASS — None.\n"
            "BEHAVIORAL:   PASS — Clean.\n\n"
            "RECOMMENDATION: APPROVE — Good package."
        )
        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": advisory_text}}]},
            )
        )

        result = advisor.assess(
            package_name="valid-package",
            version="1.0.0",
            use_case="test",
            metadata=SAMPLE_METADATA,
            alternatives=[],
        )

        assert route.called  # Valid package name DOES reach the LLM
        assert result == advisory_text
