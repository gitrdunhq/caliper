# tested-by: tests/unit/test_solver.py
"""Tests for caliper.core.solver — issue solver with model fallback."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
from pydantic import ValidationError


class TestBuildPrompt:
    def test_includes_issue_number_in_prompt(self) -> None:
        from caliper.core.solver import SolverTask, build_prompt

        task = SolverTask(
            issue_number=236,
            title="OPA bug",
            body="The OPA adapter silently approves.",
        )
        prompt = build_prompt(task)
        assert "#236" in prompt

    def test_includes_title_in_prompt(self) -> None:
        from caliper.core.solver import SolverTask, build_prompt

        task = SolverTask(issue_number=1, title="Bootstrap wires Null adapters", body="desc")
        prompt = build_prompt(task)
        assert "Bootstrap wires Null adapters" in prompt

    def test_includes_source_file_content(self) -> None:
        from caliper.core.solver import SolverTask, build_prompt

        task = SolverTask(
            issue_number=1,
            title="Bug",
            body="desc",
            source_files={"src/caliper/core/bootstrap.py": "def bootstrap(): pass"},
        )
        prompt = build_prompt(task)
        assert "src/caliper/core/bootstrap.py" in prompt
        assert "def bootstrap(): pass" in prompt

    def test_includes_test_file_content(self) -> None:
        from caliper.core.solver import SolverTask, build_prompt

        task = SolverTask(
            issue_number=1,
            title="Bug",
            body="desc",
            test_files={"tests/unit/test_bootstrap.py": "def test_it(): pass"},
        )
        prompt = build_prompt(task)
        assert "tests/unit/test_bootstrap.py" in prompt

    def test_prompt_requests_raw_python_output(self) -> None:
        from caliper.core.solver import SolverTask, build_prompt

        task = SolverTask(issue_number=1, title="Bug", body="desc")
        prompt = build_prompt(task)
        assert "ONLY" in prompt
        assert "Python" in prompt


class TestCleanCode:
    def test_strips_markdown_fences(self) -> None:
        from caliper.core.solver import _clean_code

        raw = "```python\nimport pytest\ndef test_x(): pass\n```"
        result = _clean_code(raw)
        assert result.startswith("import pytest")
        assert "```" not in result

    def test_passes_clean_code_through(self) -> None:
        from caliper.core.solver import _clean_code

        raw = "import pytest\ndef test_x(): pass"
        assert _clean_code(raw) == raw

    def test_strips_prose_before_fence(self) -> None:
        from caliper.core.solver import _clean_code

        raw = "Here is the code:\n```python\nimport pytest\n```"
        result = _clean_code(raw)
        assert "Here is" not in result
        assert result.startswith("import pytest")


class TestLooksLikePython:
    def test_recognizes_valid_test_code(self) -> None:
        from caliper.core.solver import _looks_like_python

        assert _looks_like_python("import pytest\ndef test_foo(): pass") is True

    def test_rejects_empty(self) -> None:
        from caliper.core.solver import _looks_like_python

        assert _looks_like_python("") is False

    def test_rejects_prose(self) -> None:
        from caliper.core.solver import _looks_like_python

        assert _looks_like_python("Here is the solution to your problem.") is False

    def test_rejects_invalid_syntax_with_indicators(self) -> None:
        from caliper.core.solver import _looks_like_python

        assert _looks_like_python("import pytest\ndef test_x(: pass") is False


class TestSolverConfig:
    def test_defaults(self) -> None:
        from caliper.core.solver import SolverConfig

        cfg = SolverConfig()
        assert cfg.endpoint == "https://openrouter.ai/api"
        assert len(cfg.model_ladder) == 3

    def test_model_ladder_starts_with_dense(self) -> None:
        from caliper.core.solver import ModelTier, SolverConfig

        cfg = SolverConfig()
        assert cfg.model_ladder[0].tier == ModelTier.DENSE

    def test_rejects_http_endpoint(self) -> None:
        from caliper.core.solver import SolverConfig

        with pytest.raises(ValidationError, match="endpoint"):
            SolverConfig(endpoint="http://insecure.example.com")

    def test_rejects_negative_delay(self) -> None:
        from caliper.core.solver import SolverConfig

        with pytest.raises(ValidationError):
            SolverConfig(request_delay=-1.0)

    def test_rejects_excessive_retries(self) -> None:
        from caliper.core.solver import SolverConfig

        with pytest.raises(ValidationError):
            SolverConfig(max_retries=100)

    def test_system_prompt_configurable(self) -> None:
        from caliper.core.solver import SolverConfig

        cfg = SolverConfig(system_prompt="Custom prompt")
        assert cfg.system_prompt == "Custom prompt"

    def test_system_prompt_has_default(self) -> None:
        from caliper.core.solver import SolverConfig

        cfg = SolverConfig()
        assert "test engineer" in cfg.system_prompt


class TestSolverTask:
    def test_rejects_zero_issue_number(self) -> None:
        from caliper.core.solver import SolverTask

        with pytest.raises(ValidationError):
            SolverTask(issue_number=0, title="Bug", body="desc")

    def test_rejects_empty_title(self) -> None:
        from caliper.core.solver import SolverTask

        with pytest.raises(ValidationError):
            SolverTask(issue_number=1, title="", body="desc")

    def test_truncates_large_source_files(self) -> None:
        from caliper.core.solver import SolverTask

        huge = "x" * 100_000
        task = SolverTask(
            issue_number=1,
            title="Bug",
            body="desc",
            source_files={"big.py": huge},
        )
        assert len(task.source_files["big.py"]) == 50_000


class TestSolverResult:
    def test_failed_result_has_error(self) -> None:
        from caliper.core.solver import SolverResult, TaskStatus

        r = SolverResult(issue_number=1, status=TaskStatus.FAILED, error="All models exhausted")
        assert r.status == TaskStatus.FAILED
        assert r.error != ""

    def test_success_result_has_code(self) -> None:
        from caliper.core.solver import SolverResult, TaskStatus

        r = SolverResult(
            issue_number=1,
            status=TaskStatus.SUCCESS,
            model_used="google/gemma-3-27b-it:free",
            code="import pytest\ndef test_x(): pass",
        )
        assert r.status == TaskStatus.SUCCESS
        assert "def test_" in r.code

    def test_rejects_negative_attempts(self) -> None:
        from caliper.core.solver import SolverResult, TaskStatus

        with pytest.raises(ValidationError):
            SolverResult(issue_number=1, status=TaskStatus.FAILED, attempts=-1)

    def test_flagged_patterns_field_exists(self) -> None:
        from caliper.core.solver import SolverResult, TaskStatus

        r = SolverResult(
            issue_number=1,
            status=TaskStatus.SUCCESS,
            flagged_patterns=["dangerous at char 10"],
        )
        assert len(r.flagged_patterns) == 1


class TestOpenRouterResponse:
    def test_parses_valid_response(self) -> None:
        from caliper.core.solver import OpenRouterResponse

        data = {
            "id": "gen-123",
            "choices": [{"message": {"content": "import pytest"}, "finish_reason": "stop"}],
            "model": "google/gemma-3-27b-it:free",
        }
        resp = OpenRouterResponse.model_validate(data)
        assert resp.choices[0].message["content"] == "import pytest"

    def test_rejects_empty_choices(self) -> None:
        from caliper.core.solver import OpenRouterResponse

        with pytest.raises(ValidationError):
            OpenRouterResponse.model_validate({"choices": []})

    def test_rejects_missing_choices(self) -> None:
        from caliper.core.solver import OpenRouterResponse

        with pytest.raises(ValidationError):
            OpenRouterResponse.model_validate({"id": "x"})


class TestSanitizeCode:
    def test_flags_dangerous_patterns(self) -> None:
        from caliper.core.solver import _sanitize_code

        danger = "import os\nos" + ".system('ls')"
        _, flags = _sanitize_code(danger)
        assert len(flags) > 0

    def test_flags_code_execution(self) -> None:
        from caliper.core.solver import _sanitize_code

        danger = "result = ev" + "al(user_input)"
        _, flags = _sanitize_code(danger)
        assert len(flags) > 0

    def test_clean_code_has_no_flags(self) -> None:
        from caliper.core.solver import _sanitize_code

        code, flags = _sanitize_code("import pytest\ndef test_x(): assert True")
        assert flags == []
        assert "def test_x" in code

    def test_strips_markdown_fences(self) -> None:
        from caliper.core.solver import _sanitize_code

        code, _ = _sanitize_code("```python\nimport pytest\n```")
        assert "```" not in code

    def test_truncates_oversized_output(self) -> None:
        from caliper.core.solver import _MAX_CODE_LENGTH, _sanitize_code

        huge = "x = 1\n" * 100_000
        code, _ = _sanitize_code(huge)
        assert len(code) <= _MAX_CODE_LENGTH

    def test_no_false_positive_on_execute(self) -> None:
        from caliper.core.solver import _sanitize_code

        code = "def execute_query(): pass"
        _, flags = _sanitize_code(code)
        assert flags == []


class TestExtractRateLimit:
    def test_returns_wait_when_remaining_low(self) -> None:
        from caliper.core.solver import _extract_rate_limit

        headers = httpx.Headers({"x-ratelimit-remaining": "1", "x-ratelimit-reset": "9999999999"})
        wait = _extract_rate_limit(headers)
        assert wait is not None
        assert wait > 0

    def test_returns_none_when_remaining_high(self) -> None:
        from caliper.core.solver import _extract_rate_limit

        headers = httpx.Headers({"x-ratelimit-remaining": "50", "x-ratelimit-reset": "9999999999"})
        assert _extract_rate_limit(headers) is None

    def test_returns_none_when_headers_missing(self) -> None:
        from caliper.core.solver import _extract_rate_limit

        headers = httpx.Headers({})
        assert _extract_rate_limit(headers) is None

    def test_handles_malformed_header_values(self) -> None:
        from caliper.core.solver import _extract_rate_limit

        headers = httpx.Headers({"x-ratelimit-remaining": "abc", "x-ratelimit-reset": "def"})
        assert _extract_rate_limit(headers) is None

    def test_caps_wait_at_max(self) -> None:
        from caliper.core.solver import _MAX_RATE_LIMIT_WAIT_S, _extract_rate_limit

        headers = httpx.Headers({"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"})
        wait = _extract_rate_limit(headers)
        assert wait is not None
        assert wait <= _MAX_RATE_LIMIT_WAIT_S


class TestModelSpec:
    def test_rejects_empty_id(self) -> None:
        from caliper.core.solver import ModelSpec, ModelTier

        with pytest.raises(ValidationError):
            ModelSpec(id="", tier=ModelTier.DENSE)

    def test_rejects_zero_context_window(self) -> None:
        from caliper.core.solver import ModelSpec, ModelTier

        with pytest.raises(ValidationError):
            ModelSpec(id="test/model", tier=ModelTier.DENSE, context_window=0)


class TestBackoff:
    def test_caps_at_max(self) -> None:
        from caliper.core.solver import _MAX_BACKOFF_S, _backoff

        result = _backoff(20, multiplier=5.0)
        assert result == _MAX_BACKOFF_S

    def test_grows_exponentially(self) -> None:
        from caliper.core.solver import _backoff

        assert _backoff(0) == 1.0
        assert _backoff(1) == 2.0
        assert _backoff(2) == 4.0


class TestAtomicWrite:
    def test_writes_file_atomically(self, tmp_path: Path) -> None:
        from caliper.core.solver import _atomic_write

        target = tmp_path / "output.py"
        _atomic_write(target, "import pytest\n")
        assert target.read_text(encoding="utf-8") == "import pytest\n"
        assert not target.with_suffix(".tmp").exists()


class TestSolve:
    """Tests for solve() — the core public function."""

    def _make_task(self, issue: int = 1):
        from caliper.core.solver import SolverTask

        return SolverTask(issue_number=issue, title="Test bug", body="Fix this bug")

    def _make_config(self, **kwargs):
        from caliper.core.solver import ModelSpec, ModelTier, SolverConfig

        defaults = {
            "api_key": "sk-test-key",
            "max_retries": 1,
            "model_ladder": [
                ModelSpec(id="test/model-a", tier=ModelTier.DENSE),
                ModelSpec(id="test/model-b", tier=ModelTier.MOE),
            ],
        }
        defaults.update(kwargs)
        return SolverConfig(**defaults)

    def _mock_response(self, code: str = "import pytest\ndef test_x(): pass") -> MagicMock:
        import orjson

        mock = MagicMock(spec=httpx.Client)
        resp = MagicMock()
        resp.text = orjson.dumps(
            {"id": "x", "choices": [{"message": {"content": code}}], "model": "test"}
        ).decode()
        resp.status_code = 200
        resp.headers = httpx.Headers({})
        mock.post.return_value = resp
        return mock

    def test_success_on_first_model(self) -> None:
        from caliper.core.solver import TaskStatus, solve

        client = self._mock_response()
        result = solve(self._make_task(), self._make_config(), client=client)
        assert result.status == TaskStatus.SUCCESS
        assert "def test_x" in result.code
        assert client.post.call_count == 1

    def test_fallback_to_second_model_on_api_error(self) -> None:
        from caliper.core.solver import TaskStatus, solve

        client = self._mock_response()
        resp_fail = MagicMock()
        resp_fail.text = "error"
        resp_fail.status_code = 400
        resp_fail.headers = httpx.Headers({})

        client.post.side_effect = [resp_fail, client.post.return_value]
        result = solve(self._make_task(), self._make_config(), client=client)
        assert result.status == TaskStatus.SUCCESS
        assert result.attempts == 2

    def test_all_models_exhausted_returns_failed(self) -> None:
        from caliper.core.solver import TaskStatus, solve

        client = MagicMock(spec=httpx.Client)
        resp = MagicMock()
        resp.text = "error"
        resp.status_code = 400
        resp.headers = httpx.Headers({})
        client.post.return_value = resp

        result = solve(self._make_task(), self._make_config(), client=client)
        assert result.status == TaskStatus.FAILED
        assert "exhausted" in result.error

    def test_empty_api_key_returns_failed(self) -> None:
        from caliper.core.solver import TaskStatus, solve

        config = self._make_config(api_key="")
        result = solve(self._make_task(), config)
        assert result.status == TaskStatus.FAILED
        assert "api_key" in result.error

    def test_dangerous_code_returns_failed(self) -> None:
        from caliper.core.solver import TaskStatus, solve

        dangerous = "import os\nos" + ".system('rm -rf /')\ndef test_x(): pass"
        client = self._mock_response(code=dangerous)
        result = solve(self._make_task(), self._make_config(), client=client)
        assert result.status == TaskStatus.FAILED
        assert len(result.flagged_patterns) > 0

    def test_invalid_python_falls_through(self) -> None:
        from caliper.core.solver import TaskStatus, solve

        client = self._mock_response(code="This is just prose, not code at all.")
        result = solve(self._make_task(), self._make_config(), client=client)
        assert result.status == TaskStatus.FAILED

    def test_timeout_retries(self) -> None:
        from caliper.core.solver import TaskStatus, solve

        client = self._mock_response()
        client.post.side_effect = [
            httpx.TimeoutException("timed out"),
            client.post.return_value,
        ]
        config = self._make_config(
            max_retries=2,
            model_ladder=[
                __import__("caliper.core.solver", fromlist=["ModelSpec"]).ModelSpec(
                    id="test/model", tier="dense"
                )
            ],
        )
        with patch("caliper.core.solver.time.sleep"):
            result = solve(self._make_task(), config, client=client)
        assert result.status == TaskStatus.SUCCESS


class TestSolveBatch:
    """Tests for solve_batch() — batch orchestration."""

    def _make_task(self, issue: int = 1):
        from caliper.core.solver import SolverTask

        return SolverTask(issue_number=issue, title="Bug", body="desc")

    def _make_config(self, tmp_path: Path):
        from caliper.core.solver import ModelSpec, ModelTier, SolverConfig

        return SolverConfig(
            api_key="sk-test",
            output_dir=str(tmp_path),
            request_delay=0.0,
            max_retries=1,
            model_ladder=[ModelSpec(id="test/m", tier=ModelTier.DENSE)],
        )

    def test_on_result_called_per_task(self, tmp_path: Path) -> None:
        from caliper.core.solver import solve_batch

        callbacks = []
        config = self._make_config(tmp_path)

        with patch("caliper.core.solver.solve") as mock_solve:
            from caliper.core.solver import SolverResult, TaskStatus

            mock_solve.return_value = SolverResult(
                issue_number=1, status=TaskStatus.FAILED, error="test"
            )
            solve_batch(
                [self._make_task(1), self._make_task(2)],
                config,
                on_result=callbacks.append,
            )
        assert len(callbacks) == 2

    def test_callback_failure_does_not_kill_batch(self, tmp_path: Path) -> None:
        from caliper.core.solver import solve_batch

        config = self._make_config(tmp_path)

        def bad_callback(r):
            raise RuntimeError("callback boom")

        with patch("caliper.core.solver.solve") as mock_solve:
            from caliper.core.solver import SolverResult, TaskStatus

            mock_solve.return_value = SolverResult(
                issue_number=1, status=TaskStatus.FAILED, error="test"
            )
            results = solve_batch(
                [self._make_task(1), self._make_task(2)],
                config,
                on_result=bad_callback,
            )
        assert len(results) == 2

    def test_writes_success_results_to_disk(self, tmp_path: Path) -> None:
        from caliper.core.solver import solve_batch

        config = self._make_config(tmp_path)

        with patch("caliper.core.solver.solve") as mock_solve:
            from caliper.core.solver import SolverResult, TaskStatus

            mock_solve.return_value = SolverResult(
                issue_number=42,
                status=TaskStatus.SUCCESS,
                code="import pytest\ndef test_x(): pass",
            )
            solve_batch([self._make_task(42)], config)

        out_file = tmp_path / "test_detector_42.py"
        assert out_file.exists()
        assert "def test_x" in out_file.read_text()
