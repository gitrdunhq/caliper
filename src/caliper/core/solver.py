# tested-by: tests/unit/test_solver.py
"""Issue solver — generates detector tests via LLM with model fallback.

API-style module for automated issue resolution. Reads GitHub issue context,
builds scoped prompts, sends to OpenRouter-compatible endpoints with rate-limit
aware sequential processing and model fallback ladder.

All boundary contracts use Pydantic models. LLM output is untrusted input
and is validated + sanitized before use. Flagged dangerous patterns cause
task FAILURE — detection IS enforcement.

Public interface:
  - SolverConfig     — model ladder, rate limits, endpoint
  - SolverTask       — structured task from a GitHub issue
  - SolverResult     — result from model (code + metadata)
  - solve()          — process a single task
  - solve_batch()    — process multiple tasks sequentially with rate limiting
"""

from __future__ import annotations

import ast
import os
import re
import time
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path

import httpx
import orjson
import structlog
from pydantic import BaseModel, Field, field_validator, model_validator

logger = structlog.get_logger()

_MAX_CODE_LENGTH = 50_000
_MAX_FILE_SIZE = 50_000
_MAX_PROMPT_LENGTH = 200_000
_MAX_BACKOFF_S = 120.0
_MAX_RATE_LIMIT_WAIT_S = 300.0
_DANGEROUS_PATTERNS = re.compile(
    r"\bos\.system\("
    r"|\bsubprocess\.(?:call|run|Popen|check_output|check_call)\(.*shell\s*=\s*True"
    r"|\b__import__\("
    r"|\bexec\("
    r"|\beval\("
    r"|\bpickle\.(?:load|loads)\("
    r"|\byaml\.load\("
    r"|\bshutil\.rmtree\("
    r"|\bimportlib\.import_module\(",
    re.DOTALL,
)


class ModelTier(StrEnum):
    DENSE = "dense"
    MOE = "moe"
    MOE_LARGE = "moe_large"


class ModelSpec(BaseModel):
    id: str = Field(min_length=1)
    tier: ModelTier
    context_window: int = Field(default=32_000, gt=0)
    max_output: int = Field(default=8_000, gt=0)


DEFAULT_MODEL_LADDER: list[ModelSpec] = [
    ModelSpec(
        id="google/gemma-3-27b-it:free",
        tier=ModelTier.DENSE,
        context_window=96_000,
    ),
    ModelSpec(
        id="qwen/qwen3-235b-a22b:free",
        tier=ModelTier.MOE,
        context_window=40_000,
    ),
    ModelSpec(
        id="mistralai/devstral-small:free",
        tier=ModelTier.MOE_LARGE,
        context_window=128_000,
    ),
]

_DEFAULT_SYSTEM_PROMPT = """\
You are a senior test engineer writing deterministic detection tests for known \
bugs in a Python codebase called caliper (Caliper — a CI code review tool).

Your output is ONLY raw Python code. No markdown, no code fences, no explanation.
Start with imports. End with the last test function.

Conventions you MUST follow:
- pytest as the test framework
- structlog for logging (never print)
- Typed annotations on all functions
- One test class per detection rule, named Test{BugDescription}
- Each test must FAIL on the current buggy code (RED phase)
- Use unittest.mock for isolation, never hit real APIs or filesystem
- Descriptive test names: test_{what}_{condition}_{expected}
- Add a module docstring: "Detector test for issue #{number}"
"""


class SolverConfig(BaseModel):
    endpoint: str = Field(default="https://openrouter.ai/api", pattern=r"^https://")
    api_key: str = ""
    model_ladder: list[ModelSpec] = Field(default_factory=lambda: list(DEFAULT_MODEL_LADDER))
    output_dir: str = ".temp/solver-results"
    request_delay: float = Field(default=2.0, ge=0.0)
    max_retries: int = Field(default=3, ge=1, le=5)
    timeout: int = Field(default=120, ge=5, le=600)
    system_prompt: str = Field(default=_DEFAULT_SYSTEM_PROMPT)

    @model_validator(mode="after")
    def validate_api_key_when_needed(self) -> SolverConfig:
        return self


class TaskStatus(StrEnum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"


class SolverTask(BaseModel):
    issue_number: int = Field(gt=0)
    title: str = Field(min_length=1, max_length=500)
    body: str = Field(max_length=200_000)
    group: str = ""
    source_files: dict[str, str] = Field(default_factory=dict)
    test_files: dict[str, str] = Field(default_factory=dict)

    @field_validator("source_files", "test_files")
    @classmethod
    def truncate_large_files(cls, v: dict[str, str]) -> dict[str, str]:
        return {k: content[:_MAX_FILE_SIZE] for k, content in v.items()}


class SolverResult(BaseModel):
    issue_number: int = Field(gt=0)
    status: TaskStatus
    model_used: str = ""
    code: str = Field(default="", max_length=_MAX_CODE_LENGTH)
    error: str = ""
    attempts: int = Field(default=0, ge=0)
    duration_s: float = Field(default=0.0, ge=0.0)
    flagged_patterns: list[str] = Field(default_factory=list)


class OpenRouterRequest(BaseModel):
    model: str = Field(min_length=1)
    max_tokens: int = Field(gt=0)
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    messages: list[dict[str, str]]


class OpenRouterChoice(BaseModel):
    message: dict[str, str]
    finish_reason: str | None = None


class OpenRouterResponse(BaseModel):
    id: str = ""
    choices: list[OpenRouterChoice] = Field(min_length=1)
    model: str = ""
    usage: dict[str, int] | None = None


_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_PYTHON_INDICATORS = ("import ", "def test_", "class Test", "from ", "assert ")


def build_prompt(task: SolverTask) -> str:
    sections = [f"# Issue #{task.issue_number}: {task.title}\n\n{task.body}"]

    if task.source_files:
        sections.append("# Source Files Under Test")
        for path, content in task.source_files.items():
            sections.append(f"\n## {path}\n```python\n{content}\n```")

    if task.test_files:
        sections.append("# Existing Tests (match these conventions)")
        for path, content in task.test_files.items():
            truncated = "\n".join(content.split("\n")[:80])
            sections.append(f"\n## {path}\n```python\n{truncated}\n```")

    sections.append(
        "# Task\n\n"
        f"Write a pytest test module that detects the bug in issue "
        f"#{task.issue_number}.\n\n"
        "Requirements:\n"
        "1. The test MUST fail on the current codebase (RED phase)\n"
        "2. The test verifies the specific behavior described in the bug\n"
        "3. Use mock/patch to isolate from external dependencies\n"
        "4. Match the test conventions shown in existing tests above\n"
        "5. Include: # tested-by: tests/unit/test_detector_{issue}.py\n\n"
        "Output ONLY the Python code. No markdown, no explanation."
    )

    prompt = "\n\n".join(sections)
    if len(prompt) > _MAX_PROMPT_LENGTH:
        prompt = prompt[:_MAX_PROMPT_LENGTH]
        logger.warning(
            "solver.prompt_truncated",
            issue=task.issue_number,
            length=_MAX_PROMPT_LENGTH,
        )
    return prompt


def _extract_rate_limit(headers: httpx.Headers) -> float | None:
    remaining = headers.get("x-ratelimit-remaining")
    reset = headers.get("x-ratelimit-reset")
    if remaining is None or reset is None:
        return None
    try:
        if int(remaining) < 2:
            wait = max(0, int(reset) - int(time.time()))
            return float(min(wait + 1, _MAX_RATE_LIMIT_WAIT_S))
    except ValueError:
        return None
    return None


def _sanitize_code(raw: str) -> tuple[str, list[str]]:
    code = _clean_code(raw)
    if len(code) > _MAX_CODE_LENGTH:
        code = code[:_MAX_CODE_LENGTH]

    flags: list[str] = []
    for match in _DANGEROUS_PATTERNS.finditer(code):
        flags.append(f"dangerous pattern at char {match.start()}: {match.group()}")

    return code, flags


def _backoff(retry: int, multiplier: float = 1.0) -> float:
    return min(2.0**retry * multiplier, _MAX_BACKOFF_S)


def _post(
    client: httpx.Client,
    url: str,
    api_key: str,
    model: str,
    system: str,
    user: str,
    max_tokens: int,
    timeout: int,
) -> tuple[str, int, httpx.Headers]:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/gitrdunhq/caliper",
        "X-Title": "caliper-solver",
    }
    request = OpenRouterRequest(
        model=model,
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    resp = client.post(
        url,
        json=request.model_dump(),
        headers=headers,
        timeout=httpx.Timeout(timeout, connect=10.0),
    )
    return resp.text, resp.status_code, resp.headers


def _parse_response(raw: str) -> OpenRouterResponse:
    data = orjson.loads(raw)
    return OpenRouterResponse.model_validate(data)


def _try_model(
    client: httpx.Client,
    model_spec: ModelSpec,
    prompt: str,
    config: SolverConfig,
    issue_number: int,
) -> tuple[SolverResult | None, int]:
    """Try a single model with retries. Returns (result, attempts)."""
    url = f"{config.endpoint}/v1/chat/completions"
    attempts = 0

    for retry in range(config.max_retries):
        attempts += 1
        try:
            raw, status_code, resp_headers = _post(
                client=client,
                url=url,
                api_key=config.api_key,
                model=model_spec.id,
                system=config.system_prompt,
                user=prompt,
                max_tokens=model_spec.max_output,
                timeout=config.timeout,
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "solver.request_error",
                issue=issue_number,
                model=model_spec.id,
                error=str(exc),
                attempt=attempts,
            )
            if retry < config.max_retries - 1:
                time.sleep(_backoff(retry))
            continue

        if status_code == 429:
            wait = _extract_rate_limit(resp_headers) or _backoff(retry, multiplier=5.0)
            logger.warning(
                "solver.rate_limited",
                issue=issue_number,
                model=model_spec.id,
                wait_s=wait,
            )
            if retry < config.max_retries - 1:
                time.sleep(wait)
            continue

        if status_code in _RETRYABLE_STATUS:
            logger.warning(
                "solver.retryable",
                issue=issue_number,
                model=model_spec.id,
                status=status_code,
                attempt=attempts,
            )
            if retry < config.max_retries - 1:
                time.sleep(_backoff(retry))
            continue

        if status_code != 200:
            logger.warning(
                "solver.api_error",
                issue=issue_number,
                model=model_spec.id,
                status=status_code,
            )
            return None, attempts

        try:
            response = _parse_response(raw)
            raw_code = response.choices[0].message.get("content", "")
        except (orjson.JSONDecodeError, KeyError, IndexError) as exc:
            logger.warning(
                "solver.parse_error",
                issue=issue_number,
                model=model_spec.id,
                error=f"{type(exc).__name__}: {exc}",
            )
            if retry < config.max_retries - 1:
                time.sleep(_backoff(retry))
            continue
        except Exception as exc:
            logger.warning(
                "solver.parse_error_unexpected",
                issue=issue_number,
                model=model_spec.id,
                error=f"{type(exc).__name__}: {exc}",
            )
            return None, attempts

        code, flags = _sanitize_code(raw_code)

        if flags:
            logger.warning(
                "solver.dangerous_patterns_blocked",
                issue=issue_number,
                model=model_spec.id,
                flags=flags,
            )
            return (
                SolverResult(
                    issue_number=issue_number,
                    status=TaskStatus.FAILED,
                    model_used=model_spec.id,
                    error=f"Dangerous patterns detected: {flags}",
                    attempts=attempts,
                    flagged_patterns=flags,
                ),
                attempts,
            )

        if not _looks_like_python(code):
            logger.warning(
                "solver.invalid_output",
                issue=issue_number,
                model=model_spec.id,
                preview=code[:100],
            )
            return None, attempts

        return (
            SolverResult(
                issue_number=issue_number,
                status=TaskStatus.SUCCESS,
                model_used=model_spec.id,
                code=code,
                attempts=attempts,
            ),
            attempts,
        )

    return None, attempts


def solve(
    task: SolverTask,
    config: SolverConfig,
    client: httpx.Client | None = None,
) -> SolverResult:
    """Solve a single task, trying each model in the ladder."""
    if not config.api_key:
        return SolverResult(
            issue_number=task.issue_number,
            status=TaskStatus.FAILED,
            error="api_key is empty",
        )

    start = time.monotonic()
    prompt = build_prompt(task)
    total_attempts = 0
    owns_client = client is None

    if owns_client:
        client = httpx.Client()

    try:
        for model_spec in config.model_ladder:
            result, attempts = _try_model(client, model_spec, prompt, config, task.issue_number)
            total_attempts += attempts

            if result is not None:
                result.attempts = total_attempts
                result.duration_s = round(time.monotonic() - start, 1)
                if result.status == TaskStatus.SUCCESS:
                    logger.info(
                        "solver.success",
                        issue=task.issue_number,
                        model=result.model_used,
                        code_lines=result.code.count("\n") + 1,
                        duration_s=result.duration_s,
                    )
                return result
    finally:
        if owns_client:
            client.close()

    duration = time.monotonic() - start
    return SolverResult(
        issue_number=task.issue_number,
        status=TaskStatus.FAILED,
        error="All models exhausted",
        attempts=total_attempts,
        duration_s=round(duration, 1),
    )


def _atomic_write(path: Path, content: str) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def solve_batch(
    tasks: list[SolverTask],
    config: SolverConfig,
    on_result: Callable[[SolverResult], None] | None = None,
) -> list[SolverResult]:
    """Process tasks sequentially with rate-limit pacing.

    Calls on_result(result) after each task if provided (webhook hook).
    """
    results: list[SolverResult] = []
    out_dir = Path(config.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with httpx.Client() as client:
        for i, task in enumerate(tasks):
            logger.info(
                "solver.batch_progress",
                current=i + 1,
                total=len(tasks),
                issue=task.issue_number,
            )

            result = solve(task, config, client=client)
            results.append(result)

            if result.status == TaskStatus.SUCCESS:
                out_path = out_dir / f"test_detector_{task.issue_number}.py"
                try:
                    _atomic_write(out_path, result.code)
                    logger.info("solver.wrote_file", path=str(out_path))
                except OSError as exc:
                    logger.warning(
                        "solver.write_failed",
                        path=str(out_path),
                        error=str(exc),
                    )

            if on_result is not None:
                try:
                    on_result(result)
                except Exception as exc:
                    logger.warning(
                        "solver.callback_error",
                        issue=task.issue_number,
                        error=str(exc),
                    )

            if i < len(tasks) - 1:
                time.sleep(config.request_delay)

    succeeded = sum(1 for r in results if r.status == TaskStatus.SUCCESS)
    failed = sum(1 for r in results if r.status == TaskStatus.FAILED)
    logger.info(
        "solver.batch_complete",
        succeeded=succeeded,
        failed=failed,
        total=len(tasks),
    )

    return results


def _clean_code(raw: str) -> str:
    lines = raw.strip().split("\n")
    start = 0
    for i, line in enumerate(lines):
        if line.strip().startswith("```"):
            start = i + 1
            break
    lines = lines[start:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _looks_like_python(code: str) -> bool:
    if not code:
        return False
    if not any(indicator in code for indicator in _PYTHON_INDICATORS):
        return False
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False
