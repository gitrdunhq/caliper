"""Webhook HTTP server for GitHub PR events.
# tested-by: tests/unit/test_webhook.py

Receives GitHub webhook POST requests, validates the HMAC-SHA256 signature,
and triggers caliper review on pull_request events (opened, synchronize, reopened).

Fail-open contract: every processing error is logged and HTTP 200 is returned.
The only non-200 responses are authentication failures (401 on bad/missing sig)
and input-validation failures (400 wrong Content-Type, 413 payload too large).

Run in production:
    uvicorn caliper.webhook.server:app --host 0.0.0.0 --port 12800
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
import subprocess  # noqa: F401 — kept so patch("caliper.webhook.server.subprocess") resolves
import threading
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import structlog

try:
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Route
except ImportError as _exc:
    raise ImportError(
        "starlette is required for the webhook server. Install with: pip install caliper[copilot]"
    ) from _exc

from caliper.core.use_cases import ReviewOptions, review_repository
from caliper.webhook.config import WebhookSettings

if TYPE_CHECKING:
    from caliper.composition.bootstrap import ApplicationContext

logger = structlog.get_logger()

# pull_request actions that should trigger a review
_PR_ACTIONS: frozenset[str] = frozenset({"opened", "synchronize", "reopened"})

# Review timeout (seconds) — matches pipeline_timeout in Foreman config
_REVIEW_TIMEOUT_S: int = 300

# Maximum accepted payload size — 1 MB DoS guard (patch-27)
_MAX_PAYLOAD_SIZE_BYTES: int = 1 * 1024 * 1024


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _verify_signature(body: bytes, signature: str, secret: str) -> bool:
    """Return True if *signature* is a valid HMAC-SHA256 for *body* under *secret*."""
    mac = hmac.new(secret.encode(), body, hashlib.sha256)
    expected = f"sha256={mac.hexdigest()}"
    return hmac.compare_digest(expected, signature)


def _scrub_token_from_error(text: str, token: str) -> str:
    """Replace a raw token value with [REDACTED] to prevent accidental log exposure."""
    if token and token in text:
        return text.replace(token, "[REDACTED]")
    return text


async def _post_pr_comment(token: str, full_repo: str, pr_number: int, body: str) -> None:
    """Post *body* as a comment on the given GitHub PR.

    Raises httpx.HTTPStatusError on 4xx/5xx from GitHub API.
    Raises ValueError if full_repo does not match the expected owner/repo pattern.
    """
    _repo_re = re.compile(r"[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+")
    if not _repo_re.fullmatch(full_repo):
        raise ValueError(f"Invalid repo name: {full_repo!r}")
    url = f"https://api.github.com/repos/{full_repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json={"body": body}, headers=headers)
        resp.raise_for_status()


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def build_app(
    settings: WebhookSettings,
    context: ApplicationContext | None = None,
) -> Starlette:
    """Construct and return the Starlette ASGI application.

    Accepts a *settings* instance and an optional *context* so the app is
    fully testable without touching the real environment.  Callers must supply
    a context; use ``bootstrap_test()`` in tests and ``bootstrap(settings)``
    in production (see ``_load_app``).
    """
    if context is None:
        raise ValueError(
            "build_app() requires an ApplicationContext. "
            "Pass bootstrap_test() in tests or bootstrap(CaliperSettings()) in production."
        )

    async def webhook(request: Request) -> Response:
        body = await request.body()

        # --- DoS guard: reject oversized payloads before HMAC work (patch-27) ---
        if len(body) > _MAX_PAYLOAD_SIZE_BYTES:
            logger.warning("webhook_payload_too_large", size_bytes=len(body))
            return JSONResponse(
                {"error": f"Payload exceeds {_MAX_PAYLOAD_SIZE_BYTES} bytes"},
                status_code=413,
            )

        # --- Auth: validate HMAC-SHA256 signature --------------------------
        signature = request.headers.get("X-Hub-Signature-256", "")
        if not signature:
            logger.warning("webhook_missing_signature", path=str(request.url))
            return JSONResponse({"error": "Missing X-Hub-Signature-256 header"}, status_code=401)

        if not _verify_signature(body, signature, settings.secret):
            logger.warning("webhook_invalid_signature")
            return JSONResponse({"error": "Signature mismatch"}, status_code=401)

        # --- Content-Type validation: only accept JSON (patch-28) ----------
        content_type = request.headers.get("Content-Type", "")
        if not content_type.startswith("application/json"):
            logger.warning("webhook_invalid_content_type", content_type=content_type)
            return JSONResponse(
                {"error": "Content-Type must be application/json"},
                status_code=400,
            )

        # --- Routing: only handle pull_request events ----------------------
        event_type = request.headers.get("X-GitHub-Event", "")
        if event_type != "pull_request":
            logger.info("webhook_event_ignored", event_type=event_type)
            return JSONResponse({"status": "ignored", "event": event_type}, status_code=200)

        # --- Parse payload -------------------------------------------------
        try:
            payload: dict = await request.json()
        except Exception as exc:
            logger.error("webhook_json_parse_error", error=str(exc))
            return JSONResponse({"status": "ok"}, status_code=200)

        action = payload.get("action", "")
        if action not in _PR_ACTIONS:
            logger.info("webhook_pr_action_ignored", action=action)
            return JSONResponse({"status": "ignored", "action": action}, status_code=200)

        # All further errors are fail-open: log + return 200 ---------------
        try:
            pr = payload["pull_request"]
            repo = payload["repository"]
            pr_number: int = pr["number"]
            pr_url: str = pr["html_url"]
            full_name: str = repo["full_name"]
        except KeyError as exc:
            logger.error("webhook_payload_missing_field", field=str(exc))
            return JSONResponse({"status": "ok"}, status_code=200)

        logger.info("webhook_pr_received", pr_url=pr_url, action=action)

        # --- Build file list via the FileSourcePort seam (never rglob directly;
        # the resolved source already applies the caliper exclusion layer) -------
        from caliper.core.file_source import select_file_source

        _repo_path = Path(".")
        _suffixes = (".py", ".ts", ".js", ".tf", ".yaml", ".yml", ".json")
        _source = select_file_source(_repo_path)
        _files = [str(p) for p in _source.list_files(_repo_path, suffixes=_suffixes)]

        # --- Run caliper review via use-case with timeout (fail-open) (patch-19) ---
        review_output: str
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    review_repository,
                    context,
                    _files,
                    _repo_path,
                    ReviewOptions(),
                ),
                timeout=_REVIEW_TIMEOUT_S,
            )
            review_output = (
                f"verdict: {result.verdict}, "
                f"security: {result.security_score:.1f}, "
                f"quality: {result.quality_score:.1f}"
            )
            logger.info("webhook_review_complete", verdict=result.verdict, pr_url=pr_url)
        except TimeoutError:
            logger.error("webhook_review_timeout", timeout_s=_REVIEW_TIMEOUT_S, pr_url=pr_url)
            review_output = f"caliper review timed out after {_REVIEW_TIMEOUT_S}s"
        except Exception as exc:
            logger.error("webhook_review_failed", error=str(exc), pr_url=pr_url)
            review_output = f"caliper review could not run: {exc}"

        # --- Post PR comment (fail-open) ------------------------------------
        try:
            comment_body = f"## Caliper Review\n\n{review_output}"
            await _post_pr_comment(
                token=settings.github_token.get_secret_value(),
                full_repo=full_name,
                pr_number=pr_number,
                body=comment_body,
            )
            logger.info("webhook_comment_posted", pr_url=pr_url)
        except Exception as exc:
            safe_error = _scrub_token_from_error(str(exc), settings.github_token.get_secret_value())
            logger.error("webhook_comment_failed", error=safe_error, pr_url=pr_url)

        return JSONResponse({"status": "ok"}, status_code=200)

    return Starlette(routes=[Route("/webhook", webhook, methods=["POST"])])


# ---------------------------------------------------------------------------
# Production entry point (uvicorn caliper.webhook.server:app)
# ---------------------------------------------------------------------------


def _load_app() -> Starlette:
    """Load settings from env and return the production app instance."""
    from caliper.composition.bootstrap import bootstrap as _bootstrap
    from caliper.core.config import CaliperSettings

    settings = WebhookSettings()  # type: ignore[call-arg]
    context = _bootstrap(CaliperSettings())  # type: ignore[call-arg]
    return build_app(settings, context=context)


# Module-level app for: uvicorn caliper.webhook.server:app
# Deferred so import doesn't require env vars during tests.
# Thread-safe cache — patch-18 (race condition fix).
_app_instance: Starlette | None = None
_app_lock: threading.RLock = threading.RLock()


def __getattr__(name: str) -> object:
    global _app_instance
    if name == "app":
        with _app_lock:
            if _app_instance is None:
                _app_instance = _load_app()
        return _app_instance
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
