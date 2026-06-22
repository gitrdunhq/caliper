"""Tests for webhook HTTP server.
# tested-by: tests/unit/test_webhook.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

pytest.importorskip("starlette", reason="starlette not installed (caliper[copilot])")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sign(body: bytes, secret: str) -> str:
    """Compute the HMAC-SHA256 signature GitHub sends."""
    mac = hmac.new(secret.encode(), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def _pr_body(action: str = "opened") -> bytes:
    """Minimal pull_request webhook payload."""
    payload = {
        "action": action,
        "pull_request": {
            "number": 42,
            "html_url": "https://github.com/org/repo/pull/42",
            "head": {"sha": "abc123def456"},
        },
        "repository": {
            "full_name": "org/repo",
            "clone_url": "https://github.com/org/repo.git",
        },
    }
    return json.dumps(payload).encode()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def secret() -> str:
    return "webhook-test-secret-xyz789"


@pytest.fixture
def settings(secret: str):
    from caliper.webhook.config import WebhookSettings

    return WebhookSettings(
        secret=secret,
        github_token="ghp_test_token_abc123",
        port=12800,
    )


@pytest.fixture
def app(settings):
    from caliper.composition.bootstrap import bootstrap_test
    from caliper.webhook.server import build_app

    return build_app(settings, context=bootstrap_test())


@pytest.fixture
async def client(app) -> httpx.AsyncClient:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# Shared patch context for tests that trigger a full PR processing path
# ---------------------------------------------------------------------------


def _quiet_processing_mocks():
    """Returns a context manager tuple that silences review + GH API calls."""
    mock_review_result = MagicMock(
        results=[], verdict="clear", security_score=100.0, quality_score=100.0
    )
    return (
        patch("caliper.webhook.server.review_repository", return_value=mock_review_result),
        patch("caliper.webhook.server._post_pr_comment", new_callable=AsyncMock),
    )


# ---------------------------------------------------------------------------
# 1. Signature validation — valid HMAC passes
# ---------------------------------------------------------------------------


class TestSignatureValidation:
    async def test_valid_hmac_signature_accepted(self, client, secret):
        body = _pr_body()
        sig = _sign(body, secret)

        mock_result = MagicMock(stdout="ok", stderr="", returncode=0)
        with (
            patch("caliper.webhook.server.subprocess.run", return_value=mock_result),
            patch("caliper.webhook.server._post_pr_comment", new_callable=AsyncMock),
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )
        assert resp.status_code == 200

    # 2. Signature validation — invalid HMAC returns 401
    async def test_invalid_hmac_signature_returns_401(self, client):
        body = _pr_body()
        resp = await client.post(
            "/webhook",
            content=body,
            headers={
                "X-Hub-Signature-256": "sha256=deadbeefdeadbeefdeadbeef",
                "X-GitHub-Event": "pull_request",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 401

    # 3. Signature validation — missing header returns 401
    async def test_missing_signature_header_returns_401(self, client):
        body = _pr_body()
        resp = await client.post(
            "/webhook",
            content=body,
            headers={
                "X-GitHub-Event": "pull_request",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 4 & 5. Event parsing
# ---------------------------------------------------------------------------


class TestEventParsing:
    # 4. pull_request.opened triggers review_repository and comment
    async def test_pull_request_opened_triggers_review(self, client, secret):
        body = _pr_body("opened")
        sig = _sign(body, secret)

        mock_review_result = MagicMock(
            results=[], verdict="clear", security_score=100.0, quality_score=100.0
        )
        with (
            patch(
                "caliper.webhook.server.review_repository", return_value=mock_review_result
            ) as mock_review,
            patch(
                "caliper.webhook.server._post_pr_comment", new_callable=AsyncMock
            ) as mock_comment,
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200
        mock_review.assert_called_once()
        mock_comment.assert_awaited_once()

    async def test_review_repository_called_with_non_empty_file_list(self, client, secret):
        """review_repository must receive a non-empty file list, not [].

        Before the fix the handler hard-codes `files=[]`, so the call always
        carries an empty list and produces zero findings.  After the fix it
        walks the repo and passes at least one file path.
        """
        body = _pr_body("opened")
        sig = _sign(body, secret)

        mock_review_result = MagicMock(
            results=[], verdict="clear", security_score=100.0, quality_score=100.0
        )
        with (
            patch(
                "caliper.webhook.server.review_repository", return_value=mock_review_result
            ) as mock_review,
            patch("caliper.webhook.server._post_pr_comment", new_callable=AsyncMock),
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200
        mock_review.assert_called_once()
        # Second positional arg to review_repository is the file list
        files_arg = mock_review.call_args.args[1]
        assert (
            len(files_arg) > 0
        ), f"review_repository must be called with a non-empty file list; got {files_arg!r}"

    async def test_pull_request_synchronize_triggers_review(self, client, secret):
        body = _pr_body("synchronize")
        sig = _sign(body, secret)

        mock_review_result = MagicMock(
            results=[], verdict="clear", security_score=100.0, quality_score=100.0
        )
        with (
            patch(
                "caliper.webhook.server.review_repository", return_value=mock_review_result
            ) as mock_review,
            patch("caliper.webhook.server._post_pr_comment", new_callable=AsyncMock),
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200
        mock_review.assert_called_once()

    # 5. Non-pull_request event returns 200 and does NOT trigger review
    async def test_non_pull_request_event_ignored(self, client, secret):
        body = json.dumps({"ref": "refs/heads/main", "commits": []}).encode()
        sig = _sign(body, secret)

        with patch("caliper.webhook.server.subprocess.run") as mock_run:
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "push",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200
        mock_run.assert_not_called()

    async def test_pull_request_closed_action_ignored(self, client, secret):
        body = _pr_body("closed")
        sig = _sign(body, secret)

        with patch("caliper.webhook.server.subprocess.run") as mock_run:
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# 6. Fail-open — subprocess failure still returns 200
# ---------------------------------------------------------------------------


class TestFailOpen:
    async def test_subprocess_timeout_still_returns_200(self, client, secret):
        body = _pr_body("opened")
        sig = _sign(body, secret)

        with (
            patch(
                "caliper.webhook.server.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="caliper", timeout=300),
            ),
            patch("caliper.webhook.server._post_pr_comment", new_callable=AsyncMock),
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200

    async def test_subprocess_oserror_still_returns_200(self, client, secret):
        body = _pr_body("opened")
        sig = _sign(body, secret)

        with (
            patch(
                "caliper.webhook.server.subprocess.run",
                side_effect=OSError("caliper binary not found"),
            ),
            patch("caliper.webhook.server._post_pr_comment", new_callable=AsyncMock),
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200

    async def test_github_api_failure_still_returns_200(self, client, secret):
        body = _pr_body("opened")
        sig = _sign(body, secret)

        mock_result = MagicMock(stdout="review output", stderr="", returncode=0)
        with (
            patch("caliper.webhook.server.subprocess.run", return_value=mock_result),
            patch(
                "caliper.webhook.server._post_pr_comment",
                new_callable=AsyncMock,
                side_effect=httpx.HTTPStatusError(
                    "403 Forbidden",
                    request=MagicMock(),
                    response=MagicMock(status_code=403),
                ),
            ),
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 7. Config loads from env vars
# ---------------------------------------------------------------------------


class TestConfig:
    def test_config_loads_from_env_vars(self, monkeypatch):
        monkeypatch.setenv("CALIPER_WEBHOOK_SECRET", "env-secret-value")
        monkeypatch.setenv("CALIPER_WEBHOOK_GITHUB_TOKEN", "ghp_env_token_xyz")
        monkeypatch.setenv("CALIPER_WEBHOOK_PORT", "12900")

        from caliper.webhook.config import WebhookSettings

        settings = WebhookSettings()  # type: ignore[call-arg]

        assert settings.secret == "env-secret-value"
        assert settings.github_token.get_secret_value() == "ghp_env_token_xyz"
        assert settings.port == 12900

    def test_config_port_defaults_to_12800(self, monkeypatch):
        monkeypatch.setenv("CALIPER_WEBHOOK_SECRET", "s")
        monkeypatch.setenv("CALIPER_WEBHOOK_GITHUB_TOKEN", "t")

        from caliper.webhook.config import WebhookSettings

        settings = WebhookSettings()  # type: ignore[call-arg]
        assert settings.port == 12800


# ---------------------------------------------------------------------------
# 8. _post_pr_comment SSRF validation — malicious full_repo is rejected
# ---------------------------------------------------------------------------


class TestPostPRCommentValidation:
    """_post_pr_comment must reject full_repo values that don't match
    the pattern [a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+ before making any HTTP call."""

    @pytest.mark.parametrize(
        "bad_repo",
        [
            "../../evil/repo",
            "org/repo;rm -rf /",
            "../other-org/other-repo",
            "org/repo\x00injected",
            "org repo",
            "",
            "noslash",
            "org//double-slash",
        ],
    )
    async def test_malicious_full_repo_raises_value_error(self, bad_repo: str) -> None:
        """Malformed full_repo must raise ValueError without touching the network."""
        from caliper.webhook.server import _post_pr_comment

        with pytest.raises(ValueError, match="Invalid repo"):
            await _post_pr_comment(
                token="ghp_fake",
                full_repo=bad_repo,
                pr_number=1,
                body="test comment",
            )

    @pytest.mark.parametrize(
        "good_repo",
        [
            "org/repo",
            "my-org/my-repo",
            "user.name/repo.name",
            "Org123/Repo_456",
        ],
    )
    async def test_valid_full_repo_does_not_raise_on_validation(self, good_repo: str) -> None:
        """Valid full_repo passes the regex check (HTTP call is mocked)."""
        from caliper.webhook.server import _post_pr_comment

        mock_resp = AsyncMock()
        mock_resp.raise_for_status = MagicMock()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("caliper.webhook.server.httpx.AsyncClient", return_value=mock_client):
            # Should not raise — just needs to pass validation and attempt the HTTP call
            await _post_pr_comment(
                token="ghp_fake",
                full_repo=good_repo,
                pr_number=1,
                body="test comment",
            )


# ---------------------------------------------------------------------------
# 9. Token scrubbing in error logs (security: wave2-patch-8)
# ---------------------------------------------------------------------------


class TestTokenScrubbingInWebhookLogs:
    def test_scrub_token_from_error_removes_token(self):
        """_scrub_token_from_error replaces the raw token with [REDACTED]."""
        from caliper.webhook.server import _scrub_token_from_error

        token = "ghp_secret_abc123"
        exc_msg = f"HTTPStatusError: 401 Bearer {token} is not valid"
        result = _scrub_token_from_error(exc_msg, token)
        assert token not in result
        assert "[REDACTED]" in result

    def test_scrub_token_from_error_is_noop_when_token_absent(self):
        """_scrub_token_from_error does not modify text without the token."""
        from caliper.webhook.server import _scrub_token_from_error

        result = _scrub_token_from_error("Connection refused", "ghp_secret_abc123")
        assert result == "Connection refused"

    async def test_comment_failed_log_does_not_expose_token(self, client, secret, settings):
        """When _post_pr_comment raises an exc containing the token, the token must not
        appear in the 'error' field passed to the logger."""
        body = _pr_body("opened")
        sig = _sign(body, secret)
        token_value = settings.github_token.get_secret_value()

        mock_review_result = MagicMock(
            results=[], verdict="clear", security_score=100.0, quality_score=100.0
        )

        async def _raise_with_token(*args, **kwargs):
            raise Exception(f"Authorization failed: Bearer {token_value} rejected")

        with (
            patch("caliper.webhook.server.review_repository", return_value=mock_review_result),
            patch("caliper.webhook.server._post_pr_comment", side_effect=_raise_with_token),
            patch("caliper.webhook.server.logger") as mock_logger,
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200
        # Find the webhook_comment_failed log call and assert token is scrubbed
        for call in mock_logger.error.call_args_list:
            args, kwargs = call
            event = args[0] if args else ""
            if "comment_failed" in str(event):
                error_val = str(kwargs.get("error", ""))
                assert (
                    token_value not in error_val
                ), f"Token exposed in webhook_comment_failed log: {error_val!r}"


# ---------------------------------------------------------------------------
# 10. Module __getattr__ caching — patch-18 (race condition fix)
# ---------------------------------------------------------------------------


class TestModuleGetattr:
    def test_module_app_attr_is_cached_on_repeated_access(self, monkeypatch):
        """Module-level app attribute must return the same object on every access.

        Before the fix __getattr__ calls _load_app() each time, producing multiple
        distinct instances and introducing a race on concurrent access.
        After the fix the result is cached and _load_app() is called exactly once.
        """
        import caliper.webhook.server as srv

        fake_app = object()
        call_count = [0]

        def fake_load_app():
            call_count[0] += 1
            return fake_app

        monkeypatch.setattr(srv, "_load_app", fake_load_app)
        # Reset cached instance if the fix has already been applied
        if hasattr(srv, "_app_instance"):
            monkeypatch.setattr(srv, "_app_instance", None)

        result1 = srv.app
        result2 = srv.app
        result3 = srv.app

        assert result1 is fake_app
        assert result2 is fake_app
        assert result3 is fake_app
        assert (
            call_count[0] == 1
        ), "_load_app must be called exactly once (cached after first access)"


# ---------------------------------------------------------------------------
# 11. review_repository timeout — patch-19
# ---------------------------------------------------------------------------


class TestReviewTimeout:
    async def test_review_timeout_logs_webhook_review_timeout(self, client, secret, monkeypatch):
        """Hanging review_repository must time out and log webhook_review_timeout.

        Before the fix there is no timeout enforcement, so a slow review just
        completes normally and never produces a timeout log entry.
        After the fix asyncio.wait_for wraps the call and logs webhook_review_timeout.
        """
        import time

        import caliper.webhook.server as srv

        body = _pr_body("opened")
        sig = _sign(body, secret)

        monkeypatch.setattr(srv, "_REVIEW_TIMEOUT_S", 0.05)  # 50 ms

        def slow_review(*args, **kwargs):
            time.sleep(0.3)  # 300 ms > 50 ms timeout
            return MagicMock(verdict="clear", security_score=100.0, quality_score=100.0)

        with (
            patch("caliper.webhook.server.review_repository", side_effect=slow_review),
            patch("caliper.webhook.server._post_pr_comment", new_callable=AsyncMock),
            patch("caliper.webhook.server.logger") as mock_logger,
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200  # fail-open even on timeout
        logged_error_events = [str(c.args[0]) for c in mock_logger.error.call_args_list]
        assert any(
            "timeout" in e for e in logged_error_events
        ), f"Expected webhook_review_timeout in error logs; got: {logged_error_events}"


# ---------------------------------------------------------------------------
# 12. Input validation — DoS protection and Content-Type (patches 27 & 28)
# ---------------------------------------------------------------------------


class TestInputValidation:
    # --- Payload size limit (patch-27) ---

    async def test_oversized_payload_returns_413(self, client, secret):
        """Payloads exceeding 1 MB must be rejected with 413."""
        oversized_body = b"x" * (1024 * 1024 + 1)  # 1 MB + 1 byte
        sig = _sign(oversized_body, secret)

        resp = await client.post(
            "/webhook",
            content=oversized_body,
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "pull_request",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 413

    async def test_exactly_1mb_payload_not_rejected_by_size(self, client, secret):
        """Payloads at exactly 1 MB must not be rejected with 413."""
        at_limit_body = b"x" * (1024 * 1024)
        sig = _sign(at_limit_body, secret)

        resp = await client.post(
            "/webhook",
            content=at_limit_body,
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "pull_request",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code != 413

    # --- Content-Type validation (patch-28) ---

    async def test_missing_content_type_returns_400(self, client, secret):
        """Authenticated requests without Content-Type must be rejected with 400."""
        body = _pr_body()
        sig = _sign(body, secret)

        resp = await client.post(
            "/webhook",
            content=body,
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "pull_request",
                # No Content-Type header
            },
        )
        assert resp.status_code == 400

    async def test_wrong_content_type_returns_400(self, client, secret):
        """Authenticated requests with non-JSON Content-Type must be rejected with 400."""
        body = _pr_body()
        sig = _sign(body, secret)

        resp = await client.post(
            "/webhook",
            content=body,
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "pull_request",
                "Content-Type": "text/plain",
            },
        )
        assert resp.status_code == 400

    async def test_application_json_content_type_not_rejected(self, client, secret):
        """application/json Content-Type must not be rejected with 400."""
        body = _pr_body("closed")  # closed action → ignored, no side effects needed
        sig = _sign(body, secret)

        resp = await client.post(
            "/webhook",
            content=body,
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "pull_request",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code != 400
