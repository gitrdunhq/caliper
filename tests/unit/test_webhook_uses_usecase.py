# tested-by: tests/unit/test_webhook_uses_usecase.py
"""RED tests for #185 — webhook must delegate to review_repository() use case.

These tests document the REQUIRED behaviour after the migration and fail against
the CURRENT implementation which still shells out via subprocess.run().

Three things that must be true after the fix:
  1. caliper.webhook.server imports review_repository from caliper.core.use_cases
  2. build_app() accepts a context: ApplicationContext parameter
  3. The webhook handler calls review_repository(), not subprocess.run()
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

pytest.importorskip("starlette", reason="starlette not installed (caliper[copilot])")


# ---------------------------------------------------------------------------
# Helpers (copied from test_webhook.py to keep this file self-contained)
# ---------------------------------------------------------------------------


def _sign(body: bytes, secret: str) -> str:
    mac = hmac.new(secret.encode(), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def _pr_body(action: str = "opened") -> bytes:
    payload = {
        "action": action,
        "pull_request": {
            "number": 99,
            "html_url": "https://github.com/org/repo/pull/99",
            "head": {"sha": "deadbeef1234"},
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
    return "use-case-test-secret-abc"


@pytest.fixture
def settings(secret: str):
    from caliper.webhook.config import WebhookSettings

    return WebhookSettings(
        secret=secret,
        github_token="ghp_test_use_case_token",
        port=12800,
    )


@pytest.fixture
def test_context():
    """ApplicationContext wired with all-fake implementations."""
    from caliper.composition.bootstrap import bootstrap_test

    return bootstrap_test()


# ---------------------------------------------------------------------------
# 1. Import contract: server.py must expose review_repository in its namespace
# ---------------------------------------------------------------------------


class TestServerImportsUseCase:
    def test_server_module_imports_review_repository(self):
        """server.py must import review_repository from caliper.core.use_cases.

        FAILS NOW: server.py only imports subprocess and httpx — it does not
        import review_repository at all.
        """
        import caliper.webhook.server as server_mod

        assert hasattr(server_mod, "review_repository"), (
            "caliper.webhook.server must import review_repository from "
            "caliper.core.use_cases so the handler can call it directly "
            "instead of shelling out via subprocess."
        )

    def test_review_repository_symbol_is_the_use_case_function(self):
        """The imported symbol must actually be the function from use_cases.

        FAILS NOW: the attribute does not exist on the module.
        """
        import caliper.webhook.server as server_mod
        from caliper.core.use_cases import review_repository as canonical

        assert server_mod.review_repository is canonical, (
            "caliper.webhook.server.review_repository must be the same object as "
            "caliper.core.use_cases.review_repository — not a wrapper or stub."
        )


# ---------------------------------------------------------------------------
# 2. API contract: build_app() must accept an ApplicationContext parameter
# ---------------------------------------------------------------------------


class TestBuildAppAcceptsContext:
    def test_build_app_signature_has_context_parameter(self, settings):
        """build_app() must accept a 'context' keyword argument.

        FAILS NOW: build_app(settings: WebhookSettings) has no 'context' param.
        The call below raises TypeError.
        """
        from caliper.composition.bootstrap import bootstrap_test
        from caliper.webhook.server import build_app

        ctx = bootstrap_test()
        # This must NOT raise TypeError once the fix is applied.
        app = build_app(settings, context=ctx)
        assert app is not None

    def test_build_app_context_parameter_is_in_signature(self):
        """Verify 'context' appears in build_app's formal parameter list.

        FAILS NOW: inspect.signature reveals no 'context' parameter.
        """
        from caliper.webhook.server import build_app

        sig = inspect.signature(build_app)
        assert "context" in sig.parameters, (
            "build_app() must declare a 'context: ApplicationContext' parameter "
            "so it can be wired with bootstrap_test() in unit tests."
        )


# ---------------------------------------------------------------------------
# 3. Behavioural contract: handler calls review_repository(), not subprocess
# ---------------------------------------------------------------------------


class TestWebhookDelegatesToUseCase:
    async def test_pr_opened_does_not_call_subprocess_run(self, settings, secret):
        """On pull_request:opened the handler must NOT shell out via subprocess.

        FAILS NOW: the current handler calls subprocess.run() unconditionally.
        After the fix, review_repository() is used and subprocess.run() is
        never invoked from the webhook handler.
        """
        from caliper.composition.bootstrap import bootstrap_test
        from caliper.webhook.server import build_app

        ctx = bootstrap_test()
        # build_app will TypeError here in the RED phase — that makes the test
        # fail, which is the intended RED outcome.
        app = build_app(settings, context=ctx)

        body = _pr_body("opened")
        sig = _sign(body, secret)

        with (
            patch("caliper.webhook.server.subprocess") as mock_subprocess,
            patch("caliper.webhook.server._post_pr_comment", new_callable=AsyncMock),
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test",
            ) as client:
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
        mock_subprocess.run.assert_not_called()

    async def test_pr_opened_calls_review_repository(self, settings, secret, test_context):
        """On pull_request:opened the handler must call review_repository().

        FAILS NOW: review_repository is not imported by server.py so patching
        it at the server module level will raise AttributeError.
        After the fix this asserts review_repository was called exactly once.
        """
        from caliper.webhook.server import build_app

        app = build_app(settings, context=test_context)

        body = _pr_body("opened")
        sig = _sign(body, secret)

        with (
            patch(
                "caliper.webhook.server.review_repository",
                return_value=MagicMock(
                    results=[],
                    verdict="clear",
                    security_score=10.0,
                    quality_score=10.0,
                ),
            ) as mock_review,
            patch("caliper.webhook.server._post_pr_comment", new_callable=AsyncMock),
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test",
            ) as client:
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

    async def test_build_app_with_bootstrap_test_is_fully_testable(
        self, settings, secret, test_context
    ):
        """An app built with bootstrap_test() context handles a PR event end-to-end
        without any real subprocess, filesystem, or network I/O.

        FAILS NOW: build_app() does not accept a context, so the TypeError is
        the immediate RED signal.  Once the context param lands, subprocess.run
        must also not be called.
        """
        from caliper.webhook.server import build_app

        # After the fix: build_app wires test_context so no subprocess needed.
        app = build_app(settings, context=test_context)

        body = _pr_body("synchronize")
        sig = _sign(body, secret)

        called_args: list = []

        def _fake_review_repository(context, files, repo_path, options):
            called_args.append((context, files, repo_path, options))
            return MagicMock(
                results=[],
                verdict="clear",
                security_score=10.0,
                quality_score=10.0,
            )

        with (
            patch("caliper.webhook.server.review_repository", side_effect=_fake_review_repository),
            patch("caliper.webhook.server._post_pr_comment", new_callable=AsyncMock),
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test",
            ) as client:
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
        assert len(called_args) == 1, (
            "review_repository() must be called exactly once per PR event. "
            f"Got {len(called_args)} call(s)."
        )
        # The context passed in must be the bootstrap_test context, not a new one.
        assert called_args[0][0] is test_context, (
            "review_repository() must receive the ApplicationContext that was "
            "injected into build_app(), not a freshly created one."
        )
