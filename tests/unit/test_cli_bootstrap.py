"""Tests verifying that the CLI review command is wired through bootstrap().

RED phase for issue #161 — all tests are expected to FAIL because the CLI
currently constructs PluginRegistry (via get_default_registry) and ReviewPipeline
directly, rather than calling bootstrap() and using the returned ApplicationContext.

After the refactor (#161), these tests should all pass.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from eedom.cli.main import cli

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_RUNNER_ENV = {"EEDOM_ALLOW_GLOBAL": "1"}


def _make_fake_context():
    """Return an (ApplicationContext, mock_registry, mock_policy) triple.

    The ApplicationContext is wired with fully-tracked MagicMock components so
    that test assertions can verify which components are actually called during
    CLI execution.
    """
    from eedom.composition.bootstrap import ApplicationContext, bootstrap_test

    base = bootstrap_test()

    mock_registry = MagicMock(name="FakeAnalyzerRegistry")
    mock_registry.run_all.return_value = []
    mock_registry.list.return_value = []

    mock_policy = MagicMock(name="FakePolicyEngine")

    fake_ctx = ApplicationContext(
        analyzer_registry=mock_registry,
        policy_engine=mock_policy,
        tool_runner=base.tool_runner,
        decision_store=base.decision_store,
        evidence_store=base.evidence_store,
        package_index=base.package_index,
        audit_sink=base.audit_sink,
        publisher=base.publisher,
        # Phase 5 pipeline collaborators — tracked mocks so the pipeline can run
        # end-to-end and reach the injected policy engine.
        scanners=[],
        evidence_writer=MagicMock(name="FakeEvidenceWriter"),
        package_metadata=MagicMock(name="FakePackageMetadata"),
        decision_repository=MagicMock(name="FakeDecisionRepository"),
        audit_log_appender=MagicMock(name="FakeAuditAppender"),
    )
    return fake_ctx, mock_registry, mock_policy


# ---------------------------------------------------------------------------
# 1. CLI module must import bootstrap
# ---------------------------------------------------------------------------


class TestCLIImportsBootstrap:
    def test_cli_module_imports_bootstrap_function(self) -> None:
        """cli/main.py must import bootstrap (or bootstrap_test) from eedom.composition.bootstrap.

        FAILS (RED): cli/main.py currently does not import bootstrap at all.
        After #161, the CLI must call bootstrap(settings) to obtain an
        ApplicationContext instead of constructing PluginRegistry directly via
        get_default_registry().
        """
        import eedom.cli.main as cli_module

        source = inspect.getsource(cli_module)
        assert "eedom.composition.bootstrap" in source, (
            "cli/main.py must import from eedom.composition.bootstrap. "
            "Currently it constructs PluginRegistry directly via get_default_registry()."
        )


# ---------------------------------------------------------------------------
# 2 & 3. review command must use ApplicationContext.analyzer_registry
# ---------------------------------------------------------------------------


class TestReviewUsesContextAnalyzerRegistry:
    def test_review_command_routes_through_context_analyzer_registry(self) -> None:
        """The review command must call ctx.analyzer_registry.run_all via bootstrap_review()."""
        fake_ctx, mock_registry, _ = _make_fake_context()

        with patch("eedom.composition.bootstrap.bootstrap_review", return_value=fake_ctx):
            runner = CliRunner()
            with runner.isolated_filesystem():
                runner.invoke(
                    cli,
                    ["review", "--repo-path", ".", "--all"],
                    env=_RUNNER_ENV,
                )

        mock_registry.run_all.assert_called()

    def test_review_command_does_not_call_get_default_registry(self) -> None:
        """After #161, get_default_registry must not be imported in cli/main.py."""
        import ast
        import inspect

        from eedom.cli import main as cli_module

        source = inspect.getsource(cli_module)
        tree = ast.parse(source)
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "get_default_registry"
        ]
        assert len(calls) == 0, "cli/main.py must not call get_default_registry()"


# ---------------------------------------------------------------------------
# 4. evaluate command must use ApplicationContext.policy_engine
# ---------------------------------------------------------------------------


class TestEvaluateUsesContextPolicyEngine:
    def test_evaluate_command_routes_through_context_policy_engine(self) -> None:
        """The evaluate command must use ctx.policy_engine, not build OpaEvaluator internally.

        FAILS (RED): ReviewPipeline currently constructs OpaEvaluator inside
        its evaluate() method, bypassing ApplicationContext.policy_engine
        entirely. The fake mock_policy injected via a patched bootstrap will
        never be called.
        """
        fake_ctx, _, mock_policy = _make_fake_context()

        diff_content = (
            "diff --git a/requirements.txt b/requirements.txt\n"
            "index 000..111 100644\n"
            "--- a/requirements.txt\n"
            "+++ b/requirements.txt\n"
            "@@ -0,0 +1 @@\n"
            "+requests==2.28.0\n"
        )

        with patch("eedom.composition.bootstrap.bootstrap", return_value=fake_ctx):
            runner = CliRunner()
            with runner.isolated_filesystem():
                Path("test.diff").write_text(diff_content)
                runner.invoke(
                    cli,
                    [
                        "evaluate",
                        "--repo-path",
                        ".",
                        "--diff",
                        "test.diff",
                        "--pr-url",
                        "https://github.com/org/repo/pull/1",
                        "--team",
                        "platform",
                        "--operating-mode",
                        "monitor",
                    ],
                    env=dict(_RUNNER_ENV, EEDOM_DB_DSN="postgresql://test:test@localhost/test"),
                )

        # Fails because the CLI never calls bootstrap(), so mock_policy.evaluate
        # is never invoked — ReviewPipeline constructs its own OpaEvaluator.
        mock_policy.evaluate.assert_called()


# ---------------------------------------------------------------------------
# 5. Injecting bootstrap_test() must prevent real scanner construction
# ---------------------------------------------------------------------------


class TestBootstrapTestInjection:
    def test_bootstrap_test_context_prevents_real_scanner_execution(self) -> None:
        """A test must be able to inject bootstrap_test() to run review without real scanners.

        FAILS (RED): No context-injection mechanism exists yet. The CLI
        constructs its own PluginRegistry regardless of any bootstrap_test()
        context being provided. We verify this by asserting that after
        bootstrap_test is patched, get_default_registry is NOT called. Currently
        it IS still called, so the assertion fails.
        """
        import ast
        import inspect

        from eedom.cli import main as cli_module

        source = inspect.getsource(cli_module)
        tree = ast.parse(source)
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "get_default_registry"
        ]
        assert len(calls) == 0, (
            "With bootstrap providing the registry, "
            "get_default_registry() should not appear in cli/main.py"
        )


# ---------------------------------------------------------------------------
# 6 & 7. Structural: no direct construction of PluginRegistry or ReviewPipeline
#        without ApplicationContext in cli/main.py
# ---------------------------------------------------------------------------


class TestNoCLIDirectConstruction:
    def test_cli_module_does_not_call_get_default_registry(self) -> None:
        """cli/main.py must not call get_default_registry() after #161.

        FAILS (RED): The CLI currently calls get_default_registry() in the
        review command. After the refactor it must call bootstrap() and use
        ctx.analyzer_registry instead.
        """
        import eedom.cli.main as cli_module

        source = inspect.getsource(cli_module)
        tree = ast.parse(source)

        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "get_default_registry"
        ]

        assert len(calls) == 0, (
            f"cli/main.py must not call get_default_registry() — "
            f"found {len(calls)} call(s). "
            "Use bootstrap() and ctx.analyzer_registry instead."
        )

    def test_cli_module_does_not_construct_review_pipeline_without_context(self) -> None:
        """cli/main.py must not construct ReviewPipeline(config) without an ApplicationContext.

        FAILS (RED): The evaluate command currently does ReviewPipeline(config),
        which causes ReviewPipeline to construct OpaEvaluator internally.
        After #161, the evaluate command must pass an ApplicationContext so
        the injected policy_engine is used instead of a hardwired OpaEvaluator.
        """
        import eedom.cli.main as cli_module

        source = inspect.getsource(cli_module)
        tree = ast.parse(source)

        pipeline_calls_without_context: list[ast.Call] = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "ReviewPipeline"
            ):
                # After #161, ReviewPipeline must be called with an ApplicationContext:
                # either as a second positional arg or as a keyword arg containing "context".
                has_context = (
                    any(
                        isinstance(kw.arg, str) and "context" in kw.arg.lower()
                        for kw in node.keywords
                    )
                    or len(node.args) > 1
                )
                if not has_context:
                    pipeline_calls_without_context.append(node)

        assert len(pipeline_calls_without_context) == 0, (
            f"cli/main.py calls ReviewPipeline without an ApplicationContext "
            f"({len(pipeline_calls_without_context)} call(s)). "
            "After #161, pass ctx obtained from bootstrap() to ReviewPipeline."
        )
