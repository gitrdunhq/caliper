# tested-by: tests/unit/test_agent_uses_usecase.py
"""RED tests for #184 — Align agent with use case layer.

All tests are expected to FAIL until tool_helpers.py is updated to:
  1. import review_repository from caliper.core.use_cases
  2. expose a context-aware run entry point (run_pipeline_with_context)
  3. route through review_repository so bootstrap_test() eliminates subprocess
"""

from __future__ import annotations

from unittest.mock import patch

# ---------------------------------------------------------------------------
# 1. tool_helpers imports review_repository from caliper.core.use_cases
# ---------------------------------------------------------------------------


class TestToolHelpersImportsReviewRepository:
    """tool_helpers must re-export review_repository at module level."""

    def test_review_repository_importable_from_tool_helpers(self) -> None:
        """Fails: tool_helpers does not yet import review_repository.

        Once #184 is implemented:
            from caliper.agent.tool_helpers import review_repository
        must not raise ImportError.
        """
        from caliper.agent.tool_helpers import review_repository  # noqa: F401

    def test_tool_helpers_review_repository_is_callable(self) -> None:
        """Fails: tool_helpers does not expose a callable review_repository."""
        import caliper.agent.tool_helpers as th

        fn = getattr(th, "review_repository", None)
        assert callable(fn), (
            "caliper.agent.tool_helpers.review_repository must be the callable "
            "imported from caliper.core.use_cases (#184)"
        )


# ---------------------------------------------------------------------------
# 2. evaluate_change delegates to review_repository, not subprocess
# ---------------------------------------------------------------------------


class TestEvaluateChangeDelegatesToReviewRepository:
    """The agent's pipeline path must route through review_repository.

    evaluate_change calls tool_helpers.run_pipeline which currently shells
    out via subprocess.run.  After #184 the path must be:

        evaluate_change -> run_pipeline_with_context -> review_repository
    """

    def test_run_pipeline_with_context_is_importable_from_tool_helpers(self) -> None:
        """Fails: tool_helpers has no run_pipeline_with_context yet."""
        from caliper.agent.tool_helpers import run_pipeline_with_context  # noqa: F401

    def test_run_pipeline_with_context_is_callable(self) -> None:
        """Fails: no context-aware entry point exists in tool_helpers."""
        import caliper.agent.tool_helpers as th

        fn = getattr(th, "run_pipeline_with_context", None)
        assert callable(fn), (
            "caliper.agent.tool_helpers.run_pipeline_with_context must exist "
            "and be callable (#184)"
        )

    def test_run_pipeline_with_context_calls_review_repository(self) -> None:
        """Fails: run_pipeline_with_context does not exist yet; patch target absent."""
        from caliper.composition.bootstrap import bootstrap_test
        from caliper.core.use_cases import ReviewResult

        stub = ReviewResult(
            results=[],
            verdict="clear",
            security_score=1.0,
            quality_score=1.0,
        )

        # This patch will raise AttributeError because review_repository is not
        # yet present in the tool_helpers namespace.
        with patch("caliper.agent.tool_helpers.review_repository", return_value=stub) as mock_rr:
            from caliper.agent.tool_helpers import run_pipeline_with_context

            ctx = bootstrap_test()
            run_pipeline_with_context(
                context=ctx,
                diff_text="diff --git a/requirements.txt b/requirements.txt\n+requests==2.31.0\n",
                pr_url="https://github.com/org/repo/pull/1",
                team="platform",
                repo_path=".",
            )
            mock_rr.assert_called_once()

    def test_run_pipeline_with_context_does_not_call_subprocess(self) -> None:
        """Fails: once run_pipeline_with_context exists it must not call subprocess.run.

        If the function shells out, the assertion below will fail.  If the function
        doesn't exist yet, the import itself fails — either way the test is red.
        """
        from caliper.composition.bootstrap import bootstrap_test
        from caliper.core.use_cases import ReviewResult

        stub = ReviewResult(
            results=[],
            verdict="clear",
            security_score=1.0,
            quality_score=1.0,
        )

        with patch("caliper.agent.tool_helpers.review_repository", return_value=stub):
            with patch("subprocess.run") as mock_subproc:
                from caliper.agent.tool_helpers import run_pipeline_with_context

                ctx = bootstrap_test()
                run_pipeline_with_context(
                    context=ctx,
                    diff_text="diff --git a/requirements.txt b/requirements.txt\n+requests==2.31.0\n",
                    pr_url="https://github.com/org/repo/pull/1",
                    team="platform",
                    repo_path=".",
                )
                mock_subproc.assert_not_called()


# ---------------------------------------------------------------------------
# 3. Agent can be tested with bootstrap_test() context (no real scanners)
# ---------------------------------------------------------------------------


class TestBootstrapTestContextIntegration:
    """Injecting bootstrap_test() context must produce a ReviewResult without subprocesses."""

    def test_run_pipeline_with_context_returns_review_result(self) -> None:
        """Fails: run_pipeline_with_context does not exist yet."""
        from caliper.agent.tool_helpers import run_pipeline_with_context
        from caliper.composition.bootstrap import bootstrap_test
        from caliper.core.use_cases import ReviewResult

        ctx = bootstrap_test()
        result = run_pipeline_with_context(
            context=ctx,
            diff_text="diff --git a/requirements.txt b/requirements.txt\n+requests==2.31.0\n",
            pr_url="https://github.com/org/repo/pull/1",
            team="platform",
            repo_path=".",
        )
        assert isinstance(result, ReviewResult)

    def test_bootstrap_context_yields_clear_verdict_for_empty_diff(self) -> None:
        """Fails: run_pipeline_with_context does not exist yet.

        With bootstrap_test() (FakeAnalyzerRegistry returns []), verdict must be 'clear'.
        """
        from caliper.agent.tool_helpers import run_pipeline_with_context
        from caliper.composition.bootstrap import bootstrap_test

        ctx = bootstrap_test()
        result = run_pipeline_with_context(
            context=ctx,
            diff_text="",
            pr_url="https://github.com/org/repo/pull/99",
            team="qa",
            repo_path=".",
        )
        assert result.verdict == "clear"

    def test_bootstrap_context_does_not_invoke_subprocess_run(self) -> None:
        """Fails: run_pipeline_with_context does not exist yet; subprocess guard."""
        from caliper.agent.tool_helpers import run_pipeline_with_context
        from caliper.composition.bootstrap import bootstrap_test

        ctx = bootstrap_test()
        with patch("subprocess.run") as mock_subproc:
            run_pipeline_with_context(
                context=ctx,
                diff_text="diff --git a/requirements.txt b/requirements.txt\n+requests==2.31.0\n",
                pr_url="https://github.com/org/repo/pull/1",
                team="platform",
                repo_path=".",
            )
            mock_subproc.assert_not_called()

    def test_tool_helpers_review_repository_is_same_object_as_use_cases(self) -> None:
        """Fails: tool_helpers does not import review_repository yet.

        Once implemented, the symbol must be the same function object, not a copy.
        """
        import caliper.agent.tool_helpers as th
        from caliper.core.use_cases import review_repository as canonical

        th_fn = getattr(th, "review_repository", None)
        assert th_fn is canonical, (
            "tool_helpers.review_repository must be the exact same object as "
            "caliper.core.use_cases.review_repository (#184)"
        )
