"""Tests for agent entry point and orchestrator.
# tested-by: tests/unit/test_agent_main.py
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

pytest.importorskip("agent_framework", reason="agent_framework not installed (caliper[copilot])")

from caliper.agent.config import AgentSettings, EnforcementMode


def _make_settings(**overrides) -> AgentSettings:
    defaults = {
        "github_token": "ghp_test_token_123",
        "enforcement_mode": "warn",
        "repo_path": "./test_repo",
    }
    defaults.update(overrides)
    return AgentSettings(**defaults)


class TestForemanAgent:
    @pytest.mark.asyncio
    async def test_run_posts_reviewing_comment_first(self):
        from caliper.agent.main import ForemanAgent

        config = _make_settings()
        agent = ForemanAgent(config)

        with (
            patch.object(
                agent,
                "_post_comment",
                new_callable=AsyncMock,
            ) as mock_comment,
            patch.object(agent, "_run_deterministic_pipeline", return_value=False),
            patch.object(
                agent,
                "_run_agent_session",
                new_callable=AsyncMock,
                return_value="## 🟢 APPROVED `requests@2.31.0`",
            ),
            patch.object(agent, "_set_check_status", new_callable=AsyncMock),
        ):
            await agent.run(
                diff_text="diff --git a/requirements.txt\n+requests==2.31.0",
                pr_url="https://github.com/org/repo/pull/1",
                pr_number=1,
                repo_owner="org",
                repo_name="repo",
                team="platform",
            )
            assert mock_comment.call_count >= 1
            first_body = mock_comment.call_args_list[0].args[3]
            assert "⏳" in first_body

    @pytest.mark.asyncio
    async def test_block_mode_reject_from_deterministic_pipeline(self):
        """#205: block enforcement comes from the pipeline verdict, not LLM prose."""
        from caliper.agent.main import ForemanAgent

        config = _make_settings(enforcement_mode="block")
        agent = ForemanAgent(config)

        with (
            patch.object(agent, "_post_comment", new_callable=AsyncMock),
            patch.object(agent, "_run_deterministic_pipeline", return_value=True),
            patch.object(
                agent,
                "_run_agent_session",
                new_callable=AsyncMock,
                # The LLM narrates approval prose — this must NOT override the
                # deterministic reject verdict computed above.
                return_value="## 🟢 APPROVED `evil@0.1.0`",
            ),
            patch.object(agent, "_set_check_status", new_callable=AsyncMock),
        ):
            result = await agent.run(
                diff_text="diff --git a/requirements.txt\n+evil==0.1.0",
                pr_url="https://github.com/org/repo/pull/1",
                pr_number=1,
                repo_owner="org",
                repo_name="repo",
                team="platform",
            )
            assert result["exit_code"] == 1

    @pytest.mark.asyncio
    async def test_block_mode_approve_from_deterministic_pipeline_exits_zero(self):
        """#205: an LLM that free-associates 'reject' in prose must not force a block."""
        from caliper.agent.main import ForemanAgent

        config = _make_settings(enforcement_mode="block")
        agent = ForemanAgent(config)

        with (
            patch.object(agent, "_post_comment", new_callable=AsyncMock),
            patch.object(agent, "_run_deterministic_pipeline", return_value=False),
            patch.object(
                agent,
                "_run_agent_session",
                new_callable=AsyncMock,
                return_value="This package looks fine, definitely not a reject.",
            ),
            patch.object(agent, "_set_check_status", new_callable=AsyncMock),
        ):
            result = await agent.run(
                diff_text="diff --git a/requirements.txt\n+requests==2.31.0",
                pr_url="https://github.com/org/repo/pull/1",
                pr_number=1,
                repo_owner="org",
                repo_name="repo",
                team="platform",
            )
            assert result["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_warn_mode_reject_exits_zero(self):
        from caliper.agent.main import ForemanAgent

        config = _make_settings(enforcement_mode="warn")
        agent = ForemanAgent(config)

        with (
            patch.object(agent, "_post_comment", new_callable=AsyncMock),
            patch.object(agent, "_run_deterministic_pipeline", return_value=True),
            patch.object(
                agent,
                "_run_agent_session",
                new_callable=AsyncMock,
                return_value="## 🔴 REJECTED `evil@0.1.0`\n\n**Decision**: reject",
            ),
            patch.object(agent, "_set_check_status", new_callable=AsyncMock),
        ):
            result = await agent.run(
                diff_text="diff --git a/requirements.txt\n+evil==0.1.0",
                pr_url="https://github.com/org/repo/pull/1",
                pr_number=1,
                repo_owner="org",
                repo_name="repo",
                team="platform",
            )
            assert result["exit_code"] == 0
            assert result["comments_posted"] > 0

    @pytest.mark.asyncio
    async def test_log_mode_no_comment_posted(self):
        from caliper.agent.main import ForemanAgent

        config = _make_settings(enforcement_mode="log")
        agent = ForemanAgent(config)

        with (
            patch.object(
                agent,
                "_post_comment",
                new_callable=AsyncMock,
            ) as mock_comment,
            patch.object(agent, "_run_deterministic_pipeline", return_value=True),
            patch.object(
                agent,
                "_run_agent_session",
                new_callable=AsyncMock,
                return_value="## 🔴 REJECTED `evil@0.1.0`",
            ),
            patch.object(agent, "_set_check_status", new_callable=AsyncMock),
        ):
            result = await agent.run(
                diff_text="diff --git a/requirements.txt\n+evil==0.1.0",
                pr_url="https://github.com/org/repo/pull/1",
                pr_number=1,
                repo_owner="org",
                repo_name="repo",
                team="platform",
            )
            assert result["exit_code"] == 0
            mock_comment.assert_not_called()

    @pytest.mark.asyncio
    async def test_pipeline_failure_exits_zero_in_non_block_mode(self):
        from caliper.agent.main import ForemanAgent

        config = _make_settings(enforcement_mode="warn")
        agent = ForemanAgent(config)

        with (
            patch.object(agent, "_post_comment", new_callable=AsyncMock),
            patch.object(
                agent,
                "_run_deterministic_pipeline",
                side_effect=RuntimeError("scanner down"),
            ),
            patch.object(agent, "_run_agent_session", new_callable=AsyncMock),
            patch.object(agent, "_set_check_status", new_callable=AsyncMock),
        ):
            result = await agent.run(
                diff_text="diff --git a/requirements.txt\n+requests==2.31.0",
                pr_url="https://github.com/org/repo/pull/1",
                pr_number=1,
                repo_owner="org",
                repo_name="repo",
                team="platform",
            )
            assert result["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_pipeline_failure_fails_closed_in_block_mode(self):
        """An incomplete review must not silently approve when block mode is on."""
        from caliper.agent.main import ForemanAgent

        config = _make_settings(enforcement_mode="block")
        agent = ForemanAgent(config)

        with (
            patch.object(agent, "_post_comment", new_callable=AsyncMock),
            patch.object(
                agent,
                "_run_deterministic_pipeline",
                side_effect=RuntimeError("scanner down"),
            ),
            patch.object(agent, "_run_agent_session", new_callable=AsyncMock),
            patch.object(agent, "_set_check_status", new_callable=AsyncMock),
        ):
            result = await agent.run(
                diff_text="diff --git a/requirements.txt\n+requests==2.31.0",
                pr_url="https://github.com/org/repo/pull/1",
                pr_number=1,
                repo_owner="org",
                repo_name="repo",
                team="platform",
            )
            assert result["exit_code"] == 1

    @pytest.mark.asyncio
    async def test_llm_session_failure_does_not_bypass_deterministic_reject(self):
        """#205: an LLM crash must not let a real reject verdict slip through."""
        from caliper.agent.main import ForemanAgent

        config = _make_settings(enforcement_mode="block")
        agent = ForemanAgent(config)

        with (
            patch.object(agent, "_post_comment", new_callable=AsyncMock),
            patch.object(agent, "_run_deterministic_pipeline", return_value=True),
            patch.object(
                agent,
                "_run_agent_session",
                new_callable=AsyncMock,
                side_effect=RuntimeError("LLM down"),
            ),
            patch.object(agent, "_set_check_status", new_callable=AsyncMock),
        ):
            result = await agent.run(
                diff_text="diff --git a/requirements.txt\n+evil==0.1.0",
                pr_url="https://github.com/org/repo/pull/1",
                pr_number=1,
                repo_owner="org",
                repo_name="repo",
                team="platform",
            )
            assert result["exit_code"] == 1

    @pytest.mark.asyncio
    async def test_llm_session_failure_does_not_force_block_on_approve(self):
        """#205: an LLM crash must not force a block when the pipeline approved."""
        from caliper.agent.main import ForemanAgent

        config = _make_settings(enforcement_mode="block")
        agent = ForemanAgent(config)

        with (
            patch.object(agent, "_post_comment", new_callable=AsyncMock),
            patch.object(agent, "_run_deterministic_pipeline", return_value=False),
            patch.object(
                agent,
                "_run_agent_session",
                new_callable=AsyncMock,
                side_effect=RuntimeError("LLM down"),
            ),
            patch.object(agent, "_set_check_status", new_callable=AsyncMock),
        ):
            result = await agent.run(
                diff_text="diff --git a/requirements.txt\n+requests==2.31.0",
                pr_url="https://github.com/org/repo/pull/1",
                pr_number=1,
                repo_owner="org",
                repo_name="repo",
                team="platform",
            )
            assert result["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_long_comment_is_truncated(self):
        from caliper.agent.main import ForemanAgent

        config = _make_settings(max_comment_length=500)
        agent = ForemanAgent(config)

        with (
            patch.object(
                agent,
                "_post_comment",
                new_callable=AsyncMock,
            ) as mock_comment,
            patch.object(agent, "_run_deterministic_pipeline", return_value=False),
            patch.object(
                agent,
                "_run_agent_session",
                new_callable=AsyncMock,
                return_value="x" * 2000,
            ),
            patch.object(agent, "_set_check_status", new_callable=AsyncMock),
        ):
            await agent.run(
                diff_text="diff --git a/requirements.txt\n+requests==2.31.0",
                pr_url="https://github.com/org/repo/pull/1",
                pr_number=1,
                repo_owner="org",
                repo_name="repo",
                team="platform",
            )
            posted_body = mock_comment.call_args_list[-1].args[3]
            assert "[truncated]" in posted_body
            assert len(posted_body) < 2000


class TestDeterministicPipelineGate:
    def test_run_deterministic_pipeline_true_on_reject(self):
        from caliper.agent.main import ForemanAgent
        from caliper.core.models import DecisionVerdict

        config = _make_settings()
        agent = ForemanAgent(config)

        fake_decision = type("D", (), {"decision": DecisionVerdict.reject})()

        with patch(
            "caliper.agent.tool_helpers.run_pipeline",
            return_value=([fake_decision], [], {}),
        ):
            assert agent._run_deterministic_pipeline("diff", "pr_url", "team") is True

    def test_run_deterministic_pipeline_true_on_needs_review(self):
        from caliper.agent.main import ForemanAgent
        from caliper.core.models import DecisionVerdict

        config = _make_settings()
        agent = ForemanAgent(config)

        fake_decision = type("D", (), {"decision": DecisionVerdict.needs_review})()

        with patch(
            "caliper.agent.tool_helpers.run_pipeline",
            return_value=([fake_decision], [], {}),
        ):
            assert agent._run_deterministic_pipeline("diff", "pr_url", "team") is True

    def test_run_deterministic_pipeline_false_on_approve(self):
        from caliper.agent.main import ForemanAgent
        from caliper.core.models import DecisionVerdict

        config = _make_settings()
        agent = ForemanAgent(config)

        fake_decision = type("D", (), {"decision": DecisionVerdict.approve})()

        with patch(
            "caliper.agent.tool_helpers.run_pipeline",
            return_value=([fake_decision], [], {}),
        ):
            assert agent._run_deterministic_pipeline("diff", "pr_url", "team") is False


class TestAgentConfig:
    def test_default_enforcement_mode_is_warn(self):
        config = _make_settings()
        assert config.enforcement_mode == EnforcementMode.warn

    def test_enforcement_mode_block_from_env(self):
        config = _make_settings(enforcement_mode="block")
        assert config.enforcement_mode == EnforcementMode.block

    def test_missing_github_token_raises(self):
        with pytest.raises(Exception):
            AgentSettings()

    def test_default_db_dsn_triggers_null_repository(self):
        config = _make_settings()
        assert "localhost" in config.db_dsn


class TestAgentTierViolation:
    """Finding 3 — Tier violation: agent must not pass plugin functions directly.

    GitHubCopilotAgent must NOT receive individual plugin callables
    (evaluate_change, check_package, scan_code, scan_duplicates, scan_k8s,
    analyze_complexity) in its tools= parameter.  Plugin orchestration belongs
    in the use-case / tool_helpers tier, not in the presentation-tier entry
    point.

    TODO: Fix requires creating caliper/agent/use_cases.py, calling
    use_cases.review_repository() in _run_agent_session, and passing tools=[].
    Deferred because it restructures multiple call sites across main.py.
    Track in GitHub issue: [see-something] tier-violation: agent passes plugins directly (main.py:136)
    """

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "DEFERRED: tier violation — _run_agent_session passes plugin callables "
            "directly to GitHubCopilotAgent. Fix requires caliper/agent/use_cases.py "
            "and restructuring _run_agent_session."
        ),
    )
    @pytest.mark.asyncio
    async def test_run_agent_session_does_not_pass_plugin_tools_directly(self):
        """Agent framework must not receive individual plugin functions as tools."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from caliper.agent.main import ForemanAgent

        config = _make_settings()
        agent = ForemanAgent(config)

        captured_tools: list = []

        def fake_copilot_agent(**kwargs):
            captured_tools.extend(kwargs.get("tools", []))
            instance = MagicMock()
            mock_response = MagicMock()
            mock_response.text = "ok"
            mock_response.value = {}
            instance.run = AsyncMock(return_value=mock_response)
            return instance

        with patch(
            "agent_framework_github_copilot.GitHubCopilotAgent",
            side_effect=fake_copilot_agent,
        ):
            await agent._run_agent_session(
                diff_text="diff --git a/requirements.txt b/requirements.txt\n+requests==2.31.0",
                pr_url="https://github.com/org/repo/pull/1",
                team="platform",
            )

        # Plugin functions that MUST NOT be wired directly into the agent framework.
        # Orchestration belongs in tool_helpers / use-case tier.
        # @tool-decorated functions become FunctionTool objects with .name (not .__name__).
        forbidden = {
            "evaluate_change",
            "check_package",
            "scan_code",
            "scan_duplicates",
            "scan_k8s",
            "analyze_complexity",
        }

        def _tool_name(fn) -> str | None:
            # FunctionTool (agent_framework) exposes .name; plain callables use .__name__
            if hasattr(fn, "name") and isinstance(fn.name, str):
                return fn.name
            return getattr(fn, "__name__", None)

        passed_names = {n for fn in captured_tools if (n := _tool_name(fn)) is not None}
        violations = forbidden & passed_names
        assert violations == set(), (
            f"Tier violation: GitHubCopilotAgent received plugin callables directly: "
            f"{violations}. Route through use-case / tool_helpers instead."
        )
