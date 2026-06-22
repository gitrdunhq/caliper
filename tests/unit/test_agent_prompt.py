"""Tests for agent system prompt module.
# tested-by: tests/unit/test_agent_prompt.py
"""

from __future__ import annotations

from caliper.agent.prompt import build_system_prompt

_ALL_DIMENSIONS = [
    "NECESSITY",
    "MINIMALITY",
    "MAINTENANCE",
    "SECURITY",
    "EXPOSURE",
    "BLAST_RADIUS",
    "ALTERNATIVES",
    "BEHAVIORAL",
]


def test_system_prompt_contains_all_eight_dimensions():
    prompt = build_system_prompt(policy_version="1.0.0")
    for dim in _ALL_DIMENSIONS:
        assert dim in prompt, f"Missing dimension: {dim}"


def test_system_prompt_contains_foreman_identity():
    prompt = build_system_prompt(policy_version="1.0.0")
    assert "Foreman" in prompt


def test_build_system_prompt_injects_policy_version():
    prompt = build_system_prompt(policy_version="2.5.1")
    assert "v2.5.1" in prompt


def test_build_system_prompt_injects_alternatives():
    prompt = build_system_prompt(
        policy_version="1.0.0",
        alternatives=["httpx", "urllib3"],
    )
    assert "httpx" in prompt
    assert "urllib3" in prompt


def test_build_system_prompt_no_alternatives_section_when_none():
    prompt = build_system_prompt(policy_version="1.0.0")
    assert "Approved alternative packages" not in prompt


def test_system_prompt_contains_semgrep_guidance():
    prompt = build_system_prompt(policy_version="1.0.0")
    assert "Semgrep" in prompt
    assert "Code Pattern" in prompt


def test_system_prompt_contains_comment_format():
    prompt = build_system_prompt(policy_version="1.0.0")
    assert "🟢" in prompt
    assert "🔴" in prompt
    assert "APPROVED" in prompt
    assert "REJECTED" in prompt


def test_system_prompt_contains_opa_gate_rule():
    prompt = build_system_prompt(policy_version="1.0.0")
    assert "OPA" in prompt
    assert "override" in prompt.lower()


def test_system_prompt_mentions_three_tools():
    prompt = build_system_prompt(policy_version="1.0.0")
    assert "evaluate_change" in prompt
    assert "check_package" in prompt
    assert "scan_code" in prompt
