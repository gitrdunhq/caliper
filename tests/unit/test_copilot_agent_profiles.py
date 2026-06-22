# tested-by: tests/unit/test_copilot_agent_profiles.py
"""Policy guards for repository Copilot custom agents."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_AGENTS = _ROOT / ".github" / "agents"
_RELEASE_MANAGER = _AGENTS / "release-manager.agent.md"
_FRONTMATTER = re.compile(r"\A---\n(?P<yaml>.*?)\n---\n(?P<body>.*)\Z", re.DOTALL)


def _load_agent(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_text(encoding="utf-8")
    match = _FRONTMATTER.match(raw)
    assert match, f"{path.relative_to(_ROOT)} must use YAML frontmatter"

    metadata = yaml.safe_load(match.group("yaml")) or {}
    assert isinstance(metadata, dict), "agent frontmatter must parse to a mapping"
    return metadata, match.group("body")


def test_release_manager_agent_profile_is_valid_and_scoped() -> None:
    assert _RELEASE_MANAGER.exists(), "release-manager Copilot agent must be checked in"

    metadata, body = _load_agent(_RELEASE_MANAGER)

    assert metadata["name"] == "Release Manager"
    assert metadata["target"] == "github-copilot"
    assert "release" in metadata["description"].lower()
    assert "deterministic" in metadata["description"].lower()
    assert metadata["tools"] == ["read", "search", "edit", "execute", "github/*"]
    profile_metadata = metadata["metadata"]
    assert profile_metadata["owner"] == "release"
    assert profile_metadata["category"] == "operations"
    assert profile_metadata["version"] == "1.0.0"
    assert "deterministic" in profile_metadata["tags"]

    for required_path in (
        ".github/workflows/release-candidate.yml",
        ".github/workflows/release-please.yml",
        ".github/workflows/foreman.yml",
        "tests/unit/test_github_actions_policy.py",
        "tests/unit/test_deterministic_workflow_guards.py",
        "tests/unit/test_deterministic_release_key_guards.py",
        "release-please-config.json",
        ".release-please-manifest.json",
        "pyproject.toml",
        "CHANGELOG.md",
    ):
        assert required_path in body


def test_release_manager_agent_preserves_release_safety_contract() -> None:
    _metadata, body = _load_agent(_RELEASE_MANAGER)
    normalized_body = re.sub(r"\s+", " ", body)

    required_release_rules = (
        "Do not reintroduce path-triggered full E2E",
        "Treat merge status, CI status, release-candidate status, and stable publish",
        "release-key verification path",
        "v<base>-rc.<YYYYMMDD>.<N>",
        "Nightly release candidates",
        "Nightly Release Candidate",
        "GitHub immutable releases must stay enabled",
        "Do not upload assets to a GitHub release after it is published",
        "gh api repos/gitrdunhq/caliper/immutable-releases --jq .",
        "Validation jobs should use read-only permissions",
        "`contents: write`",
        "third-party actions pinned to full commit SHAs",
        "Never store release credentials",
        "Do not use `pull_request_target` to checkout or execute pull-request head",
        "Do not force-push",
        "Do not auto-resolve merge conflicts",
        "Do not guess version numbers",
        "Never include AI attribution",
        "release-please is the default version and changelog authority",
        "Every claim about merge state, CI, version, changelog, tag, GitHub release",
        "Never use `git add -A`",
    )
    for required_rule in required_release_rules:
        assert required_rule in normalized_body

    assert "UV_CACHE_DIR=/tmp/uv-cache CALIPER_ALLOW_HOST_TESTS=1 uv run pytest" in body
    assert "tests/unit/test_copilot_agent_profiles.py" in body
    assert "daily release" not in normalized_body.lower()
