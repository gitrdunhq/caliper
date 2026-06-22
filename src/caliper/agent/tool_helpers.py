"""Internal helpers for Foreman agent tools.
# tested-by: tests/unit/test_agent_tools.py

Pipeline runner, diff parsing, manifest detection, path validation.
Scanner tools now route through PluginRegistry (caliper.plugins).
"""

from __future__ import annotations

import functools
import json
import re
import subprocess
from pathlib import Path

import structlog

from caliper.core.use_cases import ReviewOptions, ReviewResult, review_repository

logger = structlog.get_logger(__name__)

_MANIFEST_FILES: dict[str, str] = {
    "requirements.txt": "pypi",
    "requirements-dev.txt": "pypi",
    "pyproject.toml": "pypi",
    "setup.py": "pypi",
    "setup.cfg": "pypi",
    "Pipfile": "pypi",
    "Pipfile.lock": "pypi",
    "poetry.lock": "pypi",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "go.mod": "golang",
    "go.sum": "golang",
    "Gemfile": "gem",
    "Gemfile.lock": "gem",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "*.csproj": "nuget",
    "packages.config": "nuget",
    "Directory.Packages.props": "nuget",
    "pubspec.yaml": "pub",
    "pubspec.lock": "pub",
    "composer.json": "composer",
    "composer.lock": "composer",
    "mix.exs": "hex",
    "mix.lock": "hex",
    "Package.swift": "swift",
    "Podfile": "cocoapods",
    "Podfile.lock": "cocoapods",
}


_SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.@\-/]+$")

# Characters that are dangerous in shell contexts and must never appear in
# file paths extracted from untrusted diff input.
_SHELL_DANGEROUS_CHARS: frozenset[str] = frozenset(
    {";", "&", "|", "`", "$", "(", ")", "\n", "\r", "\0"}
)


def _is_safe_path(path: str) -> bool:
    """Return False if *path* contains shell metacharacters or control chars."""
    return not any(c in path for c in _SHELL_DANGEROUS_CHARS)


def run_pipeline_with_context(
    context: object,
    diff_text: str,
    pr_url: str,
    team: str,
    repo_path: str,
) -> ReviewResult:
    """Run the review pipeline using the injected ApplicationContext.

    Delegates to review_repository() so callers can inject bootstrap_test()
    for unit tests without any subprocess.run invocations.
    """
    files = extract_changed_files(diff_text)
    options = ReviewOptions()
    return review_repository(context, files, Path(repo_path), options)


def extract_changed_files(diff_text: str) -> list[str]:
    """Extract file paths from a unified diff, skipping deleted files.

    Paths containing shell metacharacters are silently dropped to prevent
    command-injection if callers ever interpolate paths into subprocess calls.
    """
    files: list[str] = []
    lines = diff_text.split("\n")
    i = 0
    while i < len(lines):
        match = re.match(r"^diff --git a/.+ b/(.+)$", lines[i])
        if match:
            path = match.group(1)
            if not _is_safe_path(path):
                logger.warning("extract_changed_files.unsafe_path_blocked", path=path)
                i += 1
                continue
            is_deleted = False
            for j in range(i + 1, len(lines)):
                if lines[j].startswith("diff --git"):
                    break
                if lines[j] == "+++ /dev/null":
                    is_deleted = True
                    break
                # Binary file deletion uses a different marker — no +++ /dev/null line
                if (
                    lines[j].startswith("Binary files")
                    and "/dev/null" in lines[j]
                    and "differ" in lines[j]
                ):
                    is_deleted = True
                    break
            if not is_deleted:
                files.append(path)
        i += 1
    return files


def validate_paths(changed_files: list[str], repo_path: str) -> list[str]:
    """Filter paths to only those safely inside the repo root.

    Rejects paths with shell metacharacters before the traversal check so
    that characters like ';', '|', '$' never reach subprocess interpolation.
    """
    root = Path(repo_path).resolve()
    safe: list[str] = []
    for f in changed_files:
        if not _is_safe_path(f):
            logger.warning("validate_paths.unsafe_path_blocked", path=f)
            continue
        try:
            resolved = (root / f).resolve()
            if resolved.is_relative_to(root):
                safe.append(f)
            else:
                logger.warning("path_traversal_blocked", path=f)
        except (ValueError, OSError):
            logger.warning("path_invalid", path=f)
    return safe


def clean_package_name(name: str) -> str:
    """Strip absolute paths from package names."""
    if name.startswith("/"):
        return Path(name).name
    if "/" in name and not name.startswith("@") and not name.startswith("pkg:"):
        parts = Path(name)
        if parts.suffix in (".txt", ".lock", ".toml", ".json", ".yaml", ".yml"):
            return parts.name
    return name


def clean_triggered_rules(rules: list[str]) -> list[str]:
    """Remove per-package suffixes from triggered rules."""
    return [re.sub(r" for .+$", "", rule) for rule in rules]


def detect_manifest_changes(diff_text: str) -> dict[str, list[str]]:
    """Detect which manifest files changed, grouped by ecosystem."""
    changed = extract_changed_files(diff_text)
    by_eco: dict[str, list[str]] = {}
    for fpath in changed:
        basename = Path(fpath).name
        eco = _MANIFEST_FILES.get(basename)
        if eco:
            by_eco.setdefault(eco, []).append(fpath)
    return by_eco


@functools.cache
def get_agent_settings() -> object:
    """Load AgentSettings from environment. Cached for the process lifetime."""
    from caliper.agent.config import AgentSettings

    return AgentSettings()


def make_pipeline_config() -> object:
    """Build CaliperSettings from AgentSettings."""
    from caliper.core.config import CaliperSettings
    from caliper.core.models import OperatingMode

    agent_cfg = get_agent_settings()
    return CaliperSettings(
        db_dsn=agent_cfg.db_dsn,
        operating_mode=OperatingMode.advise,
        evidence_path=str(agent_cfg.evidence_path),
        opa_policy_path=str(agent_cfg.opa_policy_path),
        enabled_scanners=agent_cfg.enabled_scanners,
        pipeline_timeout=agent_cfg.pipeline_timeout,
    )


def run_syft(repo_path: str, timeout: int = 120) -> dict:
    """Run Syft to generate a CycloneDX SBOM. Returns parsed JSON.

    Raises:
        ValueError: If repo_path does not exist or is not a directory.
    """
    repo_path_obj = Path(repo_path).resolve()
    if not repo_path_obj.exists():
        raise ValueError(f"repo_path does not exist: {repo_path}")
    if not repo_path_obj.is_dir():
        raise ValueError(f"repo_path is not a directory: {repo_path}")

    result = subprocess.run(
        ["syft", f"dir:{repo_path}", "-o", "cyclonedx-json"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.stdout:
        return json.loads(result.stdout)
    return {"components": []}


def _generate_base_sbom(repo_path: str) -> dict:
    """Generate SBOM from the merge-base commit for accurate diffing."""
    try:
        base_ref = subprocess.run(
            ["git", "-C", repo_path, "merge-base", "HEAD", "origin/main"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        base_sha = base_ref.stdout.strip()
        if not base_sha:
            logger.info("sbom.no_merge_base", msg="Using empty baseline")
            return {"components": []}

        # Use git worktree to create an isolated checkout so the shared working
        # tree is never modified — avoids the race condition that occurred when
        # concurrent calls both ran 'git checkout' on the same directory.
        worktree_path = str(Path(repo_path) / ".temp" / f"sbom-base-{base_sha[:8]}")
        subprocess.run(
            ["git", "-C", repo_path, "worktree", "add", worktree_path, base_sha],
            capture_output=True,
            timeout=10,
            check=False,
        )
        try:
            base_sbom = run_syft(worktree_path)
        finally:
            subprocess.run(
                [
                    "git",
                    "-C",
                    repo_path,
                    "worktree",
                    "remove",
                    worktree_path,
                    "--force",
                ],
                capture_output=True,
                timeout=10,
                check=False,
            )
        return base_sbom
    except Exception:
        logger.warning("sbom.base_generation_failed", msg="Using empty baseline")
        return {"components": []}


def run_pipeline(
    diff_text: str,
    pr_url: str,
    team: str,
    repo_path: str,
) -> tuple[list, list[dict], dict]:
    """Run the review pipeline. Returns (decisions, sbom_changes, raw_sbom)."""
    from caliper.composition.bootstrap import bootstrap
    from caliper.core.models import OperatingMode
    from caliper.core.pipeline import ReviewPipeline
    from caliper.core.sbom_diff import diff_sboms

    config = make_pipeline_config()
    pipeline = ReviewPipeline(config, context=bootstrap(config))

    manifest_changes = detect_manifest_changes(diff_text)
    python_manifests = manifest_changes.pop("pypi", [])
    non_python_manifests = manifest_changes

    all_decisions: list = []
    sbom_changes: list[dict] = []
    raw_sbom: dict = {}

    if python_manifests:
        decisions = pipeline.evaluate(
            diff_text=diff_text,
            pr_url=pr_url,
            team=team,
            mode=OperatingMode.advise,
            repo_path=Path(repo_path),
        )
        all_decisions.extend(decisions)

    if non_python_manifests:
        try:
            raw_sbom = run_syft(repo_path)
            before_sbom = _generate_base_sbom(repo_path)
            sbom_changes = diff_sboms(before_sbom, raw_sbom)
            sbom_decisions = pipeline.evaluate_sbom(
                before_sbom=before_sbom,
                after_sbom=raw_sbom,
                pr_url=pr_url,
                team=team,
                mode=OperatingMode.advise,
                repo_path=Path(repo_path),
            )
            all_decisions.extend(sbom_decisions)
        except FileNotFoundError:
            logger.warning("evaluate.syft_not_installed")
        except subprocess.TimeoutExpired:
            logger.warning("evaluate.syft_timeout")
        except Exception:
            logger.exception("evaluate.sbom_path_failed")

    if not python_manifests and not non_python_manifests:
        all_decisions = pipeline.evaluate(
            diff_text=diff_text,
            pr_url=pr_url,
            team=team,
            mode=OperatingMode.advise,
            repo_path=Path(repo_path),
        )

    return all_decisions, sbom_changes, raw_sbom
