# tested-by: tests/unit/test_github_actions_policy.py
"""GitHub Actions update vetting policy guards."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOWS = _ROOT / ".github" / "workflows"
_ALLOWLIST = _ROOT / ".github" / "actions-allowlist.yml"
_WORKFLOW_POLICY = _WORKFLOWS / "workflow-policy.yml"
_ADR = _ROOT / "docs" / "adr" / "005-github-actions-update-vetting-policy.md"
_CODEOWNERS = _ROOT / "CODEOWNERS"

_USE_LINE = re.compile(r"^\s*uses:\s*(?P<uses>['\"]?[^'\"\s#]+['\"]?)(?P<comment>\s+#.*)?$")
_ACTION_REF = re.compile(r"^(?P<action>[^/@\s]+/[^@\s]+)@(?P<ref>[^@\s]+)$")
_FULL_SHA = re.compile(r"^[A-Fa-f0-9]{40}$")
_VERSION_COMMENT = re.compile(r"#\s*v\d")
_PULL_REQUEST_TARGET_HEAD_PATTERNS = (
    "github.event.pull_request.head",
    "github.head_ref",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.sha",
)


def _load_yaml(path: Path) -> dict[object, object]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    assert isinstance(data, dict), f"{path.relative_to(_ROOT)} must parse to a YAML mapping"
    return data


def _as_mapping(value: object) -> dict[object, object]:
    return value if isinstance(value, dict) else {}


def _as_sequence(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _github_on(workflow: dict[object, object]) -> object:
    # PyYAML follows YAML 1.1, so the GitHub Actions key "on" can parse as True.
    return workflow.get("on", workflow.get(True, {}))


def _workflow_events(workflow: dict[object, object]) -> set[str]:
    on_block = _github_on(workflow)
    if isinstance(on_block, str):
        return {on_block}
    if isinstance(on_block, list):
        return {event for event in on_block if isinstance(event, str)}
    if isinstance(on_block, dict):
        return {str(event) for event in on_block}
    return set()


def _workflow_paths() -> list[Path]:
    return sorted(_WORKFLOWS.glob("*.yml"))


def _allowlisted_actions() -> list[str]:
    data = _load_yaml(_ALLOWLIST)
    actions = data.get("actions")
    assert isinstance(actions, list), ".github/actions-allowlist.yml must define an actions list"
    assert all(isinstance(action, str) for action in actions), "allowlisted actions must be strings"
    return actions


def _remote_uses_lines(path: Path) -> list[tuple[int, str, str]]:
    lines: list[tuple[int, str, str]] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = _USE_LINE.match(raw_line)
        if not match:
            continue
        uses = match.group("uses").strip("'\"")
        if uses.startswith("./"):
            continue
        comment = match.group("comment") or ""
        lines.append((line_number, uses, comment))
    return lines


def _workflow_steps(workflow: dict[object, object]) -> list[dict[object, object]]:
    steps: list[dict[object, object]] = []
    for raw_job in _as_mapping(workflow.get("jobs")).values():
        job = _as_mapping(raw_job)
        for raw_step in _as_sequence(job.get("steps")):
            step = _as_mapping(raw_step)
            if step:
                steps.append(step)
    return steps


def _job_steps(job: dict[object, object]) -> list[dict[object, object]]:
    return [step for raw_step in _as_sequence(job.get("steps")) if (step := _as_mapping(raw_step))]


def _run_text(workflow: dict[object, object]) -> str:
    runs = [step["run"] for step in _workflow_steps(workflow) if isinstance(step.get("run"), str)]
    return "\n".join(runs)


def _job_run_text(job: dict[object, object]) -> str:
    runs = [step["run"] for step in _job_steps(job) if isinstance(step.get("run"), str)]
    return "\n".join(runs)


def test_action_allowlist_is_sorted_and_unique() -> None:
    actions = _allowlisted_actions()

    assert actions == sorted(actions), "Keep action allowlist sorted for reviewable diffs"
    assert len(actions) == len(set(actions)), "Action allowlist must not contain duplicates"


def test_workflows_use_only_sha_pinned_allowlisted_actions() -> None:
    allowlist = set(_allowlisted_actions())

    for path in _workflow_paths():
        for line_number, uses, comment in _remote_uses_lines(path):
            location = f"{path.relative_to(_ROOT)}:{line_number}"
            assert not uses.startswith("docker://"), f"{location} uses an unpinned docker action"

            match = _ACTION_REF.match(uses)
            assert match is not None, f"{location} must use owner/repo@ref syntax"

            action = match.group("action")
            assert action in allowlist, f"{location} uses {action}, which is not in the allowlist"

            ref = match.group("ref")
            assert _FULL_SHA.fullmatch(ref), f"{location} must pin {action} to a full commit SHA"
            assert _VERSION_COMMENT.search(
                comment
            ), f"{location} must include a same-line version comment like '# v4'"


def test_dependabot_updates_github_actions_with_review_labels() -> None:
    dependabot = _load_yaml(_ROOT / ".github" / "dependabot.yml")
    updates = dependabot.get("updates")
    assert isinstance(updates, list), "dependabot.yml must define updates"

    github_actions_updates = [
        update
        for update in updates
        if isinstance(update, dict) and update.get("package-ecosystem") == "github-actions"
    ]
    assert github_actions_updates, "Dependabot must propose GitHub Actions updates"

    root_update = next(
        update for update in github_actions_updates if update.get("directory") == "/"
    )
    labels = root_update.get("labels")
    assert isinstance(labels, list), "GitHub Actions Dependabot updates must define labels"
    assert "github-actions" in labels

    cooldown = root_update.get("cooldown")
    assert isinstance(cooldown, dict), "GitHub Actions updates must define a cooldown"
    assert cooldown.get("default-days") == 14


def test_workflow_policy_runs_read_only_policy_checks() -> None:
    workflow = _load_yaml(_WORKFLOW_POLICY)

    assert "pull_request" in _workflow_events(workflow)
    assert workflow.get("permissions") == {"contents": "read"}

    run_text = _run_text(workflow)
    assert "tests/unit/test_github_actions_policy.py" in run_text
    assert "tests/unit/test_copilot_agent_profiles.py" in run_text
    assert "tests/unit/test_dependabot_policy.py" in run_text
    assert "tests/unit/test_ruff_policy.py" in run_text
    assert "docker.io/library/python@sha256:" in run_text
    assert '-v "$GITHUB_WORKSPACE:/workspace:ro"' in run_text
    assert "UV_PROJECT_ENVIRONMENT=/tmp/caliper-policy-venv" in run_text
    assert "uv run --frozen pytest" in run_text
    assert "CALIPER_ALLOW_HOST_TESTS" not in run_text


def test_pull_request_ci_skips_draft_prs_and_runs_when_ready_for_review() -> None:
    pr_ci_workflows = [
        _WORKFLOWS / "foreman.yml",
        _WORKFLOWS / "workflow-policy.yml",
    ]

    for path in pr_ci_workflows:
        workflow = _load_yaml(path)
        on_block = _github_on(workflow)
        assert isinstance(on_block, dict), f"{path.relative_to(_ROOT)} must define events"
        pull_request = on_block.get("pull_request")
        assert isinstance(
            pull_request, dict
        ), f"{path.relative_to(_ROOT)} must configure pull_request"
        assert "ready_for_review" in pull_request.get(
            "types", []
        ), f"{path.relative_to(_ROOT)} must run CI when a draft PR is marked ready"

        for job_name, raw_job in _as_mapping(workflow.get("jobs")).items():
            job = _as_mapping(raw_job)
            condition = str(job.get("if", ""))
            if condition.strip() in {
                "github.event_name == 'push'",
                "github.event_name == 'workflow_dispatch'",
            }:
                continue
            assert (
                "github.event.pull_request.draft == false" in condition
            ), f"{path.relative_to(_ROOT)} job {job_name} must skip draft PRs"


def test_foreman_keeps_pr_ci_fast_and_full_e2e_manual_only() -> None:
    workflow = _load_yaml(_WORKFLOWS / "foreman.yml")
    assert workflow.get("permissions") == {"contents": "read"}
    on_block = _github_on(workflow)
    assert isinstance(on_block, dict)
    pull_request = _as_mapping(on_block.get("pull_request"))
    pr_types = pull_request.get("types")
    assert isinstance(pr_types, list)
    assert "labeled" in pr_types, "adding api-contract-needed must trigger CI evaluation"
    assert "unlabeled" in pr_types, "removing api-contract-needed must trigger CI evaluation"

    jobs = _as_mapping(workflow.get("jobs"))
    preflight = _as_mapping(jobs.get("preflight"))
    release_key = _as_mapping(jobs.get("release-key"))
    contract = _as_mapping(jobs.get("api_contract"))
    smoke = _as_mapping(jobs.get("e2e_smoke"))
    full = _as_mapping(jobs.get("e2e_full"))
    gate = _as_mapping(jobs.get("gate"))
    classify_step = next(
        step for step in _job_steps(preflight) if step.get("name") == "Classify PR changes"
    )

    assert release_key.get("permissions") == {"contents": "read", "statuses": "write"}
    assert gate.get("permissions") == {
        "contents": "read",
        "issues": "write",
        "pull-requests": "write",
        "statuses": "write",
    }

    outputs = _as_mapping(preflight.get("outputs"))
    assert outputs.get("api_contract") == "${{ steps.classify.outputs.api_contract }}"
    assert outputs.get("api_contract_reason") == "${{ steps.classify.outputs.api_contract_reason }}"
    assert "full_e2e" not in outputs
    assert "full_e2e_reason" not in outputs
    classify_env = _as_mapping(classify_step.get("env"))
    assert (
        classify_env.get("API_CONTRACT_LABEL_PRESENT")
        == "${{ contains(github.event.pull_request.labels.*.name, 'api-contract-needed') }}"
    )
    assert "E2E_LABEL_PRESENT" not in classify_env

    preflight_run = _job_run_text(preflight)
    for contract_path in (
        "tests/contract/",
        "src/caliper/core/use_cases.py",
        "src/caliper/core/registry.py",
        "src/caliper/core/renderer.py",
        "src/caliper/plugins/supply_chain.py",
    ):
        assert contract_path in preflight_run

    for release_only_path in (
        "tests/e2e/",
        "src/caliper/data/scanners/",
        "src/caliper/plugins/_runners/",
        "src/caliper/plugins/typos.py",
    ):
        assert release_only_path not in preflight_run
    assert "src/caliper/plugins/*" not in preflight_run

    contract_step_names = {
        step.get("name") for step in _job_steps(contract) if isinstance(step.get("name"), str)
    }
    smoke_step_names = {
        step.get("name") for step in _job_steps(smoke) if isinstance(step.get("name"), str)
    }
    full_step_names = {
        step.get("name") for step in _job_steps(full) if isinstance(step.get("name"), str)
    }
    assert "Run API contract tests" in contract_step_names
    assert "Run smoke e2e tests" in smoke_step_names
    assert "Cache scanner binaries" not in smoke_step_names
    assert "Add scanners to PATH and warm trivy DB" not in smoke_step_names
    assert "Cache scanner binaries" in full_step_names
    assert "Add scanners to PATH and warm trivy DB" in full_step_names

    contract_run = _job_run_text(contract)
    smoke_run = _job_run_text(smoke)
    full_run = _job_run_text(full)
    assert "tests/contract/ -v --tb=short" in contract_run
    assert "tests/e2e/test_smoke_review.py" in smoke_run
    assert "tests/e2e/ -v --tb=short" in full_run

    contract_condition = str(contract.get("if", ""))
    assert "github.event_name == 'workflow_dispatch'" in contract_condition
    assert "needs.preflight.outputs.api_contract == 'true'" in contract_condition

    full_condition = str(full.get("if", ""))
    assert full_condition.strip() == "github.event_name == 'workflow_dispatch'"

    assert _as_sequence(gate.get("needs")) == [
        "preflight",
        "lint",
        "test",
        "api_contract",
        "e2e_smoke",
        "e2e_full",
        "review",
    ]
    gate_run = _job_run_text(gate)
    assert "API_CONTRACT" in gate_run
    assert "E2E_SMOKE" in gate_run
    assert "E2E_FULL" in gate_run
    assert "api-contract($API_CONTRACT)" in gate_run
    assert "e2e-smoke($E2E_SMOKE)" in gate_run
    assert "e2e-full($E2E_FULL)" in gate_run
    assert "release/manual only" in gate_run
    assert "not blocking gate" not in gate_run


def test_nightly_release_candidate_runs_full_e2e_and_creates_prerelease() -> None:
    workflow = _load_yaml(_WORKFLOWS / "release-candidate.yml")

    assert workflow.get("name") == "Nightly Release Candidate"
    assert workflow.get("concurrency") == {
        "group": "nightly-release-candidate",
        "cancel-in-progress": False,
    }
    assert workflow.get("permissions") == {"contents": "read"}
    events = _workflow_events(workflow)
    assert "schedule" in events
    assert "workflow_dispatch" in events
    assert "pull_request" not in events

    on_block = _github_on(workflow)
    assert isinstance(on_block, dict)
    schedule = _as_sequence(on_block.get("schedule"))
    assert schedule
    assert any(_as_mapping(entry).get("cron") == "0 23 * * *" for entry in schedule)

    dispatch = _as_mapping(on_block.get("workflow_dispatch"))
    inputs = _as_mapping(dispatch.get("inputs"))
    assert {"base_version", "candidate_number", "dry_run"}.issubset(inputs)

    jobs = _as_mapping(workflow.get("jobs"))
    release_candidate = _as_mapping(jobs.get("release_candidate"))
    publish_prerelease = _as_mapping(jobs.get("publish_prerelease"))
    assert release_candidate.get("timeout-minutes") == 25
    outputs = _as_mapping(release_candidate.get("outputs"))
    assert outputs.get("tag_name") == "${{ steps.metadata.outputs.tag_name }}"
    assert outputs.get("base_version") == "${{ steps.metadata.outputs.base_version }}"
    assert publish_prerelease.get("needs") == "release_candidate"
    assert publish_prerelease.get("if") == "inputs.dry_run != true"
    assert publish_prerelease.get("timeout-minutes") == 5
    assert publish_prerelease.get("permissions") == {"contents": "write"}

    release_step_names = {
        step.get("name")
        for step in _job_steps(release_candidate)
        if isinstance(step.get("name"), str)
    }
    publish_step_names = {
        step.get("name")
        for step in _job_steps(publish_prerelease)
        if isinstance(step.get("name"), str)
    }
    assert "Run full e2e tests" in release_step_names
    assert "Run full Caliper review" in release_step_names
    assert "Enforce Caliper release verdict" in release_step_names
    assert "Build distributions" in release_step_names
    assert "Upload release-candidate artifacts" in release_step_names
    assert "Create GitHub prerelease" not in release_step_names
    assert "Download release-candidate artifacts" in publish_step_names
    assert "Create GitHub prerelease" in publish_step_names

    release_run_text = _job_run_text(release_candidate)
    publish_run_text = _job_run_text(publish_prerelease)
    run_text = f"{release_run_text}\n{publish_run_text}"
    assert "tag_name={tag_name}" in run_text
    assert 'f"v{base_version}-rc.{run_date}.{candidate_number}"' in run_text
    assert "uv run pytest tests/e2e/ -v --tb=short" in run_text
    assert "uv run caliper review --repo-path . --all --format sarif" in run_text
    assert "uv run caliper review --repo-path . --all --output" in run_text
    assert 'result.get("ruleId") == "caliper-plugin-error"' in run_text
    assert 're.findall(r"BINARY_CRASHED", markdown)' in run_text
    assert "Release candidate blocked by Caliper review" in run_text
    assert "Nightly release candidate for ${BASE_VERSION}." in run_text
    assert "Daily release candidate" not in run_text
    assert "uv build" in run_text
    assert 'gh release create "$TAG_NAME"' in run_text
    assert ".release-candidate/dist/*.whl" in run_text
    assert ".release-candidate/dist/*.tar.gz" in run_text
    assert ".release-candidate/.temp/release-review.sarif" in run_text
    assert ".release-candidate/.temp/release-review.md" in run_text
    assert "--prerelease" in run_text
    assert "gh release upload" not in publish_run_text

    metadata_step = next(
        step
        for step in _job_steps(release_candidate)
        if step.get("name") == "Prepare candidate metadata"
    )
    metadata_env = _as_mapping(metadata_step.get("env"))
    assert metadata_env.get("INPUT_BASE_VERSION") == "${{ inputs.base_version }}"
    assert metadata_env.get("INPUT_CANDIDATE_NUMBER") == "${{ inputs.candidate_number }}"

    download_step = next(
        step
        for step in _job_steps(publish_prerelease)
        if step.get("name") == "Download release-candidate artifacts"
    )
    download_with = _as_mapping(download_step.get("with"))
    assert (
        download_with.get("name")
        == "release-candidate-${{ needs.release_candidate.outputs.tag_name }}"
    )

    create_step = next(
        step
        for step in _job_steps(publish_prerelease)
        if step.get("name") == "Create GitHub prerelease"
    )
    create_env = _as_mapping(create_step.get("env"))
    assert create_env.get("TAG_NAME") == "${{ needs.release_candidate.outputs.tag_name }}"


def test_release_please_is_compatible_with_immutable_releases() -> None:
    workflow = _load_yaml(_WORKFLOWS / "release-please.yml")
    jobs = _as_mapping(workflow.get("jobs"))
    publish = _as_mapping(jobs.get("publish"))

    step_names = {
        step.get("name") for step in _job_steps(publish) if isinstance(step.get("name"), str)
    }
    assert "Generate SBOM" in step_names
    assert "Upload stable release artifacts" in step_names
    assert "Upload to release" not in step_names

    publish_run = _job_run_text(publish)
    assert "gh release upload" not in publish_run
    assert "cyclonedx-py environment -o sbom.cdx.json --of json" in publish_run

    artifact_step = next(
        step
        for step in _job_steps(publish)
        if step.get("name") == "Upload stable release artifacts"
    )
    artifact_with = _as_mapping(artifact_step.get("with"))
    assert (
        artifact_with.get("name") == "stable-release-${{ needs.release-please.outputs.tag_name }}"
    )
    assert "dist/*" in str(artifact_with.get("path", ""))
    assert "sbom.cdx.json" in str(artifact_with.get("path", ""))


def test_pull_request_target_workflows_do_not_checkout_or_execute_pr_head() -> None:
    for path in _workflow_paths():
        workflow = _load_yaml(path)
        if "pull_request_target" not in _workflow_events(workflow):
            continue

        for step in _workflow_steps(workflow):
            uses = step.get("uses")
            if isinstance(uses, str):
                assert not uses.startswith(
                    "actions/checkout@"
                ), f"{path.relative_to(_ROOT)} must not checkout code under pull_request_target"

            run = step.get("run")
            if isinstance(run, str):
                for pattern in _PULL_REQUEST_TARGET_HEAD_PATTERNS:
                    assert pattern not in run, (
                        f"{path.relative_to(_ROOT)} must not execute pull_request_target code "
                        f"from {pattern}"
                    )


def test_policy_artifacts_are_codeowned_and_documented() -> None:
    assert _ADR.exists(), "Record the GitHub Actions update vetting policy in an ADR"

    codeowners = _CODEOWNERS.read_text(encoding="utf-8")
    required_paths = [
        ".github/agents/",
        ".github/actions-allowlist.yml",
        ".github/workflows/workflow-policy.yml",
        "tests/unit/test_copilot_agent_profiles.py",
        "tests/unit/test_github_actions_policy.py",
        "tests/unit/test_dependabot_policy.py",
        "tests/unit/test_ruff_policy.py",
        "docs/adr/005-github-actions-update-vetting-policy.md",
    ]
    for required_path in required_paths:
        assert required_path in codeowners, f"CODEOWNERS must cover {required_path}"
