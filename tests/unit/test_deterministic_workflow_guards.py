# tested-by: tests/unit/test_deterministic_workflow_guards.py
"""Deterministic guards for workflow, container, and release bug classes."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — fix the source code, then this test goes green",
    strict=False,
)

import re
import shlex
import tomllib
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOWS = _ROOT / ".github" / "workflows"

_WRITE_PERMISSION_SCOPES = {
    "actions",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
}

_REQUIRED_GATE_WORKFLOWS = (
    ".github/workflows/foreman.yml",
    ".github/workflows/build-container.yml",
    ".github/workflows/release-please.yml",
    ".github/workflows/dogfood.yml",
)


def _repo_path(relative_path: str) -> Path:
    return _ROOT / relative_path


def _read_text(relative_path: str) -> str:
    return _repo_path(relative_path).read_text(encoding="utf-8")


def _load_yaml(relative_path: str) -> dict[object, object]:
    data = yaml.safe_load(_read_text(relative_path)) or {}
    assert isinstance(data, dict), f"{relative_path} must parse to a YAML mapping"
    return data


def _load_toml(relative_path: str) -> dict[str, object]:
    with _repo_path(relative_path).open("rb") as file:
        data = tomllib.load(file)
    assert isinstance(data, dict), f"{relative_path} must parse to a TOML mapping"
    return data


def _as_mapping(value: object) -> dict[object, object]:
    if isinstance(value, dict):
        return value
    return {}


def _as_sequence(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    return []


def _as_string_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


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


def _runs_on_self_hosted(runs_on: object) -> bool:
    labels = _as_string_list(runs_on)
    return any(label == "self-hosted" for label in labels)


def _write_permissions(permissions: object) -> set[str]:
    if permissions == "write-all":
        return {"write-all"}
    if permissions in (None, "read-all"):
        return set()
    if not isinstance(permissions, dict):
        return set()

    write_scopes = set()
    for scope, value in permissions.items():
        scope_name = str(scope)
        if scope_name in _WRITE_PERMISSION_SCOPES and value == "write":
            write_scopes.add(scope_name)
    return write_scopes


def _job_executes_checked_out_code(job: dict[object, object]) -> bool:
    seen_checkout = False
    for raw_step in _as_sequence(job.get("steps")):
        step = _as_mapping(raw_step)
        uses = step.get("uses")
        if isinstance(uses, str) and uses.startswith("actions/checkout@"):
            seen_checkout = True
            continue
        if seen_checkout and isinstance(step.get("run"), str):
            return True
    return False


def _workflow_run_blocks(relative_path: str) -> list[str]:
    workflow = _load_yaml(relative_path)
    blocks: list[str] = []
    for raw_job in _as_mapping(workflow.get("jobs")).values():
        job = _as_mapping(raw_job)
        for raw_step in _as_sequence(job.get("steps")):
            step = _as_mapping(raw_step)
            run = step.get("run")
            if isinstance(run, str):
                blocks.append(run)
    return blocks


def _workflow_run_text(relative_path: str) -> str:
    return "\n".join(_workflow_run_blocks(relative_path))


def _find_step(relative_path: str, step_name: str) -> dict[object, object]:
    workflow = _load_yaml(relative_path)
    for raw_job in _as_mapping(workflow.get("jobs")).values():
        job = _as_mapping(raw_job)
        for raw_step in _as_sequence(job.get("steps")):
            step = _as_mapping(raw_step)
            if step.get("name") == step_name:
                return step
    raise AssertionError(f"{relative_path} must contain a step named {step_name!r}")


def _make_target_body(target: str) -> str:
    lines = _read_text("Makefile").splitlines()
    body: list[str] = []
    in_target = False
    for line in lines:
        if re.match(rf"^{re.escape(target)}\s*:", line):
            in_target = True
            continue
        if in_target and line and not line.startswith(("\t", " ")):
            break
        if in_target:
            body.append(line)
    return "\n".join(body)


def _dockerfile_workdir(relative_path: str) -> str:
    workdirs = re.findall(r"(?m)^WORKDIR\s+(\S+)", _read_text(relative_path))
    assert workdirs, f"{relative_path} must declare WORKDIR"
    return workdirs[-1]


def _volume_mount_targets(make_body: str) -> list[str]:
    targets: list[str] = []
    matches = re.finditer(r"(?:^|\s)(?:-v|--volume)\s+([\"']?)([^\"'\s]+)\1", make_body)
    for match in matches:
        mount = match.group(2)
        parts = mount.split(":")
        if len(parts) >= 2:
            targets.append(parts[1])
    return targets


def _make_gate_present(run_text: str, target: str) -> bool:
    return bool(re.search(rf"\bmake(?:\s+-C\s+\S+)?\s+{re.escape(target)}\b", run_text))


def _required_test_gate_present(run_text: str) -> bool:
    return _make_gate_present(run_text, "test") or _make_gate_present(run_text, "preflight")


def _required_quality_gate_present(run_text: str) -> bool:
    return _make_gate_present(run_text, "quality-check") or _make_gate_present(
        run_text, "preflight"
    )


def _normalize_package_name(name: str) -> str:
    return name.lower().replace("_", "-")


def _parse_requirement(requirement: str) -> tuple[str, str | None, str | None] | None:
    match = re.match(
        r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(==|>=|<=|~=|>|<)?\s*" r"([A-Za-z0-9_.!+*-]+)?",
        requirement,
    )
    if not match:
        return None
    name, operator, version = match.groups()
    return _normalize_package_name(name), operator, version


def _pyproject_pins(include_dev: bool) -> dict[str, str]:
    pyproject = _load_toml("pyproject.toml")
    project = _as_mapping(pyproject.get("project"))

    requirements = list(_as_sequence(project.get("dependencies")))
    optional_dependencies = _as_mapping(project.get("optional-dependencies"))
    for extra_name, extra_requirements in optional_dependencies.items():
        if extra_name == "all":
            continue
        requirements.extend(_as_sequence(extra_requirements))

    if include_dev:
        dependency_groups = _as_mapping(pyproject.get("dependency-groups"))
        for group_requirements in dependency_groups.values():
            requirements.extend(_as_sequence(group_requirements))

    pins: dict[str, str] = {}
    for raw_requirement in requirements:
        if not isinstance(raw_requirement, str):
            continue
        parsed = _parse_requirement(raw_requirement)
        if parsed is None:
            continue
        name, operator, version = parsed
        if name == "caliper" or operator != "==" or version is None:
            continue
        pins[name] = version
    return pins


def _uv_lock_pins() -> dict[str, str]:
    lock = _load_toml("uv.lock")
    pins: dict[str, str] = {}
    for raw_package in _as_sequence(lock.get("package")):
        package = _as_mapping(raw_package)
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            pins[_normalize_package_name(name)] = version
    return pins


def _dockerfile_run_instructions(relative_path: str) -> list[str]:
    instructions: list[str] = []
    current: list[str] = []

    for line in _read_text(relative_path).splitlines():
        stripped = line.lstrip()
        if stripped.startswith("RUN "):
            if current:
                instructions.append(" ".join(part.strip().rstrip("\\") for part in current))
            current = [line]
            if not line.rstrip().endswith("\\"):
                instructions.append(stripped)
                current = []
            continue

        if current:
            current.append(line)
            if not line.rstrip().endswith("\\"):
                instructions.append(" ".join(part.strip().rstrip("\\") for part in current))
                current = []

    if current:
        instructions.append(" ".join(part.strip().rstrip("\\") for part in current))

    return instructions


def test_pr_workflows_do_not_execute_checked_out_code_on_self_hosted_write_runners() -> None:
    """#201: PR workflows must not run checked-out code on write-scoped self-hosted runners."""
    offenders: list[str] = []

    for workflow_path in sorted(_WORKFLOWS.glob("*.yml")):
        relative_path = workflow_path.relative_to(_ROOT).as_posix()
        workflow = _load_yaml(relative_path)
        if not (_workflow_events(workflow) & {"pull_request", "pull_request_target"}):
            continue

        workflow_permissions = workflow.get("permissions")
        for job_name, raw_job in _as_mapping(workflow.get("jobs")).items():
            job = _as_mapping(raw_job)
            if not _runs_on_self_hosted(job.get("runs-on")):
                continue
            write_scopes = _write_permissions(job.get("permissions", workflow_permissions))
            if write_scopes and _job_executes_checked_out_code(job):
                offenders.append(f"{relative_path}:{job_name} writes {sorted(write_scopes)}")

    assert offenders == [], (
        "PR workflows that execute checked-out code on self-hosted runners must not have "
        f"write-scoped tokens: {offenders}"
    )


def test_make_test_does_not_bind_mount_over_container_built_uv_environment() -> None:
    """#203: make test must not hide the image-built uv environment with a repo bind mount."""
    test_body = _make_target_body("test")
    image_workdir = _dockerfile_workdir("Dockerfile.test")
    mount_targets = _volume_mount_targets(test_body)

    assert image_workdir not in mount_targets, (
        "`make test` bind-mounts the checkout over Dockerfile.test WORKDIR "
        f"{image_workdir}, hiding the image-built uv environment."
    )


def test_make_prod_build_allows_buildkit_insecure_for_docker_uv_steps() -> None:
    """#229: prod builds must permit Dockerfile uv steps that need insecure BuildKit."""
    makefile = _read_text("Makefile")
    prod_build_body = _make_target_body("prod-build")

    assert "RUN --security=insecure" in _read_text(
        "Dockerfile"
    ), "Dockerfile must declare BuildKit insecure mode on uv RUN steps."
    assert (
        "PROD_BUILD_COMMAND ?=" in makefile
    ), "Makefile must centralize prod image build command selection."
    assert "buildx build --allow security.insecure --load" in makefile, (
        "Docker prod builds must use buildx with --allow security.insecure when "
        "the Dockerfile contains RUN --security=insecure."
    )
    assert "$(PROD_BUILD_COMMAND)" in prod_build_body, "prod-build must use PROD_BUILD_COMMAND."


def test_required_workflows_run_container_tests_and_quality_gates() -> None:
    """#213: product workflows must run the required test and quality gates."""
    missing_gates: list[str] = []

    for relative_path in _REQUIRED_GATE_WORKFLOWS:
        run_text = _workflow_run_text(relative_path)
        if not _required_test_gate_present(run_text):
            missing_gates.append(f"{relative_path}: missing `make test` or `make preflight`")
        if not _required_quality_gate_present(run_text):
            missing_gates.append(
                f"{relative_path}: missing `make quality-check` or `make preflight`"
            )

    assert missing_gates == [], "Required workflow gates are absent: " + "; ".join(missing_gates)


def test_foreman_workflow_dispatch_enforcement_mode_is_wired_to_runtime() -> None:
    """#214: foreman workflow_dispatch enforcement_mode must affect runtime behavior."""
    workflow = _load_yaml(".github/workflows/foreman.yml")
    on_block = _as_mapping(_github_on(workflow))
    workflow_dispatch = _as_mapping(on_block.get("workflow_dispatch"))
    dispatch_inputs = _as_mapping(workflow_dispatch.get("inputs"))

    assert "enforcement_mode" in dispatch_inputs, "foreman must expose enforcement_mode"

    jobs_text = _read_text(".github/workflows/foreman.yml").split("jobs:", 1)[1]
    assert (
        "github.event.inputs.enforcement_mode" in jobs_text
        or "inputs.enforcement_mode" in jobs_text
    ), "foreman declares enforcement_mode but never passes the dispatch input to jobs"

    fail_closed_step = _find_step(".github/workflows/foreman.yml", "Fail-closed gate")
    fail_closed_run = str(fail_closed_step.get("run", ""))
    assert "enforcement" in fail_closed_run.lower(), (
        "Fail-closed gate must branch on enforcement_mode so warn/log modes do not behave "
        "like block mode."
    )


def test_release_key_absence_blocks_publish() -> None:
    """#215: release publish must fail closed when the ci/release-key status is absent."""
    workflow = _load_yaml(".github/workflows/release-please.yml")
    jobs = _as_mapping(workflow.get("jobs"))
    publish = _as_mapping(jobs.get("publish"))
    assert "verify-key" in _as_string_list(
        publish.get("needs")
    ), "publish must depend on verify-key"

    verify_step = _find_step(".github/workflows/release-please.yml", "Verify release key")
    verify_run = str(verify_step.get("run", ""))
    no_key_start = verify_run.find('if [ -z "$STORED" ]')
    assert no_key_start != -1, "Verify release key step must explicitly handle absent key"
    no_key_end = verify_run.find("\nfi", no_key_start)
    assert no_key_end != -1, "Absent-key branch must terminate with fi"
    no_key_branch = verify_run[no_key_start:no_key_end]

    assert (
        "exit 1" in no_key_branch and "exit 0" not in no_key_branch
    ), "Missing ci/release-key status must block release publication, not skip verification."


def test_container_only_test_policy_has_no_host_escape_hatches() -> None:
    """#216: tests must not expose host-run bypasses that contradict container-only policy."""
    escape_var = "CALIPER_ALLOW_" + "HOST_TESTS"
    host_target = "test-" + "host"
    scanned_roots = ["Makefile", "tests", ".github"]
    offenders: list[str] = []

    for root_name in scanned_roots:
        root = _repo_path(root_name)
        paths = (
            [root] if root.is_file() else sorted(path for path in root.rglob("*") if path.is_file())
        )
        for path in paths:
            if path == Path(__file__).resolve() or "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if escape_var in text or host_target in text:
                offenders.append(path.relative_to(_ROOT).as_posix())

    assert (
        offenders == []
    ), "Container-only acceptance must not provide host test bypasses: " + ", ".join(offenders)


def test_docker_runtime_python_pins_match_pyproject_and_uv_lock() -> None:
    """#229: runtime Docker Python pins must not drift from pyproject.toml or uv.lock."""
    pyproject_pins = _pyproject_pins(include_dev=False)
    lock_pins = _uv_lock_pins()
    dockerfile = _read_text("Dockerfile")
    run_instructions = _dockerfile_run_instructions("Dockerfile")
    normalized_runs = [" ".join(instruction.split()) for instruction in run_instructions]
    drift: list[str] = []

    for package_name, expected_version in sorted(pyproject_pins.items()):
        locked_version = lock_pins.get(package_name)
        if locked_version != expected_version:
            drift.append(
                f"uv.lock:{package_name} expected {expected_version}, got {locked_version}"
            )

    if "COPY pyproject.toml uv.lock LICENSE README.md ./" not in dockerfile:
        drift.append("Dockerfile must copy pyproject.toml and uv.lock before runtime uv sync")

    required_sync_commands = [
        "uv sync --frozen --no-dev --extra all --no-editable --no-install-project",
        "uv sync --frozen --no-dev --extra all --no-editable",
    ]
    for command in required_sync_commands:
        if not any(command in instruction for instruction in normalized_runs):
            drift.append(f"Dockerfile missing frozen lockfile install command: {command}")

    assert drift == [], "Docker runtime pins drift from pyproject.toml/uv.lock: " + "; ".join(drift)


def test_dockerfile_uv_steps_use_buildkit_insecure_security_under_apparmor() -> None:
    """#229: uv build steps must work on AppArmor-constrained amd64 builders."""
    offenders: list[str] = []

    for relative_path in ("Dockerfile", "Dockerfile.test"):
        for instruction in _dockerfile_run_instructions(relative_path):
            if (
                re.search(r"\buv\s+(?:sync|pip\s+install)\b", instruction)
                and "--security=insecure" not in instruction
            ):
                offenders.append(f"{relative_path}: {instruction}")

    assert (
        offenders == []
    ), "uv RUN steps must declare --security=insecure for AppArmor builders: " + "; ".join(
        offenders
    )


def test_dockerfile_test_uses_locked_uv_sync_without_unpinned_uv_pip_installs() -> None:
    """#229: test image dependencies must come from the frozen uv lock, not ad hoc installs."""
    dockerfile_test = _read_text("Dockerfile.test")
    assert (
        "uv sync --frozen --group dev" in dockerfile_test
    ), "Dockerfile.test must install test dependencies from uv.lock."

    unpinned_installs: list[str] = []
    for match in re.finditer(r"\buv\s+pip\s+install\s+([^\n]+)", dockerfile_test):
        command_tail = match.group(1).strip()
        tokens = shlex.split(command_tail)
        if "-r" in tokens or "--requirement" in tokens:
            continue
        if any("==" in token or token.startswith("-") for token in tokens):
            continue
        unpinned_installs.append(match.group(0))

    assert (
        unpinned_installs == []
    ), "Dockerfile.test must not install unpinned packages outside uv.lock: " + "; ".join(
        unpinned_installs
    )


def test_composite_action_memo_output_uses_unique_delimiter_for_untrusted_memo() -> None:
    """#233: composite action memo output must not use a fixed multiline delimiter."""
    evaluate_step = _find_step("action.yml", "Run dependency review")
    run = str(evaluate_step.get("run", ""))

    assert "memo<<" in run, "Composite action must expose the memo output"

    fixed_delimiters = re.findall(r"<<([A-Z][A-Z0-9_]*(?:EOF|END)[A-Z0-9_]*)", run)
    assert fixed_delimiters == [], (
        "GITHUB_OUTPUT multiline delimiters for untrusted memo text must be generated "
        f"per run, not fixed: {fixed_delimiters}"
    )
    assert re.search(
        r"\b(uuidgen|openssl\s+rand|mktemp|python3\s+-c)\b", run
    ), "Memo output delimiter must be unique per run before appending untrusted memo text."
