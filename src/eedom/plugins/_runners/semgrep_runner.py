"""Opengrep subprocess runner (semgrep-compatible, registry + local rules)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

_EXT_TO_RULESETS: dict[str, list[str]] = {
    ".py": ["p/python"],
    ".ts": ["r/typescript.lang"],
    ".tsx": ["r/typescript.lang"],
    ".js": ["r/javascript.lang"],
    ".jsx": ["r/javascript.lang"],
    ".tf": ["p/terraform"],
    ".yaml": ["p/kubernetes", "p/docker"],
    ".yml": ["p/kubernetes", "p/docker"],
    ".go": ["p/golang"],
    ".rb": ["p/ruby"],
    ".java": ["p/java"],
    ".sh": ["r/bash.lang"],
}

_NAME_TO_RULESETS: dict[str, list[str]] = {
    "Dockerfile": ["p/docker"],
    "Jenkinsfile": ["p/ci"],
    "docker-compose.yml": ["p/docker"],
    "docker-compose.yaml": ["p/docker"],
}

_ALWAYS_RULESETS = ["p/default", "p/ci"]


def detect_rulesets(changed_files: list[str]) -> list[str]:
    rulesets = list(_ALWAYS_RULESETS)
    for f in changed_files:
        ext = Path(f).suffix
        if ext in _EXT_TO_RULESETS:
            for rs in _EXT_TO_RULESETS[ext]:
                if rs not in rulesets:
                    rulesets.append(rs)
        name = Path(f).name
        if name in _NAME_TO_RULESETS:
            for rs in _NAME_TO_RULESETS[name]:
                if rs not in rulesets:
                    rulesets.append(rs)
    return rulesets


def _abort_detail(data: dict, returncode: int) -> str | None:
    """Return failure detail when opengrep aborted the scan, else None.

    Opengrep can abort the ENTIRE scan (e.g. one broken symlink in the
    target list) while still printing valid JSON: empty ``results`` plus
    ``level=error`` entries, exit code >= 2. Treating that as a clean scan
    is fail-open (#396) — the caller must see a scanner error instead.
    """
    errors = data.get("errors") or []
    fatal_msgs = [
        str(e.get("message") or "unknown error")
        for e in errors
        if isinstance(e, dict) and e.get("level") == "error"
    ]
    if returncode >= 2:
        return fatal_msgs[0] if fatal_msgs else f"exit code {returncode}"
    if not data.get("results") and fatal_msgs:
        return fatal_msgs[0]
    return None


def _is_excluded(check_id: str, exclude_rules: list[str]) -> bool:
    """True when *check_id* matches an excluded rule id.

    Opengrep rewrites local-rule ids with dotted path prefixes (e.g.
    ``policies.semgrep.path-traversal``), so a bare rule id matches either
    the full check_id or its trailing dotted segment — never a substring.
    """
    return any(check_id == rule or check_id.endswith(f".{rule}") for rule in exclude_rules)


def run_semgrep(
    changed_files: list[str],
    repo_path: str,
    timeout: int = 120,
    extra_config_dirs: list[str] | None = None,
    exclude_rules: list[str] | None = None,
) -> dict:
    if not changed_files:
        return {"results": [], "errors": []}

    rulesets = detect_rulesets(changed_files)
    org_rules = Path(repo_path) / "policies" / "semgrep"

    config_args: list[str] = []
    for rs in rulesets:
        config_args.extend(["--config", rs])
    if org_rules.is_dir():
        config_args.extend(["--config", str(org_rules)])
    for extra_dir in extra_config_dirs or []:
        if Path(extra_dir).is_dir():
            config_args.extend(["--config", extra_dir])
        else:
            logger.debug("semgrep.extra_config_dir_missing", path=extra_dir)

    exclude_args: list[str] = []
    for rule_id in exclude_rules or []:
        exclude_args.extend(["--exclude-rule", rule_id])

    cmd = ["opengrep", *config_args, *exclude_args, "--json", *changed_files]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=repo_path,
            check=False,
        )
        if result.stdout:
            data = json.loads(result.stdout)
            abort_detail = _abort_detail(data, result.returncode)
            if abort_detail is not None:
                from eedom.core.errors import ErrorCode, error_msg

                msg = error_msg(ErrorCode.SCANNER_DEGRADED, "opengrep", detail=abort_detail)
                logger.warning(
                    "opengrep.scan_aborted",
                    error=msg,
                    exit_code=result.returncode,
                )
                return {"results": [], "errors": [{"message": msg}], "status": "error"}
            if exclude_rules and isinstance(data.get("results"), list):
                # Post-filter: --exclude-rule only matches exact ids, but
                # opengrep prefixes local-rule ids with their dotted path
                # (policies.semgrep.<rule>). Filtering here is backend-agnostic.
                data["results"] = [
                    r
                    for r in data["results"]
                    if not _is_excluded(str(r.get("check_id", "")), exclude_rules)
                ]
            return data
        return {
            "results": [],
            "errors": [{"message": "no output", "level": "warn"}],
            "status": "degraded",
        }
    except FileNotFoundError:
        from eedom.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.NOT_INSTALLED, "opengrep")
        logger.warning("opengrep.not_installed", error=msg)
        return {"results": [], "errors": [{"message": msg}], "status": "error"}
    except subprocess.TimeoutExpired:
        from eedom.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.TIMEOUT, "opengrep", timeout=timeout)
        logger.warning("opengrep.timeout", error=msg)
        return {"results": [], "errors": [{"message": msg}], "status": "error"}
    except json.JSONDecodeError:
        from eedom.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.PARSE_ERROR, "opengrep")
        logger.warning("opengrep.parse_error", error=msg)
        return {"results": [], "errors": [{"message": msg}], "status": "error"}
    except Exception:
        from eedom.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.BINARY_CRASHED, "opengrep", exit_code=-1)
        logger.exception("opengrep.failed")
        return {"results": [], "errors": [{"message": msg}], "status": "error"}


class OpengrepRunner:
    """SemgrepRunnerPort adapter over run_semgrep (the opengrep CLI)."""

    def run(
        self,
        changed_files: list,
        repo_path: str,
        timeout: int = 120,
        extra_config_dirs: list | None = None,
        exclude_rules: list | None = None,
    ) -> dict:
        return run_semgrep(
            changed_files,
            repo_path,
            timeout=timeout,
            extra_config_dirs=extra_config_dirs,
            exclude_rules=exclude_rules,
        )


from eedom.core.registries import RULE_RUNNERS  # noqa: E402  (registration wiring)


@RULE_RUNNERS.register("semgrep")
def build_semgrep_runner() -> OpengrepRunner:
    return OpengrepRunner()
