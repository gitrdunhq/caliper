"""Opengrep subprocess runner — pinned local rules only, never the registry.

Community rules are read from a local checkout of semgrep/semgrep-rules whose
commit is pinned in the Dockerfile (``SEMGREP_RULES_COMMIT``) and baked into the
image at ``/opt/caliper/semgrep-rules``. Registry packs (``p/default``,
``p/python``, ...) are never passed to opengrep: they are fetched over the network
at scan time and change under you between runs, which a deterministic gate cannot
tolerate. Org rules (caliper's own ``policies/semgrep``) are passed explicitly so
they apply to every target, not only to caliper's own checkout.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

# File suffix -> language directories inside the semgrep-rules snapshot.
_EXT_TO_RULE_DIRS: dict[str, list[str]] = {
    ".py": ["python"],
    ".ts": ["typescript"],
    ".tsx": ["typescript"],
    ".js": ["javascript"],
    ".jsx": ["javascript"],
    ".tf": ["terraform"],
    ".hcl": ["terraform"],
    ".yaml": ["yaml"],
    ".yml": ["yaml"],
    ".go": ["go"],
    ".rb": ["ruby"],
    ".java": ["java"],
    ".kt": ["kotlin"],
    ".rs": ["rust"],
    ".swift": ["swift"],
    ".php": ["php"],
    ".cs": ["csharp"],
    ".sh": ["bash"],
    ".json": ["json"],
    ".html": ["html"],
}

# Exact file name -> snapshot directories.
_NAME_TO_RULE_DIRS: dict[str, list[str]] = {
    "Dockerfile": ["dockerfile"],
    "docker-compose.yml": ["yaml"],
    "docker-compose.yaml": ["yaml"],
}

# Cross-language rules (secrets, CI, templating) that always apply.
_ALWAYS_RULE_DIRS = ["generic"]


def detect_rule_dirs(changed_files: list[str]) -> list[str]:
    """Return the snapshot sub-directory names the changed files call for, in order."""
    dirs = list(_ALWAYS_RULE_DIRS)
    for f in changed_files:
        for d in _EXT_TO_RULE_DIRS.get(Path(f).suffix, []) + _NAME_TO_RULE_DIRS.get(
            Path(f).name, []
        ):
            if d not in dirs:
                dirs.append(d)
    return dirs


def _snapshot_configs(rules_dir: str | None, changed_files: list[str]) -> list[str]:
    """Resolve snapshot sub-dirs to existing paths; fail-open to none (never the registry)."""
    if not rules_dir:
        return []
    root = Path(rules_dir)
    if not root.is_dir():
        logger.warning(
            "semgrep.rules_snapshot_missing",
            path=str(root),
            msg="community rules skipped; set CALIPER_SEMGREP_RULES_DIR to a rules checkout",
        )
        return []
    out: list[str] = []
    for d in detect_rule_dirs(changed_files):
        p = root / d
        if p.is_dir():
            out.append(str(p))
        else:
            logger.debug("semgrep.rules_snapshot_dir_missing", path=str(p))
    return out


def _org_configs(
    org_rules_dir: str | None, repo_path: str, community_rules_dir: str | None = None
) -> list[str]:
    """Caliper's packaged org rules, the baked caliper-community-rules snapshot, and the
    target's own policies/semgrep, deduplicated. A configured-but-absent dir is skipped."""
    out: list[str] = []
    seen: set[Path] = set()
    for cand in (
        org_rules_dir,
        community_rules_dir,
        str(Path(repo_path) / "policies" / "semgrep"),
    ):
        if not cand:
            continue
        p = Path(cand)
        if p.is_dir() and p.resolve() not in seen:
            seen.add(p.resolve())
            out.append(str(p))
    return out


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


def _dedupe_config_dirs(dirs: list[str]) -> list[str]:
    """Drop exact and nested duplicates, first-seen order preserved (#548).

    ``--config <dir>`` loads every rule file under ``<dir>`` recursively — the
    three sources feeding this (the pinned community snapshot's per-language
    subdirs, the org/community-mirror dirs, and ``.caliper.yaml``'s
    ``extra_config_dirs``) were each deduplicated *within* themselves but
    never against each other. If any two resolved paths were identical, or
    one was a subdirectory of another already passed, opengrep loaded and
    applied that rule tree twice, reporting every match in it twice —
    root cause of the exact-duplicate findings seen in a real PR review.
    """
    kept: list[Path] = []
    out: list[str] = []
    for d in dirs:
        resolved = Path(d).resolve()
        if any(resolved == k or resolved.is_relative_to(k) for k in kept):
            continue
        kept.append(resolved)
        out.append(d)
    return out


def run_semgrep(
    changed_files: list[str],
    repo_path: str,
    timeout: int = 120,
    extra_config_dirs: list[str] | None = None,
    exclude_rules: list[str] | None = None,
    rules_dir: str | None = None,
    org_rules_dir: str | None = None,
    community_rules_dir: str | None = None,
) -> dict:
    if not changed_files:
        return {"results": [], "errors": []}

    candidate_dirs: list[str] = [
        *_snapshot_configs(rules_dir, changed_files),
        *_org_configs(org_rules_dir, repo_path, community_rules_dir),
    ]
    for extra_dir in extra_config_dirs or []:
        if Path(extra_dir).is_dir():
            candidate_dirs.append(extra_dir)
        else:
            logger.debug("semgrep.extra_config_dir_missing", path=extra_dir)

    config_args: list[str] = []
    for cfg in _dedupe_config_dirs(candidate_dirs):
        config_args.extend(["--config", cfg])

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
                from caliper.core.errors import ErrorCode, error_msg

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
        from caliper.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.NOT_INSTALLED, "opengrep")
        logger.warning("opengrep.not_installed", error=msg)
        return {"results": [], "errors": [{"message": msg}], "status": "error"}
    except subprocess.TimeoutExpired:
        from caliper.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.TIMEOUT, "opengrep", timeout=timeout)
        logger.warning("opengrep.timeout", error=msg)
        return {"results": [], "errors": [{"message": msg}], "status": "error"}
    except json.JSONDecodeError:
        from caliper.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.PARSE_ERROR, "opengrep")
        logger.warning("opengrep.parse_error", error=msg)
        return {"results": [], "errors": [{"message": msg}], "status": "error"}
    except Exception:
        from caliper.core.errors import ErrorCode, error_msg

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
        rules_dir: str | None = None,
        org_rules_dir: str | None = None,
        community_rules_dir: str | None = None,
    ) -> dict:
        return run_semgrep(
            changed_files,
            repo_path,
            timeout=timeout,
            extra_config_dirs=extra_config_dirs,
            exclude_rules=exclude_rules,
            rules_dir=rules_dir,
            org_rules_dir=org_rules_dir,
            community_rules_dir=community_rules_dir,
        )


from caliper.core.port_registries import RULE_RUNNERS  # noqa: E402  (registration wiring)


@RULE_RUNNERS.register("semgrep")
def build_semgrep_runner() -> OpengrepRunner:
    return OpengrepRunner()
