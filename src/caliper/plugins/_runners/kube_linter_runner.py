"""kube-linter subprocess runner."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)


def run_kube_linter(
    changed_files: list[str],
    repo_path: str,
    timeout: int = 60,
) -> dict:
    k8s_files = [f for f in changed_files if Path(f).suffix in (".yaml", ".yml")]
    if not k8s_files:
        return {"findings": [], "files_scanned": 0}

    cmd = ["kube-linter", "lint", "--format", "json", *k8s_files]
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
            reports = data.get("Reports") or []
            findings = []
            for r in reports:
                diag = r.get("Diagnostic", {})
                obj = r.get("Object", {}).get("K8sObject", {})
                check_name = diag.get("Check") or r.get("Check") or diag.get("check") or ""
                findings.append(
                    {
                        "check": check_name,
                        "message": diag.get("Message", ""),
                        "remediation": diag.get("Remediation", ""),
                        "object_name": obj.get("Name", ""),
                        "object_kind": obj.get("GroupVersionKind", {}).get("Kind", ""),
                        "file": obj.get("FilePath", ""),
                    }
                )
            return {
                "findings": findings,
                "files_scanned": len(k8s_files),
                "finding_count": len(findings),
            }
        return {"findings": [], "files_scanned": len(k8s_files)}
    except FileNotFoundError:
        from caliper.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.NOT_INSTALLED, "kube-linter")
        logger.warning("kube_linter.not_installed", error=msg)
        return {"findings": [], "files_scanned": 0, "error": msg}
    except subprocess.TimeoutExpired:
        from caliper.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.TIMEOUT, "kube-linter", timeout=60)
        logger.warning("kube_linter.timeout", error=msg)
        return {"findings": [], "files_scanned": 0, "error": msg}
    except Exception:
        from caliper.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.BINARY_CRASHED, "kube-linter", exit_code=-1)
        logger.exception("kube_linter.failed")
        return {"findings": [], "files_scanned": 0, "error": msg}
