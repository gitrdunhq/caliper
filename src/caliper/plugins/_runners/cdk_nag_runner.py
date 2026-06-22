"""cdk-nag subprocess runner — synths CDK app then scans templates with cfn_nag_scan."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

_SEVERITY_MAP = {
    "FAIL": "critical",
    "WARN": "warning",
}


def run_cdk_nag(
    repo_path: str,
    synth_timeout: int = 120,
    scan_timeout: int = 60,
    skip_synth: bool = False,
) -> dict:
    """Run cdk-nag against a CDK project.

    When ``skip_synth`` is False (default), runs ``cdk synth`` first to
    generate fresh templates. When True, scans existing ``cdk.out/``
    templates directly — used for assembly-only repos without ``cdk.json``.
    """
    from caliper.core.errors import ErrorCode, error_msg

    rp = Path(repo_path)
    cdk_out = rp / "cdk.out"

    if not skip_synth:
        try:
            result = subprocess.run(
                ["cdk", "synth", "--quiet"],
                capture_output=True,
                text=True,
                timeout=synth_timeout,
                cwd=repo_path,
                check=False,
            )
            if result.returncode != 0:
                stderr = result.stderr.strip()
                logger.warning(
                    "cdk_nag.synth_failed",
                    returncode=result.returncode,
                    stderr=stderr,
                )
                return {
                    "findings": [],
                    "error": f"cdk synth failed (exit {result.returncode}): {stderr}",
                }
        except FileNotFoundError:
            msg = error_msg(ErrorCode.NOT_INSTALLED, "cdk")
            logger.warning("cdk_nag.cdk_not_installed", error=msg)
            return {"findings": [], "error": msg}
        except subprocess.TimeoutExpired:
            msg = error_msg(ErrorCode.TIMEOUT, "cdk", timeout=synth_timeout)
            logger.warning("cdk_nag.synth_timeout", error=msg)
            return {"findings": [], "error": msg}

    templates = list(cdk_out.glob("*.template.json"))
    if not templates:
        logger.info("cdk_nag.no_templates", cdk_out=str(cdk_out))
        return {"findings": [], "files_scanned": 0}

    all_findings: list[dict] = []

    for template in templates:
        cmd = ["cfn_nag_scan", "--input-path", str(template), "--output-format", "json"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=scan_timeout,
                cwd=repo_path,
                check=False,
            )
            if result.returncode != 0 and not result.stdout:
                msg = error_msg(
                    ErrorCode.BINARY_CRASHED, "cfn_nag_scan", exit_code=result.returncode
                )
                logger.warning("cdk_nag.scan_crashed", error=msg, returncode=result.returncode)
                return {"findings": [], "error": msg}
            if result.stdout:
                file_findings = _parse_output(result.stdout, str(template))
                all_findings.extend(file_findings)
            elif result.returncode == 0:
                msg = error_msg(ErrorCode.BINARY_CRASHED, "cfn_nag_scan", exit_code=0)
                logger.warning("cdk_nag.empty_stdout")
                return {"findings": [], "error": msg}
        except ValueError:
            msg = error_msg(ErrorCode.BINARY_CRASHED, "cfn_nag_scan", exit_code=result.returncode)
            logger.warning("cdk_nag.invalid_json", returncode=result.returncode)
            return {"findings": [], "error": msg}
        except FileNotFoundError:
            msg = error_msg(ErrorCode.NOT_INSTALLED, "cfn_nag_scan")
            logger.warning("cdk_nag.cfn_nag_not_installed", error=msg)
            return {"findings": [], "error": msg}
        except subprocess.TimeoutExpired:
            msg = error_msg(ErrorCode.TIMEOUT, "cfn_nag_scan", timeout=scan_timeout)
            logger.warning("cdk_nag.scan_timeout", error=msg)
            return {"findings": [], "error": msg}
        except Exception:
            msg = error_msg(ErrorCode.BINARY_CRASHED, "cfn_nag_scan", exit_code=-1)
            logger.exception("cdk_nag.scan_failed")
            return {"findings": [], "error": msg}

    return {
        "findings": all_findings,
        "files_scanned": len(templates),
        "finding_count": len(all_findings),
    }


def _parse_output(stdout: str, default_file: str) -> list[dict]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("cfn_nag_scan produced invalid JSON") from exc

    findings: list[dict] = []
    for file_result in data:
        filename = file_result.get("filename", default_file)
        violations = file_result.get("file_results", {}).get("violations", [])
        for v in violations:
            violation_type = v.get("type", "WARN")
            severity = _SEVERITY_MAP.get(violation_type, "warning")
            line_numbers = v.get("line_numbers", [])
            line = line_numbers[0] if line_numbers else 0
            findings.append(
                {
                    "rule_id": v.get("id", ""),
                    "severity": severity,
                    "message": v.get("message", ""),
                    "file": filename,
                    "line": line,
                    "logical_resource_ids": v.get("logical_resource_ids", []),
                }
            )
    return findings
