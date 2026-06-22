"""cfn-nag subprocess runner."""

from __future__ import annotations

import json
import subprocess

import structlog

logger = structlog.get_logger(__name__)

_SEVERITY_MAP = {
    "FAIL": "critical",
    "WARN": "warning",
}


def run_cfn_nag(
    cfn_files: list[str],
    repo_path: str,
    timeout: int = 60,
) -> dict:
    if not cfn_files:
        return {"findings": [], "files_scanned": 0}

    findings: list[dict] = []

    for file_path in cfn_files:
        cmd = ["cfn_nag_scan", "--input-path", file_path, "--output-format", "json"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=repo_path,
                check=False,
            )
            if result.returncode != 0:
                # cfn-nag exits non-zero both when it finds violations (stdout
                # contains valid JSON) and when it crashes (empty / garbled
                # stdout).  Only the crash case is an error.
                stdout_is_valid_json = False
                if result.stdout:
                    try:
                        json.loads(result.stdout)
                        stdout_is_valid_json = True
                    except json.JSONDecodeError:
                        pass
                if not stdout_is_valid_json:
                    from caliper.core.errors import ErrorCode, error_msg

                    msg = error_msg(
                        ErrorCode.BINARY_CRASHED,
                        "cfn-nag",
                        exit_code=result.returncode,
                    )
                    logger.warning(
                        "cfn_nag.crashed",
                        error=msg,
                        returncode=result.returncode,
                    )
                    return {"error": msg, "findings": []}
            if result.stdout:
                file_findings = _parse_output(result.stdout, file_path)
                findings.extend(file_findings)
            elif result.returncode == 0:
                from caliper.core.errors import ErrorCode, error_msg

                msg = error_msg(ErrorCode.BINARY_CRASHED, "cfn-nag", exit_code=0)
                logger.warning("cfn_nag.empty_stdout")
                return {"error": msg, "findings": []}
        except ValueError:
            from caliper.core.errors import ErrorCode, error_msg

            msg = error_msg(ErrorCode.BINARY_CRASHED, "cfn-nag", exit_code=result.returncode)
            logger.warning("cfn_nag.invalid_json", returncode=result.returncode)
            return {"error": msg, "findings": []}
        except FileNotFoundError:
            from caliper.core.errors import ErrorCode, error_msg

            msg = error_msg(ErrorCode.NOT_INSTALLED, "cfn-nag")
            logger.warning("cfn_nag.not_installed", error=msg)
            raise
        except subprocess.TimeoutExpired:
            from caliper.core.errors import ErrorCode, error_msg

            msg = error_msg(ErrorCode.TIMEOUT, "cfn-nag", timeout=timeout)
            logger.warning("cfn_nag.timeout", error=msg)
            raise
        except Exception:
            from caliper.core.errors import ErrorCode, error_msg

            msg = error_msg(ErrorCode.BINARY_CRASHED, "cfn-nag", exit_code=-1)
            logger.exception("cfn_nag.failed")
            raise

    return {
        "findings": findings,
        "files_scanned": len(cfn_files),
        "finding_count": len(findings),
    }


def _parse_output(stdout: str, default_file: str) -> list[dict]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("cfn-nag produced invalid JSON") from exc

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
