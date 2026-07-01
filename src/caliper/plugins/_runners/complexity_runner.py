"""Lizard + Radon complexity subprocess runner.
# tested-by: tests/unit/test_complexity_runner.py

Lizard (CCN/NLOC/Halstead) is the complexity source of record for every
language caliper scans, JS/TS included: as of 2026 no actively maintained,
permissively-licensed CLI computes a JS/TS-specific maintainability index.
Revisit periodically (#441).
"""

from __future__ import annotations

import math
import subprocess
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

_SUPPORTED_EXTS = (
    ".py",
    ".ts",
    ".js",
    ".tsx",
    ".jsx",
    ".go",
    ".java",
    ".rs",
    ".c",
    ".cpp",
    ".swift",
)


def _halstead_mi(nloc: int, ccn: int, tokens: int) -> float:
    """Return the Halstead-approximated Maintainability Index clamped to [0, 100]."""
    safe_nloc = nloc or 1
    safe_tokens = tokens or (safe_nloc * 5)
    halstead_volume = safe_tokens * math.log2(max(safe_tokens * 0.5, 2))
    mi = 171.0 - 5.2 * math.log(max(halstead_volume, 1)) - 0.23 * ccn - 16.2 * math.log(safe_nloc)
    return max(0.0, min(100.0, mi))


def run_complexity(
    changed_files: list[str],
    repo_path: str,
    timeout: int = 60,
) -> dict:
    supported = [f for f in changed_files if Path(f).suffix in _SUPPORTED_EXTS]
    if not supported:
        return {"functions": [], "files_scanned": 0, "summary": {}}

    functions: list[dict] = []

    try:
        result = subprocess.run(
            ["lizard", "--csv", *supported],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=repo_path,
            check=False,
        )
        for line in (result.stdout or "").strip().split("\n"):
            if not line:
                continue
            parts = line.split(",")
            if len(parts) >= 10:
                nloc = int(parts[0])
                ccn = int(parts[1])
                tokens = int(parts[2])
                params = int(parts[3])
                func_length = int(parts[4])
                raw_name = parts[5].split("@")[0] if "@" in parts[5] else parts[5]
                name = raw_name.strip('"').strip("'")
                raw_file = parts[6].strip('"').strip("'")
                try:
                    rel_file = str(Path(raw_file).relative_to(repo_path))
                except ValueError:
                    rel_file = raw_file
                functions.append(
                    {
                        "function": name,
                        "file": rel_file,
                        "nloc": nloc,
                        "cyclomatic_complexity": ccn,
                        "token_count": tokens,
                        "parameters": params,
                        "length": func_length,
                    }
                )
    except FileNotFoundError:
        from caliper.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.NOT_INSTALLED, "lizard")
        logger.warning("complexity.lizard_not_installed", error=msg)
        return {"functions": [], "files_scanned": 0, "summary": {}, "error": msg}
    except subprocess.TimeoutExpired:
        from caliper.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.TIMEOUT, "lizard", timeout=timeout)
        logger.warning("complexity.timeout", error=msg)
        return {"functions": [], "files_scanned": 0, "summary": {}, "error": msg}
    except Exception:
        from caliper.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.BINARY_CRASHED, "lizard", exit_code=-1)
        logger.exception("complexity.lizard_failed")
        return {
            "functions": [],
            "files_scanned": 0,
            "summary": {},
            "error": "unexpected failure",
        }

    for fn in functions:
        mi = _halstead_mi(
            nloc=fn.get("nloc", 1),
            ccn=fn.get("cyclomatic_complexity", 1),
            tokens=fn.get("token_count", 0),
        )
        grade = "A" if mi >= 20 else ("B" if mi >= 10 else "C")
        fn["maintainability_index"] = f"{grade} ({mi:.1f})"

    py_files = [f for f in supported if f.endswith(".py")]
    if py_files:
        try:
            result = subprocess.run(
                ["radon", "mi", "-s", *py_files],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=repo_path,
                check=False,
            )
            for line in (result.stdout or "").strip().split("\n"):
                if " - " in line:
                    parts = line.strip().split(" - ")
                    if len(parts) == 2:
                        fpath = parts[0].strip()
                        score = parts[1].strip()
                        for fn in functions:
                            if fn["file"] == fpath:
                                fn["maintainability_index"] = score
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.debug("complexity.radon_unavailable", error=str(exc))
        except Exception:
            logger.exception("complexity.radon_failed")

    functions.sort(
        key=lambda f: f.get("cyclomatic_complexity", 0),
        reverse=True,
    )

    high = [f for f in functions if f["cyclomatic_complexity"] > 10]
    avg_ccn = (
        sum(f["cyclomatic_complexity"] for f in functions) / len(functions) if functions else 0
    )

    return {
        "functions": functions,
        "files_scanned": len(supported),
        "function_count": len(functions),
        "summary": {
            "total_nloc": sum(f["nloc"] for f in functions),
            "avg_cyclomatic_complexity": round(avg_ccn, 1),
            "high_complexity_count": len(high),
            "max_cyclomatic_complexity": (
                functions[0]["cyclomatic_complexity"] if functions else 0
            ),
        },
    }
