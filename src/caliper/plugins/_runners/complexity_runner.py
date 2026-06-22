"""Lizard + Radon complexity subprocess runner.
# tested-by: tests/unit/test_complexity_runner.py
"""

from __future__ import annotations

import json
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

_JS_TS_EXTS = {".js", ".ts", ".jsx", ".tsx"}


def _halstead_mi(nloc: int, ccn: int, tokens: int) -> float:
    """Return the Halstead-approximated Maintainability Index clamped to [0, 100]."""
    safe_nloc = nloc or 1
    safe_tokens = tokens or (safe_nloc * 5)
    halstead_volume = safe_tokens * math.log2(max(safe_tokens * 0.5, 2))
    mi = 171.0 - 5.2 * math.log(max(halstead_volume, 1)) - 0.23 * ccn - 16.2 * math.log(safe_nloc)
    return max(0.0, min(100.0, mi))


def _apply_escomplex_mi(
    functions: list[dict],
    js_ts_files: list[str],
    repo_path: str,
    timeout: int,
) -> None:
    """Override maintainability_index for JS/TS functions using escomplex.

    Mutates *functions* in-place.  Falls back silently to the existing
    Halstead approximation when escomplex is not installed or times out,
    emitting a warning in both cases.
    """
    try:
        result = subprocess.run(
            ["escomplex", "--format", "json", *js_ts_files],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=repo_path,
            check=False,
        )
        data = json.loads(result.stdout or "{}")
        # Build a file → MI map from escomplex output
        mi_by_file: dict[str, float] = {}
        for report in data.get("reports", []):
            path = report.get("path", "")
            mi_val = report.get("maintainability")
            if path and mi_val is not None:
                mi_by_file[path] = float(mi_val)

        for fn in functions:
            file_path = fn.get("file", "")
            if Path(file_path).suffix in _JS_TS_EXTS and file_path in mi_by_file:
                mi = max(0.0, min(100.0, mi_by_file[file_path]))
                grade = "A" if mi >= 20 else ("B" if mi >= 10 else "C")
                fn["maintainability_index"] = f"{grade} ({mi:.1f})"

    except FileNotFoundError:
        logger.warning(
            "complexity.escomplex_not_installed",
            fallback="halstead_approximation",
            detail="escomplex not found; install with: npm install -g escomplex-cli",
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            "complexity.escomplex_timeout",
            fallback="halstead_approximation",
        )
    except (json.JSONDecodeError, ValueError, KeyError):
        logger.warning(
            "complexity.escomplex_parse_error",
            fallback="halstead_approximation",
        )
    except Exception:
        logger.exception("complexity.escomplex_failed")


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

    # JS/TS override: use escomplex for accurate Halstead MI
    js_ts_files = [f for f in supported if Path(f).suffix in _JS_TS_EXTS]
    if js_ts_files:
        _apply_escomplex_mi(functions, js_ts_files, repo_path, timeout)

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
