"""PMD CPD subprocess runner (detect) + deterministic enrichment (ADR-006).
# tested-by: tests/unit/test_cpd_runner.py

Detect: PMD CPD across every language PMD 7 supports, with a jscpd fallback for
the rest (and when PMD is unavailable) — so duplication detection is as
language-agnostic as the available tools allow, and scans the *actual* changed
files recursively via a file-list (not a non-recursive top-level dir).

Enrich (ADR-006): each clone group is annotated deterministically — the enclosing
symbol per location, the N-way ``occurrences`` count, and a ``suggested_home`` for
consolidation — so a downstream consumer knows *where a shared base belongs*
without re-deriving it. Every step is fail-open: a missing tool or parse error
yields fewer findings, never an exception.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET  # noqa: N817
from pathlib import Path

import structlog

from eedom.core.enrichment import enclosing_symbol as _enclosing_symbol_core

logger = structlog.get_logger(__name__)

# Extension -> PMD 7 CPD language id. Anything not here is routed to the jscpd fallback.
_PMD_LANGUAGES: dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "ecmascript",
    ".jsx": "ecmascript",
    ".mjs": "ecmascript",
    ".cjs": "ecmascript",
    ".go": "go",
    ".rb": "ruby",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".rs": "rust",
    ".c": "cpp",
    ".h": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "cs",
    ".php": "php",
    ".scala": "scala",
    ".sc": "scala",
    ".dart": "dart",
    ".lua": "lua",
    ".groovy": "groovy",
    ".pl": "perl",
    ".pm": "perl",
    ".html": "html",
    ".htm": "html",
    ".xml": "xml",
    ".json": "json",
    ".jsp": "jsp",
    ".jl": "julia",
    ".feature": "gherkin",
}


def _parse_cpd_xml(xml_text: str, lang: str) -> list[dict]:
    """Parse PMD CPD XML output into a list of duplication dicts."""
    dupes: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return dupes
    for dup_el in root.findall("{*}duplication"):
        locs = []
        for file_el in dup_el.findall("{*}file"):
            locs.append(
                {
                    "file": file_el.get("path", ""),
                    "start_line": int(file_el.get("line", "0")),
                    "end_line": int(file_el.get("endline", "0")),
                }
            )
        if len(locs) >= 2:
            fragment_el = dup_el.find("{*}codefragment")
            dupes.append(
                {
                    "tokens": int(dup_el.get("tokens", "0")),
                    "lines": int(dup_el.get("lines", "0")),
                    "language": lang,
                    "locations": locs,
                    "fragment": (fragment_el.text or "")[:200] if fragment_el is not None else "",
                }
            )
    return dupes


def _extract_xml_payload(raw_output: str) -> str:
    """Extract the XML document from mixed command output.

    PMD may prepend log lines before the XML payload. Keep parsing robust by
    slicing from the first XML marker through the end of output.
    """
    if not raw_output:
        return ""
    idx = raw_output.find("<?xml")
    if idx == -1:
        idx = raw_output.find("<pmd-cpd")
    if idx == -1:
        return ""
    return raw_output[idx:]


# --- enrichment (ADR-006): deterministic, fail-open -----------------------------------------------


def _enclosing_symbol(abs_path: str, start_line: int) -> str:
    """Innermost function/class enclosing the location (delegates to the core resolver, SoT)."""
    try:
        text = Path(abs_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    name, _kind = _enclosing_symbol_core(text, start_line, is_python=abs_path.endswith(".py"))
    return name


def _rel(path: str, repo_path: str) -> str:
    try:
        return os.path.relpath(path, repo_path)
    except ValueError:
        return path


def _suggested_home(locations: list[dict], repo_path: str) -> str:
    files = sorted({loc["file"] for loc in locations})
    if len(files) == 1:
        return f"extract a local helper in {_rel(files[0], repo_path)}"
    try:
        common = os.path.commonpath(files)
    except ValueError:
        common = repo_path
    return f"extract a shared module under {_rel(common, repo_path)}/"


def _enrich_clones(dupes: list[dict], repo_path: str) -> list[dict]:
    """Annotate each clone group with enclosing symbols, occurrences, and a consolidation home."""
    for dup in dupes:
        dup["occurrences"] = len(dup.get("locations", []))
        for loc in dup.get("locations", []):
            loc["symbol"] = _enclosing_symbol(loc.get("file", ""), loc.get("start_line", 0))
        dup["suggested_home"] = _suggested_home(dup.get("locations", []), repo_path)
    # Rank by impact: a large block copied many times is the highest-value consolidation.
    dupes.sort(key=lambda d: d.get("tokens", 0) * max(d.get("occurrences", 1), 1), reverse=True)
    return dupes


# --- detection ------------------------------------------------------------------------------------


def _run_pmd_lang(files: list[str], lang: str, min_tokens: int, timeout: int) -> str:
    """Run PMD CPD for one language over an explicit file-list. Returns XML payload ('' on none)."""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(files))
        list_path = fh.name
    try:
        result = subprocess.run(
            [
                "pmd",
                "cpd",
                "--minimum-tokens",
                str(min_tokens),
                "--language",
                lang,
                "--format",
                "xml",
                "--file-list",
                list_path,
                "--no-fail-on-violation",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    finally:
        with contextlib.suppress(OSError):
            os.unlink(list_path)
    payload = _extract_xml_payload(result.stdout or "")
    return payload or _extract_xml_payload(result.stderr or "")


def _jscpd_available() -> bool:
    from shutil import which

    return which("npx") is not None or which("jscpd") is not None


def _run_jscpd(files: list[str], min_tokens: int, timeout: int) -> list[dict]:
    """Fallback detector for languages PMD can't handle (or when PMD is absent). Fail-open."""
    if not files or not _jscpd_available():
        return []
    with tempfile.TemporaryDirectory() as out:
        cmd = [
            "npx",
            "--yes",
            "jscpd",
            *files,
            "--min-tokens",
            str(min_tokens),
            "--reporters",
            "json",
            "--output",
            out,
            "--silent",
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            report = Path(out) / "jscpd-report.json"
            if not report.exists():
                return []
            data = json.loads(report.read_text(encoding="utf-8"))
        except (subprocess.TimeoutExpired, OSError, ValueError):
            return []
    dupes: list[dict] = []
    for d in data.get("duplicates", []):
        locs = []
        for key in ("firstFile", "secondFile"):
            fobj = d.get(key) or {}
            start = fobj.get("start") or (fobj.get("startLoc") or {}).get("line") or 0
            end = fobj.get("end") or (fobj.get("endLoc") or {}).get("line") or 0
            if fobj.get("name"):
                locs.append({"file": fobj["name"], "start_line": int(start), "end_line": int(end)})
        if len(locs) >= 2:
            dupes.append(
                {
                    "tokens": int(d.get("tokens", 0) or d.get("lines", 0)),
                    "lines": int(d.get("lines", 0)),
                    "language": str(d.get("format", "")),
                    "locations": locs,
                    "fragment": (d.get("fragment") or "")[:200],
                }
            )
    return dupes


def run_cpd(
    changed_files: list[str],
    repo_path: str,
    min_tokens: int = 75,
    timeout: int = 60,
) -> dict:
    if not changed_files:
        return {"duplicates": [], "files_scanned": 0}

    repo = Path(repo_path)
    abs_files: list[str] = []
    for f in changed_files:
        p = Path(f)
        abs_files.append(str(p if p.is_absolute() else repo / f))

    by_lang: dict[str, list[str]] = {}
    jscpd_files: list[str] = []
    for f in abs_files:
        lang = _PMD_LANGUAGES.get(Path(f).suffix.lower())
        if lang:
            by_lang.setdefault(lang, []).append(f)
        else:
            jscpd_files.append(f)

    all_dupes: list[dict] = []
    scanned = 0
    pmd_missing = False

    for lang, files in by_lang.items():
        try:
            xml_text = _run_pmd_lang(files, lang, min_tokens, timeout)
        except FileNotFoundError:
            pmd_missing = True
            break
        except subprocess.TimeoutExpired:
            from eedom.core.errors import ErrorCode, error_msg

            msg = error_msg(ErrorCode.TIMEOUT, "pmd", timeout=timeout)
            logger.warning("cpd.timeout", error=msg)
            return {"duplicates": [], "files_scanned": 0, "error": msg}
        except Exception:
            logger.exception("cpd.pmd_failed", language=lang)
            continue
        if xml_text:
            all_dupes.extend(_parse_cpd_xml(xml_text, lang))
        scanned += len(files)

    # jscpd handles non-PMD languages always, and every language if PMD is unavailable.
    fallback = list(jscpd_files)
    if pmd_missing:
        for files in by_lang.values():
            fallback.extend(files)
    if fallback:
        fb = _run_jscpd(fallback, min_tokens, timeout)
        all_dupes.extend(fb)
        scanned += len(fallback)

    if pmd_missing and not _jscpd_available():
        from eedom.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.NOT_INSTALLED, "pmd")
        logger.warning("cpd.not_installed", error=msg)
        return {"duplicates": [], "files_scanned": 0, "error": msg}

    _enrich_clones(all_dupes, repo_path)
    return {
        "duplicates": all_dupes,
        "files_scanned": scanned,
        "duplicate_count": len(all_dupes),
    }
