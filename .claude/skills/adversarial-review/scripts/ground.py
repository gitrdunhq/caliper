#!/usr/bin/env python3
"""Language- & project-agnostic grounding bundle generator for adversarial-review.

Given a set of target files (one review partition), emit a markdown "grounding
bundle" that makes a cheap reviewer model accurate from the start:

  1. FACT SHEET (#5 AST, generic): every symbol DEFINED inside the target files
     (kind + name + line + signature) so the model sees the real shapes, not
     guesses. Driven by a multi-language symbol index, never by language-specific
     assumptions.
  2. TYPE CONTEXT (#1, generic): definitions of type-like symbols (class/struct/
     enum/interface/typedef/constant/...) that the target files REFERENCE but
     that live elsewhere — the contracts whose absence causes most false
     positives ("raw string" that's really an enum, "missing timeout" that's
     injected, "falsy field" that's type-constrained).

Design rules:
  * Project-agnostic: operates on whatever --root and files you pass. No hardcoded
    paths, filenames, or module names.
  * Language-agnostic: universal-ctags (≈150 langs) is primary; ripgrep generic
    definition heuristics are the fallback; if neither exists it emits an empty
    (but valid) bundle.
  * Fail-open: any tool error degrades to a weaker source and finally to nothing.
    Grounding never blocks a review.

Usage:
  # build a repo-wide symbol index once (cached), then ground each partition:
  ground.py --root REPO --build-index --index-cache tags.json
  ground.py --root REPO --index-cache tags.json --out bundle.md FILE1 FILE2 ...

  # or one-shot (no cache):
  ground.py --root REPO --out bundle.md FILE1 FILE2 ...
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

# Kinds that represent a "contract" worth attaching as type context (#1).
TYPE_KINDS = {
    "class", "struct", "interface", "enum", "enumerator", "enumconstant",
    "typedef", "type", "trait", "record", "protocol", "union", "member",
    "constant", "const", "macro", "namespace", "module", "annotation",
    "field", "property", "variable", "alias", "object", "schema",
}
MAX_TYPE_SYMBOLS = 40       # cap attached cross-file defs to keep prompts lean
MAX_CONTEXT_LINES = 12      # lines of source to show per attached definition
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _run(cmd: list[str], cwd: str | None = None) -> str:
    try:
        out = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=120, check=False
        )
        return out.stdout
    except Exception:  # fail-open: any failure -> no output from this source
        return ""


# ---------------------------------------------------------------------------
# Symbol extraction (universal-ctags primary, ripgrep fallback)
# ---------------------------------------------------------------------------
def ctags_tags(root: str, paths: list[str] | None) -> list[dict]:
    """Return tag dicts via universal-ctags JSON. paths=None => whole repo."""
    if not have("ctags"):
        return []
    base = ["ctags", "--output-format=json", "--fields=+nKSl", "-f", "-"]
    cmd = base + (paths if paths else ["-R", "."])
    raw = _run(cmd, cwd=root)
    tags: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            t = json.loads(line)
        except Exception:
            continue
        if t.get("_type") != "tag":
            continue
        tags.append(
            {
                "name": t.get("name", ""),
                "path": t.get("path", ""),
                "line": int(t.get("line", 0) or 0),
                "kind": (t.get("kind") or "").lower(),
                "signature": t.get("signature", "") or t.get("pattern", "") or "",
                "lang": t.get("language", ""),
            }
        )
    return tags


# Generic, multi-language definition patterns for the ripgrep fallback.
_RG_DEF = (
    r"^\s*(?:export\s+|public\s+|pub\s+|private\s+|final\s+|abstract\s+|static\s+)*"
    r"(?:class|struct|interface|enum|trait|protocol|record|type|typedef|"
    r"def|func|function|fn|module|namespace|const|let|var|val)\b"
    r"[\s:]+([A-Za-z_][A-Za-z0-9_]*)"
)


def rg_tags(root: str, paths: list[str] | None) -> list[dict]:
    """Fallback symbol index using ripgrep + generic def patterns."""
    if not have("rg"):
        return []
    cmd = ["rg", "--no-heading", "--line-number", "--color", "never", _RG_DEF]
    cmd += paths if paths else ["."]
    raw = _run(cmd, cwd=root)
    tags: list[dict] = []
    for line in raw.splitlines():
        # format: path:line:matchtext
        m = re.match(r"^(.*?):(\d+):(.*)$", line)
        if not m:
            continue
        path, lno, text = m.group(1), int(m.group(2)), m.group(3)
        nm = re.search(_RG_DEF, text)
        if not nm:
            continue
        tags.append(
            {
                "name": nm.group(1),
                "path": path,
                "line": lno,
                "kind": "def",
                "signature": text.strip()[:160],
                "lang": "",
            }
        )
    return tags


def build_index(root: str) -> list[dict]:
    tags = ctags_tags(root, None)
    if tags:
        return tags
    return rg_tags(root, None)


# ---------------------------------------------------------------------------
# Bundle construction
# ---------------------------------------------------------------------------
def _norm(root: str, p: str) -> str:
    p = p.replace("\\", "/")
    rp = os.path.relpath(os.path.join(root, p), root) if not os.path.isabs(p) else os.path.relpath(p, root)
    return rp.replace("\\", "/")


def read_lines(root: str, path: str, start: int, count: int) -> str:
    fp = path if os.path.isabs(path) else os.path.join(root, path)
    try:
        with open(fp, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except Exception:
        return ""
    s = max(0, start - 1)
    snippet = "".join(lines[s : s + count]).rstrip("\n")
    return snippet


def identifiers_in(root: str, files: list[str]) -> set[str]:
    idents: set[str] = set()
    for f in files:
        fp = f if os.path.isabs(f) else os.path.join(root, f)
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                for tok in IDENT_RE.findall(fh.read()):
                    idents.add(tok)
        except Exception:
            continue
    return idents


def make_bundle(root: str, files: list[str], index: list[dict]) -> str:
    target_set = {_norm(root, f) for f in files}

    # Fact sheet: definitions located in the target files (#5).
    infile = [t for t in (ctags_tags(root, files) or rg_tags(root, files))]
    infile.sort(key=lambda t: (_norm(root, t["path"]), t["line"]))

    # Type context: type-like defs referenced by, but defined outside, targets (#1).
    refs = identifiers_in(root, files)
    seen: set[tuple] = set()
    type_ctx: list[dict] = []
    for t in index:
        if t["kind"] not in TYPE_KINDS:
            continue
        if t["name"] not in refs:
            continue
        if _norm(root, t["path"]) in target_set:
            continue  # defined inside the partition already shown in fact sheet
        key = (t["name"], _norm(root, t["path"]), t["line"])
        if key in seen:
            continue
        seen.add(key)
        type_ctx.append(t)
    # Prefer richer kinds, then stable order; cap.
    type_ctx.sort(key=lambda t: (t["name"], _norm(root, t["path"]), t["line"]))
    type_ctx = type_ctx[:MAX_TYPE_SYMBOLS]

    out: list[str] = []
    out.append("# Grounding bundle (language- & project-agnostic)")
    out.append("")
    src = "universal-ctags" if have("ctags") else ("ripgrep-heuristic" if have("rg") else "none")
    out.append(f"_symbol source: {src}; "
               f"{len(infile)} in-file defs, {len(type_ctx)} referenced type defs attached._")
    out.append("")
    out.append("## Fact sheet — symbols defined in the files under review")
    out.append("Trust these signatures over your assumptions about the code's shape.")
    out.append("")
    if infile:
        for t in infile:
            sig = (" " + t["signature"]) if t["signature"] else ""
            out.append(f"- `{t['kind']}` **{t['name']}**{sig} — {_norm(root, t['path'])}:{t['line']}")
    else:
        out.append("_(no symbol indexer available — fact sheet empty; review ungrounded)_")
    out.append("")
    out.append("## Type context — contracts referenced from elsewhere")
    out.append("Before flagging a 'raw string', 'missing timeout', 'wrong type', or "
               "'unvalidated value', check whether the contract below already "
               "constrains it. A configured/injected/typed value is NOT a defect.")
    out.append("")
    if type_ctx:
        for t in type_ctx:
            out.append(f"### `{t['kind']}` {t['name']} — {_norm(root, t['path'])}:{t['line']}")
            ctx = read_lines(root, t["path"], t["line"], MAX_CONTEXT_LINES)
            if ctx:
                out.append("```")
                out.append(ctx)
                out.append("```")
            out.append("")
    else:
        out.append("_(no cross-file type contracts resolved)_")
        out.append("")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", required=True)
    ap.add_argument("--out")
    ap.add_argument("--index-cache")
    ap.add_argument("--build-index", action="store_true")
    ap.add_argument("files", nargs="*")
    a = ap.parse_args()
    root = os.path.abspath(a.root)

    if a.build_index:
        idx = build_index(root)
        if a.index_cache:
            with open(a.index_cache, "w", encoding="utf-8") as fh:
                json.dump(idx, fh)
        sys.stderr.write(f"indexed {len(idx)} symbols\n")
        return 0

    if a.index_cache and os.path.exists(a.index_cache):
        with open(a.index_cache, "r", encoding="utf-8") as fh:
            index = json.load(fh)
    else:
        index = build_index(root)

    bundle = make_bundle(root, a.files, index)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(bundle)
        sys.stderr.write(f"wrote {a.out} ({len(bundle)} bytes)\n")
    else:
        sys.stdout.write(bundle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
