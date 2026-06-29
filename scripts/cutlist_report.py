#!/usr/bin/env python3
"""Render a caliper `part` cut list (+ optional `inspect` reports) as a single
self-contained HTML report an engineer can open in a browser.

Reads an output directory produced by `caliper part` / `caliper inspect`:

    <out>/cutlist.json            # required — the ordered cut list
    <out>/inspect/<part>.json     # optional — per-part Screen/Adjudicate results

and writes a dependency-free `report.html` (inline CSS + a few lines of vanilla
JS for live filtering). No network, no build step, no external assets.

Usage:
    python3 scripts/cutlist_report.py <out-dir> [-o report.html] [--open]

Example:
    python3 scripts/cutlist_report.py \
        ~/.cache/caliper-tryout/aws-...-pr48-out --open
"""

# ruff: noqa: E501  — embedded CSS/HTML template lines are intentionally long.

from __future__ import annotations

import argparse
import glob
import html
import json
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

# Bucket -> accent hue (CSS var driven; see STYLE). Unknown buckets fall back to slate.
_BUCKET_HUE = {
    "logic": 213,  # blue
    "generated": 38,  # amber
    "test": 152,  # green
    "docs": 280,  # violet
    "config": 198,  # cyan
    "vendor": 0,  # red
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}


def _short(sha: str, n: int = 9) -> str:
    return sha[:n] if sha else "—"


def _load(out: Path) -> tuple[dict, dict[str, dict]]:
    """Return (cutlist, {part_id: inspect_report}). Inspect dir is optional."""
    cutlist_path = out / "cutlist.json"
    if not cutlist_path.is_file():
        sys.exit(f"error: {cutlist_path} not found — run `caliper part` first")
    cutlist = json.loads(cutlist_path.read_text())

    reports: dict[str, dict] = {}
    for path in sorted(glob.glob(str(out / "inspect" / "*.json"))):
        try:
            r = json.loads(Path(path).read_text())
        except (json.JSONDecodeError, OSError):
            continue
        pid = r.get("part_id")
        if pid:
            reports[pid] = r
    return cutlist, reports


def _gauge_summary(report: dict | None) -> dict:
    """Collapse a part's inspect report into render-ready counts."""
    if not report:
        return {"has": False}
    gauges = report.get("gauges", [])
    npass = sum(1 for g in gauges if g.get("verdict") == "pass")
    nfail = sum(1 for g in gauges if g.get("verdict") == "fail")
    findings = sum(len(g.get("findings", [])) for g in gauges)
    failed = sorted(
        (g.get("gauge", "?"), len(g.get("findings", [])))
        for g in gauges
        if g.get("verdict") == "fail"
    )
    return {
        "has": True,
        "pass": npass,
        "fail": nfail,
        "findings": findings,
        "failed_gauges": failed,
        "claims": len(report.get("claims", [])),
        "dropped": len(report.get("dropped", [])),
        "skipped_llm": bool(report.get("skipped_llm")),
    }


# --------------------------------------------------------------------------- #
# HTML rendering
# --------------------------------------------------------------------------- #

STYLE = """
:root {
  --bg: #0d1117; --surface: #161b22; --surface-2: #1c2330; --border: #30363d;
  --text: #e6edf3; --muted: #8b949e; --accent: #2f81f7;
  --pass: #3fb950; --fail: #f85149; --warn: #d29922;
  --radius: 12px; --shadow: 0 1px 3px rgba(0,0,0,.4), 0 8px 24px rgba(0,0,0,.2);
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #f6f8fa; --surface: #ffffff; --surface-2: #f0f3f6; --border: #d0d7de;
    --text: #1f2328; --muted: #636c76; --accent: #0969da;
    --shadow: 0 1px 2px rgba(31,35,40,.08), 0 6px 20px rgba(31,35,40,.06);
  }
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 1100px; margin: 0 auto; padding: 0 20px 80px; }
code, .mono { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; }

header.hero {
  position: sticky; top: 0; z-index: 10; backdrop-filter: blur(12px);
  background: color-mix(in srgb, var(--bg) 88%, transparent);
  border-bottom: 1px solid var(--border); margin-bottom: 28px;
}
.hero-inner { max-width: 1100px; margin: 0 auto; padding: 18px 20px; display: flex;
  align-items: baseline; gap: 14px; flex-wrap: wrap; }
.hero h1 { font-size: 20px; margin: 0; letter-spacing: -.01em; }
.hero .sub { color: var(--muted); font-size: 13px; }
.hero .sha { font-family: ui-monospace, monospace; font-size: 12px; color: var(--muted);
  background: var(--surface-2); padding: 2px 8px; border-radius: 6px; border: 1px solid var(--border); }

.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 14px; margin: 0 0 28px; }
.stat { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 16px 18px; box-shadow: var(--shadow); }
.stat .n { font-size: 28px; font-weight: 700; letter-spacing: -.02em; }
.stat .l { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; margin-top: 2px; }
.stat.bad .n { color: var(--fail); }
.stat.good .n { color: var(--pass); }

.toolbar { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 18px; }
.toolbar input { flex: 1; min-width: 220px; background: var(--surface); color: var(--text);
  border: 1px solid var(--border); border-radius: 8px; padding: 9px 12px; font-size: 14px; }
.toolbar input:focus { outline: 2px solid var(--accent); outline-offset: 0; border-color: transparent; }
.chip-filter { display: inline-flex; gap: 6px; }
.chip-filter button { background: var(--surface); color: var(--muted); border: 1px solid var(--border);
  border-radius: 999px; padding: 6px 12px; font-size: 13px; cursor: pointer; }
.chip-filter button.on { background: var(--accent); color: #fff; border-color: transparent; }

.part { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid hsl(var(--hue) 70% 55%);
  border-radius: var(--radius); padding: 16px 18px; margin-bottom: 14px; box-shadow: var(--shadow); }
.part-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.idx { font-weight: 700; font-size: 15px; color: var(--muted); min-width: 26px; }
.badge { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .04em;
  padding: 3px 9px; border-radius: 999px; background: hsl(var(--hue) 70% 55% / .16);
  color: hsl(var(--hue) 70% 70%); border: 1px solid hsl(var(--hue) 70% 55% / .3); }
.pid { font-family: ui-monospace, monospace; font-size: 12px; color: var(--muted); }
.rule { font-size: 11px; color: var(--muted); margin-left: auto; }
.rule b { color: var(--text); font-family: ui-monospace, monospace; }

.meter { height: 7px; border-radius: 999px; background: var(--surface-2); margin: 12px 0 4px; overflow: hidden; }
.meter > i { display: block; height: 100%; border-radius: 999px; background: hsl(var(--hue) 70% 55%); }
.meter.over > i { background: var(--fail); }
.meta-row { display: flex; gap: 16px; font-size: 12px; color: var(--muted); flex-wrap: wrap; }
.meta-row b { color: var(--text); }

.gauges { display: flex; gap: 6px; flex-wrap: wrap; margin: 12px 0 0; }
.g { font-size: 11px; padding: 3px 8px; border-radius: 6px; border: 1px solid var(--border);
  background: var(--surface-2); color: var(--muted); font-family: ui-monospace, monospace; }
.g.pass { color: var(--pass); border-color: color-mix(in srgb, var(--pass) 40%, var(--border)); }
.g.fail { color: var(--fail); border-color: var(--fail); background: color-mix(in srgb, var(--fail) 12%, var(--surface)); font-weight: 700; }

details.files { margin-top: 12px; }
details.files summary { cursor: pointer; color: var(--muted); font-size: 13px; user-select: none; }
details.files summary:hover { color: var(--text); }
.files ul { list-style: none; margin: 8px 0 0; padding: 0; }
.files li { font-family: ui-monospace, monospace; font-size: 12.5px; padding: 3px 0;
  border-bottom: 1px dashed var(--border); color: var(--text); word-break: break-all; }
.files li:last-child { border-bottom: 0; }
.dim { color: var(--muted); }
footer { text-align: center; color: var(--muted); font-size: 12px; margin-top: 40px; }
.hidden { display: none !important; }
"""

FILTER_JS = """
const q = document.getElementById('q');
const chips = [...document.querySelectorAll('.chip-filter button')];
let bucket = 'all';
function apply() {
  const term = (q.value || '').toLowerCase();
  document.querySelectorAll('.part').forEach(el => {
    const okBucket = bucket === 'all' || el.dataset.bucket === bucket;
    const okTerm = !term || el.dataset.search.includes(term);
    el.classList.toggle('hidden', !(okBucket && okTerm));
  });
}
q.addEventListener('input', apply);
chips.forEach(c => c.addEventListener('click', () => {
  chips.forEach(x => x.classList.remove('on')); c.classList.add('on');
  bucket = c.dataset.bucket; apply();
}));
"""


def _part_html(idx: int, part: dict, summary: dict, cap: int) -> str:
    pid = part.get("id", "?")
    bucket = part.get("bucket", "?")
    size = part.get("size", 0)
    files = part.get("files", [])
    oversized = part.get("oversized")
    rule = part.get("opened_by", {}).get("fired_rule", "—")
    hue = _BUCKET_HUE.get(bucket, 215)
    pct = min(100, round(size / cap * 100)) if cap else 0

    gauge_html = ""
    if summary.get("has"):
        chips = [f'<span class="g pass">{summary["pass"]}P</span>']
        if summary["fail"]:
            chips.append(f'<span class="g fail">{summary["fail"]}F</span>')
        for gname, n in summary["failed_gauges"]:
            chips.append(f'<span class="g fail">{html.escape(gname)} · {n}</span>')
        if summary["findings"]:
            chips.append(f'<span class="g">{summary["findings"]} findings</span>')
        if summary["skipped_llm"]:
            chips.append('<span class="g">llm: skip</span>')
        gauge_html = f'<div class="gauges">{"".join(chips)}</div>'

    file_items = "".join(f"<li>{html.escape(f)}</li>" for f in files)
    search_blob = html.escape((pid + " " + bucket + " " + " ".join(files)).lower(), quote=True)

    return f"""
<article class="part" data-bucket="{html.escape(bucket)}" data-search="{search_blob}" style="--hue:{hue}">
  <div class="part-head">
    <span class="idx">{idx}</span>
    <span class="badge">{html.escape(bucket)}</span>
    <span class="pid">{html.escape(pid)}</span>
    <span class="rule">opened by <b>{html.escape(str(rule))}</b></span>
  </div>
  <div class="meter {"over" if oversized else ""}"><i style="width:{pct}%"></i></div>
  <div class="meta-row">
    <span><b>{size}</b> size <span class="dim">/ cap {cap}</span></span>
    <span><b>{len(files)}</b> file{"s" if len(files) != 1 else ""}</span>
    {'<span style="color:var(--fail)"><b>oversized</b></span>' if oversized else ""}
  </div>
  {gauge_html}
  <details class="files">
    <summary>{len(files)} file{"s" if len(files) != 1 else ""}</summary>
    <ul>{file_items}</ul>
  </details>
</article>"""


def render(cutlist: dict, reports: dict[str, dict], label: str, generated_at: str) -> str:
    prov = cutlist.get("provenance", {})
    stats = cutlist.get("stats", {})
    cap = cutlist.get("size_cap", 0) or 1
    parts = cutlist.get("parts", [])
    buckets = sorted({p.get("bucket", "?") for p in parts})

    # aggregate inspect signal across parts
    total_fail = sum(_gauge_summary(reports.get(p["id"])).get("fail", 0) for p in parts)
    total_find = sum(_gauge_summary(reports.get(p["id"])).get("findings", 0) for p in parts)
    has_inspect = any(reports.get(p["id"]) for p in parts)

    cards = [
        ("good", stats.get("part_count", len(parts)), "parts"),
        ("", stats.get("file_count", sum(len(p.get("files", [])) for p in parts)), "files"),
        ("", f'{stats.get("size_p50", "—")}/{stats.get("size_p90", "—")}', "size p50/p90"),
        ("", cap, "size cap"),
    ]
    if has_inspect:
        cards.append(("bad" if total_fail else "good", total_fail, "failed gauges"))
        cards.append(("", total_find, "screen findings"))
    cards_html = "".join(
        f'<div class="stat {cls}"><div class="n">{val}</div><div class="l">{lbl}</div></div>'
        for cls, val, lbl in cards
    )

    chip_html = '<button class="on" data-bucket="all">all</button>' + "".join(
        f'<button data-bucket="{html.escape(b)}">{html.escape(b)}</button>' for b in buckets
    )

    parts_html = "".join(
        _part_html(i, p, _gauge_summary(reports.get(p["id"])), cap) for i, p in enumerate(parts, 1)
    )

    ver = prov.get("caliper_version", "?")
    base = _short(prov.get("base_sha", ""))
    head = _short(prov.get("head_sha", ""))
    digest = _short(prov.get("config_digest", ""), 12)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>caliper · {html.escape(label)} · {base}→{head} · {generated_at}</title>
<style>{STYLE}</style>
</head>
<body>
<header class="hero">
  <div class="hero-inner">
    <h1>caliper cut list · {html.escape(label)}</h1>
    <span class="sub">{len(parts)} parts · caliper {html.escape(str(ver))} · {generated_at}</span>
    <span class="sha">{base} → {head}</span>
  </div>
</header>
<div class="wrap">
  <div class="cards">{cards_html}</div>
  <div class="toolbar">
    <input id="q" type="search" placeholder="filter by file path or part id…" autocomplete="off">
    <div class="chip-filter">{chip_html}</div>
  </div>
  {parts_html}
  <footer>config digest <code>{digest}</code> · rename threshold {prov.get("rename_threshold", "—")} ·
    generated by scripts/cutlist_report.py</footer>
</div>
<script>{FILTER_JS}</script>
</body>
</html>"""


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "out", type=Path, help="caliper output dir (contains cutlist.json [+ inspect/])"
    )
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="HTML path (default: <out>/cutlist-report-<label>-<head>-<RUN_ID>.html)",
    )
    ap.add_argument(
        "--label",
        default=None,
        help="human label for the title (default: derived from the out dir name)",
    )
    ap.add_argument("--open", action="store_true", help="open the report in a browser when done")
    args = ap.parse_args()

    cutlist, reports = _load(args.out)

    # Unique title + filename per run: every report is distinguishable in a browser tab
    # and never silently clobbers a prior one (Output Persistence — RUN_ID in the name).
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    label = args.label or args.out.resolve().name.removesuffix("-out") or "cut-list"
    head = _short(cutlist.get("provenance", {}).get("head_sha", ""), 8)

    out_html = args.output or (args.out / f"cutlist-report-{label}-{head}-{run_id}.html")
    out_html.write_text(render(cutlist, reports, label, generated_at), encoding="utf-8")

    n_parts = len(cutlist.get("parts", []))
    print(f"wrote {out_html}  ({n_parts} parts, {len(reports)} inspect reports merged)")
    if args.open:
        webbrowser.open(f"file://{out_html.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
