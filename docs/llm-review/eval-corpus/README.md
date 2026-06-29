# Review-quality eval corpus

Each `*.json` file is one case for `caliper eval --corpus docs/llm-review/eval-corpus`.
The harness runs every case through the **same** pure Adjudicate filter the real
pipeline uses and reports precision / recall / F1 / nit-rate / SNR **pre- and
post-Adjudicate**, plus the per-rule Adjudicate drop rate.

A case carries *recorded* model claims (a deterministic stand-in for a live backend),
so the eval is fully reproducible — the same role a recorded run plays in BATTLEARENA,
whose sweep over (model, context strategy, sampling) is what populates real cases.

## Case schema

```jsonc
{
  "part": { "id": "...", "files": ["a.py"], "bucket": "logic", "size": 12 },
  "changed_lines": { "a.py": [10, 11, 12] },   // new-side changed line numbers
  "changed_text":  { "a.py": "..." },          // joined added lines (anchor_quote is checked against this)
  "screen": [ { "id": "...", "file": "a.py", "line_range": [11,11], "category": "security", "severity": "high" } ],
  "raw_claims": [ { "file": "...", "line_range": [11,11], "severity": "...", "category": "...", "assertion": "...", "anchor_quote": "..." } ],
  "truths": [ { "file": "a.py", "line": 11 } ]  // ground-truth bug sites ("detectable via review")
}
```

A claim *hits* a truth when it is on that file and its `line_range` covers the line.

## Building real cases (follow-on)

Seed a bug by `git blame`-ing a fix to its introducing commit, reintroduce it on a
clean fork, record a backend's claims for the affected part, and mark the introduced
site in `truths`. Keep only bugs validated as detectable via review (the CR-Bench
filter). The two cases here are illustrative, not a benchmark.
