# `caliper part` — quick reference

Cut a PR diff into small, ordered, reviewable parts. Pure-deterministic
classification (no LLM in the decision path), emits a `jj` restack script.

## Fastest path

```bash
# feed it a GitHub PR — clones it in isolation and parts base..head for you
caliper part --pr https://github.com/owner/repo/pull/123
caliper part --pr 123                      # bare number → current repo's origin

# cut the current branch against main, write restack.sh + cutlist.json to .temp/
caliper part --base main --head HEAD --out .temp

# open the live, reclassify-able report in a browser (loopback only)
caliper part --base main --head HEAD --serve
#  → http://127.0.0.1:12700  (reclassify a file → writes parting.overrides → re-parts)
```

## Feeding it a PR (`--pr`)

`--pr` takes a **GitHub PR URL or number** and does the fetch-and-resolve for you,
so you don't hand-wrangle `--base`/`--head`:

```bash
caliper part --pr https://github.com/owner/repo/pull/123
caliper part --pr 123                       # bare number → origin of the repo you're in
caliper part --pr 123 --serve               # resolve the PR, then open the reclassify UI
```

What it does:

1. Clones the PR's repo into `.<repo>/.temp/part-pr/<repo>-pr<N>/` (isolated — it
   **never touches your working repo**).
2. Fetches `refs/pull/N/head`, resolves the base branch (via `gh`, falling back to
   origin's default branch), and computes `base = merge-base(base, head)`.
3. `jj`-inits the clone and neutralizes immutability **there** (a pushed PR's commits
   are immutable; this throwaway clone isn't pushed), so the parting gate can read it.
4. Parts `base..head` and writes `restack.sh` + `cutlist.json` to a sibling
   `<repo>-pr<N>-out/` dir (outside the clone, so it survives a re-part).

**Self-cleaning — no weird states.** Every `--pr` run wipes any stale clone to a
clean slate first, and a failed/interrupted run removes its partial clone before
erroring — so a crashed run can never poison the next one. Requires `git`, `gh`
(authenticated), and `jj`. `--pr` is mutually exclusive with `--base`/`--head`.

For a different repo than the one you're in, just pass the full URL — it clones that
repo. (The local-branch case is already served by `--base/--head`; `--pr` is
specifically "fetch a GitHub PR and part it in isolation".)

From the container, swap `caliper` for the `cal`-style invocation (repo mounted at
`/workspace`):

```bash
podman run --rm --platform linux/amd64 \
  -v "$PWD":/workspace:ro -v "$PWD/.temp":/workspace/.temp \
  caliper:latest part --base main --head HEAD --repo /workspace --out /workspace/.temp
```

## Common commands

| Command | What it does |
|---|---|
| `caliper part --pr <url\|number>` | Clone a GitHub PR in isolation and part its `base..head`. Self-cleaning. |
| `caliper part --base main --head HEAD` | Propose the cut list, print it, emit `restack.sh`. |
| `caliper part --base main --head HEAD --out .temp` | Same, write `restack.sh` + `cutlist.json` to `.temp/`. |
| `caliper part --base main --head HEAD --target stack` | Restack as a single jj stack (default from config). |
| `caliper part --base main --head HEAD --target series` | Restack as an independent series instead of a stack. |
| `caliper part --base main --head HEAD --size-cap 200` | Override the per-part size cap. |
| `caliper part --explain .temp/cutlist.json` | Re-print a saved cut list + the rule fired at each kerf. No diff needed. |
| `caliper part --base main --head HEAD --serve` | Live reclassify sidecar at `127.0.0.1:12700`. |
| `caliper part --base main --head HEAD --serve --port 12701` | Same, custom in-range port. |
| `caliper part --base main --head HEAD --describe` | Advisory: name each commit subject with a local model (fail-soft). |
| `caliper part --base main --head HEAD --describe-model gemma4:e4b` | Pick the describer model (overrides env). |
| `caliper part ... --force` | Override the already-pushed safety check. |

## Flags

| Flag | Default | Notes |
|---|---|---|
| `--pr <url\|number>` | — | Clone+resolve a GitHub PR into `base..head`. Mutually exclusive with `--base/--head`. Needs `git`, `gh`, `jj`. |
| `--base` / `--head` | — | Stock = `--base..--head`. Required unless `--pr`/`--explain`. |
| `--repo` | `.` | Repository root. |
| `--target` | from config | `stack` \| `series` — affects only the emitted script. |
| `--size-cap` | from config | Per-part size cap (R4). |
| `--out` | — | Directory for `restack.sh` / `cutlist.json`. |
| `--explain <cutlist.json>` | — | Print a saved cut list; no diff computed. |
| `--serve` / `--port` | off / 12700 | Loopback report; requires `--base` + `--head`. |
| `--describe` / `--no-describe` | env-driven | Local OpenAI-compatible describer; advisory, off the `config_digest`. |
| `--describe-model` | env | e.g. `gemma4:e4b`, `llama3.2:3b`. |
| `--force` | off | Bypass the already-pushed precondition gate. |

## Describer config (optional, advisory only)

The describer names commit *subjects*; caliper always prepends the deterministic
`type(scope):` prefix, so it can't leak format. It's env/CLI-driven and **outside**
`PartingConfig` — the cut, classification, and `config_digest` stay 100% deterministic.

```bash
export CALIPER_DESCRIBER_MODEL=gemma4:e4b        # enables --describe by default
export CALIPER_DESCRIBER_BASE_URL=http://127.0.0.1:11434/v1   # Ollama/OMLX/llama.cpp
```

## Reclassify loop (`--serve`)

1. `caliper part --base main --head HEAD --serve`
2. Open `http://127.0.0.1:12700`.
3. Files that couldn't be tiered land in **Untiered** (the honest residual). Pick a
   bucket from the per-file `<select>` → POST `/reclassify`.
4. That appends/updates a `parting.overrides` entry (`{glob, bucket, note}`) in
   `.caliper.yaml`, re-parts, and re-renders. The override is version-controlled and
   hashed into `provenance.config_digest`.

## Taxonomy (where a file lands)

Precedence in `_classify` (`core/part_stock.py`): structural facts first (never
overridable) → **override table** → ordered glob heuristics (most-specific-first) →
`logic` residual.

- **Structural** (git): `move`, `delete`, `binary`.
- **Generated**: `generated` (vendored/lockfiles).
- **Non-code intent**: `documentation`, `supply_chain`, `ci_cd`, `security_policy`,
  `config`, `schema_contracts`, `test`.
- **Code tiers**: `frontend`, `business`, `data`, `infra`.
- **Residual**: `logic` — untiered code a human should label (this is the thing the
  `--serve` loop is for).

`documentation` collapses into one cap-exempt part; `generated`/`binary` collapse and
are never cap-checked. Every other bucket accretes by the size cap.
