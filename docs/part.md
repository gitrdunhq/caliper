# `caliper part` — cutting a diff into reviewable commits

`caliper part` takes a diff (`--base..--head`, or a GitHub PR via `--pr`) and proposes an ordered cut list: which files go in which commit, in what order, so a big change becomes a series of small, reviewable ones. Classification is a deterministic taxonomy walk — glob heuristics, an override table, structural git facts — never an LLM. The two advisory features that *do* call a local model (`--describe`, `--suggest`) are opt-in, off the decision path, and fail soft to deterministic output if the model is unavailable. `caliper part` never pushes, force-pushes, or force-updates anything — it emits a script (`restack.sh`) for you to read and run, plus a `cutlist.json` for provenance.

This doc is a tutorial arc: first a five-minute walkthrough, then fixing a misclassification, then the live `--serve` sidecar, then working straight from a GitHub PR. A full flags reference and the classification taxonomy are at the end.

## Your first cut in five minutes

Start with `--doctor`. It's read-only, never cuts anything, and tells you which execution backend you have:

```bash
caliper part --doctor
```

```
caliper part --doctor

  [PASS] jj: jj 0.44.0
  [PASS] git: git version 2.55.0
  [PASS] execution backend: jj
  [PASS] gh auth (for --pr): github.com
  [PASS] state workdir (for --pr): /Users/you/.config/caliper/state/part-pr

5/5 checks passed
```

`caliper part` prefers [`jj`](https://github.com/jj-vcs/jj) (stronger op-log rollback guarantee) and falls back to a native git backend if `jj` isn't on `PATH` — either way the safety story below holds. `gh auth` and the state workdir check only matter if you plan to use `--pr`; a `git`-only environment with no `gh` still passes the checks that matter for a plain `--base/--head` cut.

Now cut a real diff:

```bash
caliper part --base main --head my-feature-branch --out .temp/part-out
```

This writes two files into `.temp/part-out/`:

- **`cutlist.json`** — the ordered parts (each with its file list, bucket, size, and `match_reason` per file), plus provenance: resolved base/head commit ids, which execution `backend` ran (`"jj"` or `"git"`), the jj version if applicable, and the config digest.
- **`restack.sh`** — an executable script (chmod 0755) that replays the cut as a sequence of commits.

Read `restack.sh` before running it — it's plain, generated shell/jj/git commands, no magic. It opens with a rollback header explaining exactly how to undo it (backend-aware: `jj op restore <rescue-op-id>` for jj, or `git checkout <rescue-ref>` for the git backend), and it ends with a footer reminding you that pushing and opening PRs are manual, printed-only next steps — `caliper part` never does either for you.

Run it:

```bash
bash .temp/part-out/restack.sh
```

Before doing anything destructive, the gate takes exactly one state-changing action, done last, only after every precondition passes: it creates an *additive* backup bookmark (jj) or branch (git) named `caliper-part-backup-<timestamp>` anchored at the resolved base. Preconditions checked first (both backends): clean working tree, no untracked files, no stray git stash, and — unless you pass `--force` — the target isn't already reachable from a remote bookmark/branch (i.e. you haven't already pushed it). The immutable-overlap check (the stock doesn't cross into already-shared history) is also `--force`-gated on the git backend, but on the jj backend it is **unconditional** — `--force` there only ever overrides the already-pushed check, never the immutability check. Any failed precondition aborts with **no state change at all**.

If something goes wrong after running `restack.sh`, the rollback header told you the exact command — that's your escape hatch, independent of anything else in this doc.

## Fixing a misclassified file: overrides

Not every file matches a known pattern. Files the classifier can't confidently tier land in `logic` — the honest untiered residual, not a wrong guess. Use `--explain` to see why every file landed where it did:

```bash
caliper part --explain .temp/part-out/cutlist.json
```

```
cut list — 4 parts across 4 buckets, 4 files, cap none (1 part/bucket) (size p50=8 p90=40)
provenance: caliper <version>  base=...  head=...  rename=50%  cfg=...
(proposal, not a verdict — bottom of stack first)

  1. move (1 files, size 0) kerf=R1
       new_module.py  [move:92%]
  2. documentation (1 files, size 8) kerf=R1
       docs/adr/0006-scribes.md  [glob:documentation_globs]
  3. generated (1 files, size 0) kerf=R1
       vendor/generated_client.py  [linguist-generated]
  4. logic (1 files, size 40) kerf=bucket-end
       src/caliper/legacy/weird_helper.py  [logic]
```

(This is the same output `--explain` prints and a live run prints — one renderer, no drift. A rename is keyed by its **new** path only; a file's `match_reason` always matches the bucket the part header shows, since the reason *is* why it landed in that bucket.)

Each file gets a `match_reason` string, matching classification precedence (most specific first):

- **`delete`** — the file was removed (git status `D`).
- **`move:NN%`** (or bare `move` if git didn't report a parseable similarity) — a rename/copy; `NN` is git's similarity score, e.g. `R088` → `move:88%`.
- **`binary`** — binary content, a type-change, or a symlink/gitlink.
- **`override:<glob>`** — matched a `parting.overrides` rule you (or a teammate) added.
- **`linguist-generated`** — matched a `.gitattributes` `linguist-generated` content attribute; catches generated files that don't match any glob.
- **`glob:<field>`** — matched an ordered glob heuristic, e.g. `glob:supply_chain_globs`.
- **`logic`** — untiered residual. No rule fired. This is where you look first.

To fix `src/caliper/legacy/weird_helper.py` landing in `logic`, add an override to `.caliper.yaml`:

```yaml
parting:
  overrides:
    - glob: "src/caliper/legacy/**"
      bucket: business
      note: "legacy module, still core business logic"
```

The first matching glob wins, duplicate globs are rejected at load, and the whole override table is hashed into `config_digest` — so a reviewer can always tell which cut ran under which override set. Re-run `caliper part` and the file now reports `override:src/caliper/legacy/**`.

## The live reclassify loop: `--serve`

Editing YAML by hand works, but for a big diff with a lot of `logic` residual, the sidecar is faster:

```bash
caliper part --serve --base main --head my-feature-branch
```

This opens a stdlib `http.server` at `http://127.0.0.1:12700` (no `caliper[webhook]` extra needed) serving a small SPA — no Node required at runtime, the bundle is prebuilt and shipped. You can also start it with **no target at all**:

```bash
caliper part --serve
```

— the SPA opens on an empty-state prompt where you either enter a literal base/head or a PR URL/number, resolved the same way `--pr` works on the CLI.

**Reclassifying a file**: pick a file in the untiered `logic` bucket, choose a bucket from the dropdown (13 selectable buckets: `frontend`, `business`, `data`, `infra`, `documentation`, `supply_chain`, `ci_cd`, `security_policy`, `config`, `schema_contracts`, `test`, `generated`, `logic` — structural facts like `move`/`delete`/`binary` are never offered, the classifier already decided those), and the sidecar writes/updates a `parting.overrides` entry and re-cuts live. Reclassifying the same glob twice is idempotent — last write wins, no duplicate rules.

**`--suggest` tier suggestions ("Sorting Hat")**: click "suggest tiers" and a local OpenAI-compatible model proposes `parting.overrides` globs for the `logic` residual. This is advisory and off the decision path — the model only ever authors glob strings, and a proposal can never claim a file that's already tiered. Each suggestion shows as an accept chip; accepting one reuses the same `/reclassify` path. Bulk-accepting writes all rules and re-parts once, atomically.

**Retargeting and settings**: from the empty-state prompt (or any time), `POST /range` retargets to a literal base/head and `POST /pr` retargets to a GitHub PR; `POST /repart` re-applies size-cap/target settings and re-cuts. All of these roll back cleanly on a bad input — a bad revset never wedges the session.

**A read-only view from another device**: `--lan` binds a *second*, TLS server on a LAN-routable address so someone else can watch the cut list without touching your machine's loopback:

```bash
caliper part --serve --base main --head my-feature-branch \
  --lan 192.168.1.50 --cert ./192.168.1.50.pem --key ./192.168.1.50-key.pem
```

Generate the cert/key with `mkcert 192.168.1.50` first — check it's installed with `caliper part --doctor --serve --lan <ip> --cert <path> --key <path>` (the `mkcert` check only runs when `--lan` is passed, and `--lan` alone errors: it requires `--serve`, and `--cert`/`--key` besides). `--lan`, `--cert`, and `--key` are required together. The LAN server implements GET only — every mutating route (`/reclassify`, `/repart`, `/range`, `/pr`, `/suggest/apply`, `/restack`, `/apply`, `/rollback`) is structurally unreachable from it, independent of anything else; the primary loopback server still owns all mutations. Default LAN port is `12701`, always separate from `--port` (default `12700`).

**Executing for real — `/restack`, `/apply`, `/rollback`**: this is the one thing `--serve` can do that the CLI's file output can't — actually run the script for you, with a confirm step:

1. Clicking "restack" hits `POST /restack`, which runs the full gate → cut → describe → render pipeline and mints a one-shot CSRF token, along with downloadable `restack.sh`/`cutlist.json` and the rollback header info.
2. The SPA shows a confirm modal echoing the backup bookmark name, then `POST /apply` — which requires that exact one-shot token (timing-safe comparison, rejected on replay) and only accepts requests whose Origin/Host is loopback. It runs `bash restack.sh` for real (300s timeout).
3. `POST /rollback` needs no token — it's available any time after a `/restack`, whether or not `/apply` ever ran, and undoes via `jj op restore` or `git checkout <rescue-ref>` depending on backend.

## Working straight from a GitHub PR: `--pr`

```bash
caliper part --pr https://github.com/yourorg/yourrepo/pull/1234
```

or just the number, if `--repo` already points at that repo. `--pr` is mutually exclusive with `--base`/`--head`.

`--pr` clones the PR into a **centralized workdir outside any checkout** — `~/.config/caliper/state/part-pr` by default (XDG: `CALIPER_STATE_DIR` wins, then `$XDG_CONFIG_HOME/caliper/state/part-pr`), keyed by `<owner>-<repo>-pr<N>` so two repos with the same name never collide. Each run prints where it landed:

```
>> yourorg-yourrepo#1234  base=a1b2c3d4e5f6  head=f6e5d4c3b2a1  (clone: /Users/you/.config/caliper/state/part-pr/yourorg-yourrepo-pr1234)
```

Inside that workdir, the clone directory and the managed output directory are wiped fresh at the start of every run (self-healing — a stale or partially-failed clone from a previous run never poisons the next one). If `--out` isn't given, output goes to that PR's own managed `-out` directory automatically. One thing is *not* wiped: a sibling `-overrides` directory holds any reclassifications you made via `--serve` — those persist across re-runs of `--pr` even though the clone itself is thrown away each time.

Requires `git`. `jj` is optional — when present, the clone is jj-colocated so the jj backend's op-log rollback applies, and jj's default immutability for pushed commits is neutralized *inside this throwaway clone only* (never in your real repo); when absent, the clone stays plain git and the git-native backend takes over, same as everywhere else. `gh` is used best-effort to resolve the PR's base branch and falls back to inspecting the git remote if `gh` isn't authenticated.

Combine it with `--serve` to reclassify a PR's diff live before generating the restack script — the reclassify overrides land in that PR's durable `-overrides` sidecar, not your working repo's `.caliper.yaml`.

## Flags reference

| Flag | Default | Purpose |
|---|---|---|
| `--base` | `None` | Base revision (stock = `--base..--head`). Required together with `--head` unless `--pr`, `--explain`, or an untargeted `--serve`. |
| `--head` | `None` | Head revision. |
| `--pr` | `None` | GitHub PR URL or number; clones into the centralized workdir and parts `base..head`. Mutually exclusive with `--base`/`--head`. |
| `--repo` | `.` | Repository root. |
| `--target` | `None` (from config) | `stack` (one bookmark/branch per part) or `series` (single tip). Affects only the emitted script — both backends honor it. |
| `--size-cap` | `None` (from config) | Override the size cap; `None` (the config default too) means one part per bucket, no splitting. |
| `--out` | `None` | Directory for `restack.sh`/`cutlist.json`. Defaults to `repo_path` normally; defaults to the PR's managed out dir when `--pr` is used and `--out` is omitted. |
| `--explain` | `None` | Print a saved `cutlist.json` with the match reason for every file; short-circuits (no base/head/gate needed). |
| `--doctor` | `False` | Check jj/git/gh/mkcert and the state workdir, then exit. Never cuts. |
| `--force` | `False` | Skip the already-pushed safety check. |
| `--serve` | `False` | Serve a live reclassify sidecar on localhost instead of cutting to files. `--base`/`--head` optional here. |
| `--port` | `None` → `12700` | Port for `--serve` (loopback only); scans 12000–13000 if busy. |
| `--lan` | `None` | With `--serve`, also bind a read-only view server at this LAN IP. Requires `--cert`/`--key`. Mutating routes stay loopback-only regardless. |
| `--lan-port` | `None` → `12701` | Port for `--lan`; always separate from `--port`. |
| `--cert` | `None` | TLS cert for `--lan` (e.g. `mkcert` output). Requires `--lan`. |
| `--key` | `None` | TLS key for `--lan`. Requires `--lan`. |
| `--describe` / `--no-describe` | `None` (follows `CALIPER_DESCRIBER_MODEL` env) | Advisory: name each commit with a local model; fails soft to the deterministic subject. |
| `--describe-model` | `None` (env `CALIPER_DESCRIBER_MODEL`) | Model id for `--describe`, e.g. `gemma4:e4b`, `llama3.2:3b`. |
| `--suggest` / `--no-suggest` | `None` (follows `CALIPER_SUGGESTER_MODEL` env) | Advisory: ask a local model to propose override globs for the `logic` residual. Off the decision path. |
| `--suggest-model` | `None` (env `CALIPER_SUGGESTER_MODEL`, else falls back to `--describe-model`) | Model id for `--suggest`, e.g. `llama3.1`. |
| `--suggest-apply` | `False` | Write accepted `--suggest` overrides into `.caliper.yaml` and re-part. Default is print-only. |

Validation notes: `--lan` requires `--serve`, and requires both `--cert` and `--key` together; `--cert`/`--key` only make sense with `--lan`. `--doctor` and `--explain` each short-circuit the rest of the command. Outside those two, and outside `--serve`, both `--base` and `--head` are required.

## Taxonomy: where a file lands

`_classify()` walks files in strict precedence order, first match wins:

1. **Structural facts** (never overridable) — delete, move/rename (with similarity), binary/type-change/symlink.
2. **Override table** (`parting.overrides` in `.caliper.yaml`) — the one human decision point in an otherwise deterministic pipeline.
3. **`linguist-generated`** — `.gitattributes` content-attribute check, catches generated files no glob covers.
4. **Ordered glob heuristics** — most-specific-first, e.g. `supply_chain_globs`, `ci_cd_globs`, `documentation_globs`, `business_globs`.
5. **`logic`** — the untiered residual. Not a wrong guess — an honest "a human should look at this."

Bucket grouping when building parts: `generated` and `binary` collapse into a single part each and are never size-cap-checked. `documentation` also collapses into one part (a reviewer reads docs as a unit) — cap-exempt, but honestly marked oversized if a cap is set and exceeded. Every other bucket is one part by default, and only splits further (R4 accretion) once you set `--size-cap`.
