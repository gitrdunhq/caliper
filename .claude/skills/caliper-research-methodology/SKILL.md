---
name: caliper-research-methodology
description: >-
  The evidence bar and idea lifecycle for turning a hunch into an accepted
  result on caliper: one causal mechanism must explain ALL observations
  including negatives, every claim must survive an assigned adversarial
  refutation pass (never self-graded), and numbers must be predicted BEFORE
  an experiment runs, not fitted after. Covers the idea lifecycle experiment
  -> flag -> adopted change -> documented retirement, worked with caliper's
  real gated `rules_enabled` flags (`dev_scope_exemption`,
  `unmaintained_package`, `cisa_kev`, `copyleft_propagation`,
  `unreachable_vuln_exemption`). Load before proposing a new detector, OPA
  rule, heuristic, or config default; before writing an ADR Decision
  section; before deciding a review/experiment result is strong enough to
  act on; before promoting a `rules_enabled` flag's default; when asked "is
  this proven", "what's the evidence for", "should we ship this as
  default-on", "did we predict this", "who refuted this", or "what stage is
  this idea at". This is the METHODOLOGY layer (when a result is allowed to
  be believed) — for the multi-agent orchestration MECHANICS that generate
  and refute review findings (fan-out reviewers, challenger/verify-model
  roles, canary agent, bounded waves), load `adversarial-review` instead;
  do not duplicate its procedure here.
---

# Caliper Research Methodology

Facts date-stamped **2026-07-02** (repo at commit `c78154b`) — see
[Provenance & maintenance](#provenance--maintenance) to re-verify anything
that may have drifted.

## What this is, and what it is not

This skill is the **methodology layer**: the rules that decide whether a
claim ("grounding improves precision", "this heuristic reduces false
positives", "this default should flip") is allowed to move from a hunch to
something that changes caliper's behavior. It does not describe *how* a
multi-agent review pipeline is orchestrated — that is
**`adversarial-review`**'s job (fan-out reviewer agents, the
cheap-reviewer/expensive-challenger model inversion, canary-agent-first,
bounded waves, the raw→confirmed→adjudicated funnel). Load that skill for
the mechanics; load this one for the standard the mechanics' *output* has to
clear before anyone believes it.

| Question | Load instead |
|---|---|
| "How do I run a multi-agent review / fan out reviewer agents?" | `adversarial-review` |
| "What flags/env vars/config exist and their current values?" | `caliper-config-and-flags` |
| "Has this bug/idea already been investigated? Is this a known dead end?" | `caliper-failure-archaeology` |
| "What commit prefix / RED-GREEN split / dogfood step do I need to land this?" | `caliper-change-control` |
| "How do I write a property-based / TDD test for this?" | `caliper-testing-and-tdd` |

**Do not use this skill** to decide *whether* to run an experiment, only to
decide whether its *result* is strong enough to act on. And do not use it as
a substitute for the change-control gates in `caliper-change-control` — a
result "accepted" by this skill's evidence bar still has to land through the
normal RED/GREEN TDD split and self-review dogfood step like any other
change; this skill governs the claim, not the commit.

## Vocabulary (defined once)

| Term | Meaning here |
|---|---|
| **Mechanism** | The *causal* reason a claim is true — not a correlation, not "the numbers moved." Must be stated in words before it counts as explaining anything. |
| **Observation** | Something that did (or, for a prediction, should) happen. Split into **positive** (the effect shows up) and **negative** (the effect correctly does *not* show up in a case the mechanism rules out). |
| **Confound** | A hidden variable producing the effect you're crediting to your mechanism. The load-bearing example below is the Haiku verifier itself being the confound behind an apparent "grounding" effect. |
| **Refutation pass** | An attempt, by someone other than the claim's author, to prove the claim false. "Someone" may be a human reviewer or a differently-modeled agent (e.g. the Sonnet challenger role in `adversarial-review`). |
| **Pre-registration** | Writing the predicted number(s) down *before* running the experiment that will produce them. |
| **Gate** | A pass/fail check a hypothesis record must clear before moving to the next lifecycle stage. This skill ships one as `scripts/hypothesis_gate.py`. |

## The evidence bar

A result is **accepted** — allowed to justify a code change, a config
default, or a claim in a report — only when both of these hold:

1. **One mechanism explains every observation, including the negatives.** A
   mechanism that only accounts for the cases supporting the claim and is
   silent on (or contradicted by) the cases that don't is not accepted. It
   is not enough for the numbers to move in the predicted direction on
   average — every observation, especially the ones where the effect should
   *not* appear, needs an explanation tied back to the same mechanism.
2. **The claim survived an assigned adversarial refutation pass.**
   Self-review does not count, and neither does "the tests pass" — the
   assigned refuter's job is specifically to try to break the *causal*
   claim, not just check the code runs. On caliper this is either the
   `adversarial-review` pipeline's challenger/verify-model stage (for
   code-review findings) or, for a smaller research claim (a config flag, an
   ADR decision, a single heuristic), an explicitly named reviewer distinct
   from the author, recorded alongside the claim.

### Worked case study: the grounding experiment (why "explains the negatives" is load-bearing)

Source: `docs/reviews/grounding-conclusions-2026-06-22.md` (full data in the
sibling `grounded-full-20-2026-06-22.{md,json}`). Three acts, same
underlying data, three different apparent conclusions:

| Act | Setup | Apparent result |
|---|---|---|
| 1 | 3 **cherry-picked** FP-heavy partitions | Grounding looks like a miracle: Haiku confirm rate 45% → 100% |
| 2 | Unbiased **full 20** partitions, Haiku-verifier view | Reverses: grounded 48% confirm vs ungrounded 64% — looks like grounding *hurts* |
| 3 | **Opus de-biasing** of every delta between the two arms | The real mechanism: the cheap Haiku *verifier itself* was the confound. It over-confirmed 39 of 69 ungrounded "bugs" (57%) — rubber-stamping style nits and documented fail-open paths as real bugs. |

De-biased numbers (the ones that survived the refutation pass):

| | Ungrounded | Grounded |
|---|---|---|
| Raw findings | 117 | 68 |
| Haiku-"confirmed" | 69 | 31 |
| **Opus TRUE bugs** | **30** | **26** |
| True precision (true/raw) | 26% | **38%** |

**Why this is the worked example for the evidence bar, not just a fun
history lesson:** a mechanism that stopped at Act 1 ("grounding raises
confirm rate") would have been *contradicted* by Act 2 and someone would
have concluded grounding is worse. A mechanism that stopped at Act 2
("grounding lowers confirm rate, therefore ship it off") would have missed
that Act 2's own metric was dominated by verifier noise, not a real
grounding effect. Only the Act 3 mechanism — "the verifier over-confirms
independent of grounding; grounding's real effect is a precision gain (26%
→ 38%) with a small honest recall cost (net −4 real bugs)" — accounts for
**all three acts at once**, including the reversal (a negative result for
the naive "grounding helps" claim) and the eventual recall cost (a negative
result for "grounding is strictly better"). That is what "must explain all
observations including negatives" means in practice: the accepted
conclusion is the one explanation compatible with every act, not the one
compatible with whichever act you looked at first.

The refutation-pass requirement is visible in the same document: the Act 3
Opus adjudication is exactly an assigned refutation pass over the Act 1/Act
2 Haiku-verifier claims, run by a different, more skeptical model than the
one that produced the apparent result. Grounding-conclusions.md also states
the generalizable lesson from this: *"the highest-leverage fix is the
verifier, not the reviewer"* — every number in that document's early acts
was verifier-inflated until a genuinely independent pass ran.

## Predict-the-numbers-before-running discipline

**Rule:** write the number(s) you expect down *before* the experiment that
will produce them runs. Not "grounding should help" — a number: "grounding
should raise true precision by roughly 1.5–2x" or "this new rule should
produce 0–2 findings on caliper's own dogfood run."

**Why:** a prediction written after the fact is indistinguishable from
rationalizing whatever number came out. The grounding case study above is
the cautionary tale for skipping this — Act 1's "miracle" number (100%
confirm) was consistent with a hypothesis nobody had written down in
advance, so there was nothing to catch the selection bias before Act 2's
unbiased run reversed it. If a number had been pre-registered ("grounding
raises *true* precision, it does not necessarily raise the cheap verifier's
*raw* confirm rate"), Act 2's naive reversal would have been recognized
immediately as a metric problem rather than mistaken for a real result.

**How, concretely on caliper:** use the hypothesis record + gate script
shipped with this skill (below). It forces a `predicted_numbers` field to be
filled with real values — not `"TBD"` — before an experiment is allowed to
be marked pre-registered, and it requires an `actual_numbers` entry for
every metric you predicted once the experiment has run, whether or not the
prediction was right.

## The hypothesis record + gate script

`scripts/hypothesis_gate.py` (stdlib-only Python 3, no repo venv required)
validates a hypothesis record — a small JSON file — against the evidence
bar above, in two stages that map onto the two points where a hunch could
otherwise sneak past the bar:

| Stage | Run | Fails unless |
|---|---|---|
| `preregister-check` | **Before** the experiment | `claim`, `mechanism`, `predicted_numbers` (real values, not placeholders), and `observations_explained` (at least one `positive` **and** one `negative` entry) are filled in, and a `refutation_owner` is named |
| `accept-check` | **After** the experiment + refutation pass | everything `preregister-check` needs, plus `actual_numbers` for every predicted metric, a `refutation_verdict` of `CONFIRMED`/`REFUTED`/`UNCERTAIN`, an `explanation` on every `observations_explained` entry, and `refutation_owner != author` |

Template and a filled worked example ship alongside it:

```bash
ls .claude/skills/caliper-research-methodology/templates/
# hypothesis.template.json   hypothesis.example.json
```

### Usage

```bash
# 1. Copy the template into your own scratch space and fill it in.
cp .claude/skills/caliper-research-methodology/templates/hypothesis.template.json \
   .temp/research/my-claim-2026-07-02.json

# 2. Before running your experiment, gate the pre-registration.
python3 .claude/skills/caliper-research-methodology/scripts/hypothesis_gate.py \
  preregister-check .temp/research/my-claim-2026-07-02.json

# 3. Run your experiment, fill in actual_numbers + the refutation verdict.

# 4. Gate acceptance before you let the result inform a change.
python3 .claude/skills/caliper-research-methodology/scripts/hypothesis_gate.py \
  accept-check .temp/research/my-claim-2026-07-02.json
```

`.temp/research/` follows the same gitignored-scratch convention
`adversarial-review` uses for `.temp/review/` — never commit filled-in
records there; only a record that graduates to a **flag** or an **ADR**
(next section) becomes tracked, in the code/policy comment or ADR itself,
not as a standalone JSON file.

**Verified output (run 2026-07-02, this exact repo):**

```
$ python3 .claude/skills/caliper-research-methodology/scripts/hypothesis_gate.py \
    preregister-check .claude/skills/caliper-research-methodology/templates/hypothesis.template.json
FAIL (preregister-check): 5 issue(s)
  - claim: empty. One sentence: what do you believe is true?
  - mechanism: empty. State the CAUSAL reason, not just a correlation.
  - predicted_numbers: empty. Write down the number(s) you expect BEFORE running the experiment -- this is the whole point of the gate.
  - observations_explained: empty. List every observation (existing or expected) the mechanism must account for.
  - refutation_owner: empty. Name the person/agent assigned to try to kill this hypothesis (must not be the author -- see adversarial-review skill's challenger-model role for the orchestration mechanics).
```
Exit code `1`.

```
$ python3 .claude/skills/caliper-research-methodology/scripts/hypothesis_gate.py \
    preregister-check .claude/skills/caliper-research-methodology/templates/hypothesis.example.json
PASS (preregister-check): .claude/skills/caliper-research-methodology/templates/hypothesis.example.json

$ python3 .claude/skills/caliper-research-methodology/scripts/hypothesis_gate.py \
    accept-check .claude/skills/caliper-research-methodology/templates/hypothesis.example.json
PASS (accept-check): .claude/skills/caliper-research-methodology/templates/hypothesis.example.json
```
Exit code `0` both times.

```
# Self-refutation is explicitly rejected (refutation_owner set equal to author):
FAIL (accept-check): 1 issue(s)
  - refutation_owner == author: self-refutation doesn't count. Assign a different reviewer/challenger.
```

`hypothesis.example.json` is an **illustrative** record shaped like a real
`rules_enabled` flag proposal (see `_comment` field in the file) — it is not
a claim that any actual caliper flag was pre-registered this way
historically; none currently has a JSON pre-registration record. It exists
to show the schema passing both gates with real, non-placeholder content.

## Idea lifecycle: experiment → flag → adopted change → documented retirement

| Stage | What it means | Where it lives on caliper |
|---|---|---|
| **Experiment** | A hypothesis record exists; may or may not have cleared `accept-check` yet. | `.temp/research/*.json` (gitignored scratch) or a `docs/reviews/*.md` review artifact |
| **Flag** | The mechanism cleared the evidence bar for *this specific* claim, but is shipped **default-off** so no one is opted in without deciding to be. | A `rules_enabled.<name>` key in `src/caliper/core/opa_input.py` `_DEFAULT_RULES_ENABLED` (`False`), consumed by a guarded rule in `policies/policy.rego`; optionally also documented as its own ADR in `docs/adr/` for a bigger decision |
| **Adopted change** | The flag's default flips to `True` (or the mechanism is folded into always-on code) because it has since proven net-positive across real usage, not just the original experiment's fixtures. | A code change to `_DEFAULT_RULES_ENABLED` (or equivalent) plus its own fresh accept-check — promoting a flag is itself a claim and needs its own evidence, not a carry-over of the original one |
| **Documented retirement** | The idea didn't pan out (net-negative, superseded, or a dead end) and that verdict is written down so nobody re-litigates it. | `docs/solutions/**` frontmatter convention (`title`/`component`/`tags`/`category`/`date`/`severity`/`root_cause`/`status`) — this is `caliper-failure-archaeology`'s territory; cross-reference it by name, do not duplicate its format here |

### Worked example: the currently-gated `rules_enabled` flags (flag stage)

Confirmed by reading `src/caliper/core/opa_input.py` `_DEFAULT_RULES_ENABLED`
(2026-07-02): **6 always-on** rules (`critical_vuln`, `forbidden_license`,
`package_age`, `malicious_package`, `transitive_count`,
`supply_chain_diff`) and **5 opt-in, default-`False`** flags currently
sitting at the *flag* stage of this lifecycle:

| Flag | Default | Rego rule | Source citation |
|---|---|---|---|
| `dev_scope_exemption` | `False` | T-345, downgrades critical/high vuln + forbidden-license deny to warn for `pkg.scope == "dev"` (never for `MAL-` advisories) | `opa_input.py:58`, `policies/policy.rego:70,144-181` |
| `cisa_kev` | `False` | T-344, denies vulns whose `advisory_id` is in operator-supplied `config.kev_ids` | `opa_input.py:63` |
| `unmaintained_package` | `False` | T-346, warns when `pkg.last_release_date` is older than `max_days_since_release` (default 365d); fails open (never fires) if the date is absent/null | `opa_input.py:68`, `policies/policy.rego:234-241` |
| `copyleft_propagation` | `False` | T-347, link-type-aware copyleft enforcement (`copyleft_strong`/`copyleft_weak` operator lists) | `opa_input.py:76` |
| `unreachable_vuln_exemption` | `False` | T-348, downgrades critical/high vuln deny to warn only when the reachability scribe set `reachable == false` explicitly (never on `null`) | `opa_input.py:83`, `docs/adr/009-reachability.md` |

Verified live: `opa test policies/ --ignore '*.yaml' --ignore '*.yml'` → **`PASS: 51/51`** (run 2026-07-02, confirms these guarded rules exist and their fixtures pass with the flags at their documented defaults).

**Why these are the right worked example:** each is a self-contained,
default-off `rules_enabled` gate — exactly the "flag" stage of this
lifecycle, captured either as an inline comment block next to the flag
(`dev_scope_exemption`, `unmaintained_package`, etc.) or, for the bigger
`unreachable_vuln_exemption` decision, as a full ADR
(`docs/adr/009-reachability.md`) whose own Decision/Consequences sections
state the mechanism, note it "mirrors `dev_scope_exemption`," and record the
opt-in default explicitly. Both are legitimate ways to capture a "flag"
stage on caliper — a one-line rule gets an inline comment, a rule with real
design tradeoffs (like the distribution-name → import-name resolution
problem in ADR-009) gets its own ADR.

**Adopted-change stage — currently empty, and that is the honest state.**
As of 2026-07-02, `git log --follow -p -- src/caliper/core/opa_input.py`
shows every `rules_enabled` entry that has ever existed in this file was
added directly as `False`; none has since flipped to `True`. No flag on
caliper has graduated to "adopted." That is not a gap to paper over — do
not write documentation implying otherwise. Promoting a flag's default
requires clearing the evidence bar a **second time**, with evidence from
real usage (not just the original fixture-scale experiment): a fresh
`hypothesis_gate.py accept-check` whose `predicted_numbers` are about
noise/false-positive rate *in production dogfood/CI runs*, not the original
lab conditions, plus its own independent refutation pass.

**Documented-retirement stage.** No `rules_enabled` flag has been retired
either (all 5 opt-in flags above are live and unresolved either way). When
one is — because a fresh accept-check comes back `REFUTED`, or real usage
shows net-negative noise — write it up using `caliper-failure-archaeology`'s
`docs/solutions/**` frontmatter convention (see e.g.
`docs/solutions/runtime-errors/silent-safety-rule-bypasses.md` for the
shape: `title`/`component`/`tags`/`category`/`date`/`severity`/`root_cause`/
`status`) so the *why it didn't pan out* is discoverable the same way every
other dead end on this project is. Do not silently delete the flag code —
`caliper-failure-archaeology` exists specifically so nobody re-fights a
settled question.

## Quick checklist (copy this into a PR description or agent handoff)

- [ ] Claim is one sentence, and it's causal ("X because Y"), not just a
      correlation ("X and Y moved together").
- [ ] `predicted_numbers` written down **before** the experiment ran —
      `hypothesis_gate.py preregister-check` passes.
- [ ] `observations_explained` includes at least one case where the
      mechanism predicts the effect should **not** appear, and that case
      was checked, not assumed.
- [ ] A refuter **other than the author** was assigned and actually tried
      to break the claim (not just re-ran the same check).
- [ ] Every predicted metric has a recorded actual value, including ones
      that contradict the hypothesis — `hypothesis_gate.py accept-check`
      passes.
- [ ] If the result ships as a change: it lands as a **flag**
      (`rules_enabled.<name>`, default `False`) unless you have
      production-scale evidence, not lab-scale, for shipping it default-on.
- [ ] If the result doesn't pan out: it gets a `docs/solutions/**` writeup
      (`caliper-failure-archaeology` convention), not a silent revert.
- [ ] The change itself still goes through `caliper-change-control`'s
      RED/GREEN split, commit-prefix discipline, and dogfood step — this
      checklist governs the *claim*, that skill governs the *commit*.

## Provenance & maintenance

Re-run these to check whether any fact above has drifted:

```bash
# Re-confirm the 5 opt-in rules_enabled flags and their defaults:
python3 -c "
import re
text = open('src/caliper/core/opa_input.py').read()
m = re.search(r'_DEFAULT_RULES_ENABLED: dict\[str, bool\] = \{(.*?)\n\}', text, re.S)
for line in m.group(1).splitlines():
    line = line.strip()
    if line.startswith('\"') and ':' in line:
        print(line.split(':')[0].strip('\"'), 'True' in line)
"

# Re-confirm no rules_enabled flag has ever flipped False -> True:
git log --follow -p --format='COMMIT %h %ad %s' --date=short -- src/caliper/core/opa_input.py | grep -c "True,"

# Re-confirm the OPA policy test count (was PASS: 51/51 on 2026-07-02):
opa test policies/ --ignore '*.yaml' --ignore '*.yml'

# Re-confirm no ADR has been superseded/deprecated (all were "Accepted" on 2026-07-02):
for f in docs/adr/*.md; do echo "$f: $(sed -n '5p' "$f")"; done

# Re-run the gate script's documented examples verbatim:
python3 .claude/skills/caliper-research-methodology/scripts/hypothesis_gate.py \
  preregister-check .claude/skills/caliper-research-methodology/templates/hypothesis.template.json
python3 .claude/skills/caliper-research-methodology/scripts/hypothesis_gate.py \
  accept-check .claude/skills/caliper-research-methodology/templates/hypothesis.example.json
```

Lint the script itself with the project's own tools (both passed clean on
2026-07-02):

```bash
uv run ruff check .claude/skills/caliper-research-methodology/scripts/hypothesis_gate.py
uv run black --check .claude/skills/caliper-research-methodology/scripts/hypothesis_gate.py
```
