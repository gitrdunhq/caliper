# Grounded vs Ungrounded Haiku Review — Full 20-Partition Adjudication

**Date:** 2026-06-22  **Adjudicator:** Opus (delta-only; Haiku challenger was base verifier)
**Target:** /home/user/eedom, 20 partitions  **Question:** is the 69->31 confirmed drop real recall loss or removed baseline noise?

## TL;DR
- Overlap: **both=14, grounded-only=17, ungrounded-only=55**.
- Recall verdict on the 55 ungrounded-only: **16 REAL_BUG_SUPPRESSED vs 39 BASELINE_OVERCONFIRM**. The 69->31 drop is *mostly* baseline noise (~71% of the dropped uniques were not bugs), but **not entirely** — 16 genuine defects were suppressed.
- De-biased TRUE-confirmed: **ungrounded 30, grounded 26**. Real recall delta = **4** (ungrounded found 4 more real bugs).
- Grounded-only adjudication: **12 REAL_NEW_BUG vs 5 GROUNDED_OVERPRODUCE** — grounding surfaced 12 real bugs the ungrounded arm missed.

## Aggregate

### Haiku-verifier view (as-run)
| Arm | raw | confirmed | FP | uncertain | precision |
|---|---|---|---|---|---|
| Ungrounded | 117 | 69 | 38 | 10 | 64.5% |
| Grounded | 68 | 31 | 33 | 4 | 48.4% |

Grounded cut raw volume 42% (117->68) and confirmed 55% (69->31). At face value grounded looks *worse* on precision (48% vs 64%) — but that is the Haiku challenger's view and is misleading; see de-biased.

### Opus-adjudicated de-biased view
Counts each arm's TRUE-confirmed = matched-both (corroborated by both arms) + that arm's Opus-adjudicated real uniques.

| Arm | Haiku-confirmed | matched-both | real uniques | non-bug uniques | **Opus TRUE-confirmed** |
|---|---|---|---|---|---|
| Ungrounded | 69 | 14 | 16 | 39 (overconfirm) | **30** |
| Grounded | 31 | 14 | 12 | 5 (overproduce) | **26** |

**Real recall delta = 30 - 26 = 4 bugs.** The headline 38-bug gap (69-31) is ~90% illusory: 39 of the 55 ungrounded-only confirms were baseline over-confirmation by the lenient Haiku challenger. The genuine recall cost of grounding is **4 net real bugs** (16 suppressed minus 12 newly-surfaced).

## Overlap matrix
- **BOTH (14):** same file, line within ~12, same underlying defect — corroborated by both arms.
- **GROUNDED_ONLY (17):** 12 real-new-bug, 5 overproduce.
- **UNGROUNDED_ONLY (55):** 16 real-suppressed, 39 baseline-overconfirm.

### GROUNDED_ONLY real-new-bugs (12) — grounding caught these, ungrounded missed
- **P01-1** evaluate_sbom() never sets commit_sha on ReviewRequests -> None into audit/parquet (evaluate() does)
- **P03-2** OpaRegoAdapter never populates triggered_rules; OpaEvaluator does -> user sees no rules on adapter path
- **P03-3** pipeline PolicyDecision->PolicyEvaluation drops warn_reasons/constraints -> approve_with_constraints renders empty
- **P08-3** concern_prompt except omits ValueError/JSONDecodeError from resp.json() -> uncaught, breaks fail-open
- **P11-1** get_annotation_text ', '.join(elements) crashes (TypeError) when a recursive call returns None (ast.Starred)
- **P11-6** is_applicable fnmatch on file.name only -> docstring 'config/*.yaml' patterns can never match
- **P13-3** circuit_breaker "half" in keyword.arg.lower() with no None guard -> AttributeError on **kwargs (swallowed)
- **P14-1** _is_dangerous_merge returns True for ANY {**a,**b} dict; config-key check is dead -> over-broad false positives
- **P15-2** graph_builder _walk_upstream .fetchone()["id"] unguarded -> TypeError crash when symbol missing/stale
- **P16-4** osv _resolve_severity uses assignment not max() -> CVSS 5.0 downgrades a database_specific "high" to "medium"
- **P16-5** gitleaks crash-detect requires exit!=0/1 AND missing report -> partial report on crash silently parsed as clean
- **P20-1** webhook _load_app EedomSettings() with required db_dsn no default -> ValidationError crash before fail-open bootstrap

### GROUNDED_ONLY overproduce (5) — wrongly confirmed despite grounding
`P02-2` no-op solver validator (style); `P09-1` cached-config duplication (style); `P11-3` BatchVisitor 'dead code' is actually single-dispatch correct; `P13-2` cache_ttl over-broad var-marking (tunable heuristic); `P14-4` enclosing_symbol misses .pyi/.pyw (graceful fail-open degradation).

### UNGROUNDED_ONLY real-suppressed-bugs (16) — TRUE recall cost of grounding
- **P05-6** load_merged_config drops PluginConfig.semgrep sub-config on package merge -> extra_config_dirs/exclude_rules lost
- **P10-1** subprocess_runner does not catch UnicodeDecodeError (text=True on binary) -> propagates, breaks fail-open
- **P10-2** get_version() unguarded importlib.metadata.version("eedom") at import -> PackageNotFoundError crashes renderer import
- **P10-3** subprocess_runner catches only FileNotFoundError, not other OSError (PermissionError) -> propagates
- **P11-2** DetectorFinding.to_finding() drops line_number/column (Finding model lacks them) -> SARIF/PR location lost
- **P12-1** secret_str only visits ast.AnnAssign; bare api_key="secret" (ast.Assign) never flagged -> false negative
- **P12-7** sql_injection flags .format with no args ("...?".format()) -> false positive on safe query
- **P12-8** sql_injection flags any ast.JoinedStr incl. constant f"SELECT" (no FormattedValue) -> false positive
- **P13-10** cache_eviction treats @lru_cache(maxsize=None) (unbounded) as bounded -> false negative
- **P13-4** transaction_rollback _is_looped_insert attributes execute to ANY loop in func, not enclosing one -> wrong scoping
- **P14-1** config_merge _is_dangerous_merge over-broad (same defect as grounded P14-1)
- **P14-2** docker_pin_drift regex pip\s+install\b unanchored at "pip" -> "mypip install x==1" false positive
- **P17-2** complexity.py run() passes no timeout to runner -> config scanner_timeout ignored, runner hardcoded 60 used
- **P17-3** cpd.py run() passes no timeout to runner -> config timeout never propagates
- **P20-1** webhook config.py WebhookSettings.secret required no default; _load_app() unguarded -> ValidationError startup crash
- **P20-2** webhook server enumerates via Path.rglob() directly, bypassing FileSourcePort seam (CLAUDE.md violation)

### UNGROUNDED_ONLY baseline-overconfirm (39) — lenient Haiku challenger noise
These were confirmed by the ungrounded arm but are NOT bugs (correct code, documented intent, or pure style): P01-10, P01-5, P01-6, P01-7, P01-9, P02-3, P03-1, P03-3, P03-6, P04-1, P04-4, P06-3, P09-2, P09-3, P10-5, P11-3, P12-3, P12-5, P12-6, P13-7, P13-8, P14-6, P15-2, P15-4, P15-5, P15-7, P16-5, P16-6, P17-1, P17-10, P17-5, P17-6, P17-9, P18-2, P18-3, P18-4, P18-5, P20-3, P20-6.

### Matched-both (14)
| grounded | ungrounded | file | g_ln | u_ln |
|---|---|---|---|---|
| P02-1 | P02-1 | core/normalizer.py | 38 | 40 |
| P03-1 | P03-2 | core/opa_adapter.py | 116 | 107 |
| P05-1 | P05-5 | core/repo_config.py | 73 | 69 |
| P13-1 | P13-3 | detectors/reliability/subprocess_timeout.py | 132 | 132 |
| P14-2 | P14-3 | detectors/metrics/high_cardinality.py | 156 | 151 |
| P14-3 | P14-4 | detectors/process/tested_by.py | 85 | 82 |
| P15-1 | P15-1 | plugins/_runners/graph_builder.py | 389 | 392 |
| P15-3 | P15-3 | plugins/_runners/cpd_runner.py | 297 | 297 |
| P16-1 | P16-1 | plugins/osv_scanner.py | 106 | 106 |
| P16-2 | P16-3 | plugins/clamav.py | 69 | 69 |
| P16-3 | P16-2 | plugins/syft.py | 69 | 69 |
| P16-6 | P16-8 | plugins/scancode.py | 56 | 56 |
| P17-1 | P17-4 | plugins/ls_lint.py | 47 | 47 |
| P18-1 | P18-1 | plugins/supply_chain.py | 292 | 292 |

## Per-partition table
(Ungrounded per-partition raw/FP were not persisted in the baseline artifact — only confirmed+uncertain carry partition there; grounded has full raw/confirmed/FP.)

| Part | Title | U conf | U unc | G raw | G conf | G FP | G unc |
|---|---|---|---|---|---|---|---|
| P01 | pipeline/orchestration | 5 | 0 | 1 | 1 | 0 | 0 |
| P02 | solver/normalizer | 2 | 0 | 2 | 2 | 0 | 0 |
| P03 | policy/OPA | 4 | 2 | 3 | 3 | 0 | 0 |
| P04 | seal/evidence/telemetry | 2 | 2 | 0 | 0 | 0 | 0 |
| P05 | config/file-enumeration | 2 | 0 | 1 | 1 | 0 | 0 |
| P06 | enrichment/llm | 1 | 1 | 1 | 0 | 1 | 0 |
| P07 | output/render/sarif | 0 | 1 | 8 | 0 | 7 | 1 |
| P08 | concern/review | 0 | 0 | 10 | 1 | 6 | 3 |
| P09 | taskfit/actionability | 2 | 0 | 2 | 1 | 1 | 0 |
| P10 | models/infra | 4 | 0 | 3 | 0 | 3 | 0 |
| P11 | detector framework | 2 | 0 | 6 | 3 | 3 | 0 |
| P12 | detectors/security | 6 | 1 | 0 | 0 | 0 | 0 |
| P13 | detectors/reliability | 5 | 0 | 4 | 3 | 1 | 0 |
| P14 | detectors config/metrics/process/enrichers | 5 | 0 | 4 | 4 | 0 | 0 |
| P15 | plugin infra/runners | 6 | 1 | 7 | 3 | 4 | 0 |
| P16 | scanner plugins A | 6 | 1 | 6 | 6 | 0 | 0 |
| P17 | scanner plugins B | 8 | 0 | 1 | 1 | 0 | 0 |
| P18 | supply-chain | 5 | 0 | 5 | 1 | 4 | 0 |
| P19 | data/cli | 0 | 1 | 0 | 0 | 0 | 0 |
| P20 | composition/agent/webhook | 4 | 0 | 4 | 1 | 3 | 0 |

## Where grounding helped vs hurt (per partition)

**Grounding CRUSHED false positives on context-starvation partitions** — where a finding's safety depends on cross-file contracts the ungrounded reviewer couldn't see:
- **P07 (json/sarif render):** grounded raw 8 -> 0 confirmed, 7 FP self-caught. Ungrounded confirmed 0 here too, but only after the challenger killed them; grounded's ledger pre-empted all 8 (orjson/extra=allow, SARIF startLine-only, timestamp-determinism — all documented intent).
- **P08 (concern/LLM PR-review):** grounded 10 raw -> 1 confirmed, 6 FP, 3 uncertain. The don't-flag ledger correctly spared polymorphic hasattr/get, any() short-circuit, dict.get defaults. Ungrounded confirmed 0 in P08 — neither arm over-confirmed, but grounded did the work up front.
- **P18 (sbom/supply-chain diff):** grounded 5 raw -> 1 confirmed, 4 FP (fail-open lexicographic fallback, bounded install-hooks, dual score_signals paths all correctly spared). Ungrounded over-confirmed 5 here, 3 of which Opus rules baseline-overconfirm (P18-2/3/4/5 mostly NOTABUG).
- **P10 (subprocess/version seams):** grounded 3 raw -> 0 confirmed, 3 FP — BUT this is where grounding HURT: it self-refuted P10-1 (UnicodeDecodeError) and P10-3 (OSError) which Opus rules REAL. Over-trusting the 'fail-open is intentional' ledger suppressed two genuine uncaught-exception gaps.

**Grounding OVER-PRODUCED / mis-fired on:**
- **P11 / P13 / P14 (detectors):** grounded confirmed several real None-guard crashes (good — P11-1, P13-3, P14-x) but also shipped style/heuristic overproduce (P11-3 dead-code misread, P13-2, P14-4). Detector-internal AST reasoning is where both arms are noisiest.
- **P16 (scanner timeout messages):** both arms confirmed the timeout=0 family (6 grounded, matched in ungrounded). These are REAL but purely cosmetic wrong-message bugs; grounding did not filter low-value findings, it confirmed all of them.

**Where grounding clearly WON on recall (real new bugs ungrounded missed):** the OpaRegoAdapter cross-file contract divergences (P03-2 triggered_rules, P03-3 constraints/warn_reasons) and the graph_builder `_walk_upstream` unguarded fetchone crash (P15-2) — exactly the cross-file-contract class the grounding bundle was built to expose. Ungrounded never surfaced these.

## VERDICT

**On the unbiased run, grounding was a net-neutral-to-slightly-negative trade on RECALL and a large WIN on PRECISION/effort — but it did cause real, non-zero recall loss. Do not spin it as free.**

The 69->31 collapse is overwhelmingly the removal of baseline noise: of 55 ungrounded-only confirms, **39 (71%) were not bugs** — the plain-Haiku challenger rubber-stamped style nits, documented fail-open paths, and reserved-by-design choices. The Opus-debiased confirmed counts are **30 (ungrounded) vs 26 (grounded)**, not 69 vs 31. So the honest precision story flips: ungrounded's *true* precision was 30/69 = 43%; grounded's was 26/31 = 84%. Grounding roughly **doubled precision and halved reviewer volume**.

BUT recall is not free. Grounding genuinely suppressed **16 real bugs** the ungrounded arm caught, while surfacing **12 real bugs** ungrounded missed — a **net loss of 4 real defects**. The suppression pattern is diagnostic and concerning: grounding's 'this is intentional fail-open' ledger caused Haiku to wave through genuine uncaught-exception gaps (P10-1 UnicodeDecodeError, P10-3 OSError, P08-3-adjacent) and real detector false-negatives (P12-1 bare-assign secrets, P12-7/8 sql_injection FPs, P13-4/P13-10 scoping). The grounding bundle's strength (knowing what's intended) is also its failure mode: it over-trusts 'documented = correct' and rationalizes away true defects in fail-open code. Meanwhile the 12 real new bugs it found are higher-value (cross-file contract divergences, a real crash) than several of the cosmetic ones it lost.

**Net:** grounding is worth shipping for the precision/effort win, but it needs a recall backstop on fail-open / exception-handling code, because that is exactly where its 'intentional' prior misfires. The reviewer should be instructed that 'fail-open by design' justifies a *broad* except, not a *missing* one (uncaught UnicodeDecodeError/OSError are still bugs).

## Caveats
- **Single run.** No variance estimate; one Haiku sample per arm.
- **Haiku challenger as base verifier.** Opus only adjudicated the deltas (the 55+17 uniques), not the 14 matched-both nor the FPs both arms agreed on. The de-biased counts inherit the challenger's calls on the overlap.
- **Opus shares family priors** with the reviewers (same defect taxonomy), so 'REAL' calls on heuristic-detector findings (P11/P13/P14) are not independent ground truth.
- **Cross-arm matching is fuzzy** (same file, line within ~12, judged-same defect). P15-1/P15-2 grounded both describe the one `_walk_upstream` crash (intra-arm duplicate); counted once on the real side.
- **Ungrounded per-partition raw/FP not persisted** in the baseline artifact, so the per-partition table shows ungrounded confirmed/uncertain only against grounded's full raw/confirmed/FP.
- Timeout-message family (P16) counts as REAL but cosmetic; if those were reclassified as non-defects the recall delta would widen against ungrounded slightly (they appear in matched-both, not the delta).