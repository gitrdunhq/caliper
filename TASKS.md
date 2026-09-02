# TASKS — next branch

Epic: #146 — Black-Box Architecture Refactoring
Branch: `next` (main frozen at v0.2.7)
Principles: Eskil Steenberg — black box modules, primitives first, vendor insulation

## Dependency Graph

```
P0 (source cleanup) ─┐
                      ├─> P1 (PluginFinding) ─┐
                      │                        ├─> P2 (policy separation) ─┐
                      │                        │                           ├─> P3 (composition root) ─┐
                      │                        │                           │                           ├─> P8 (thin entrypoints)
                      │                        │                           │                           ├─> P9 (audit/persistence)
                      │                        │                           │                           └─> P10 (drift guards)
                      │                        ├─> P7 (renderer boundary)  │
                      │                        │                           │
                      ├─> P4 (ToolRunnerPort) ─┘                           │
                      │                                                    │
                      ├─> P5 (RepoSnapshotPort) ──────────────────────────┘
                      │
                      └─> P6 (PullRequestPublisherPort) ──────────────────┘
```

## Packet 0: Source of Truth Cleanup

| # | Task | Size | Status |
|---|------|------|--------|
| #147 | Inventory duplicate src/* mirror trees | S | TODO |
| #148 | Remove duplicate src/* mirror trees | S | TODO |
| #149 | CI guard preventing mirror reintroduction | S | TODO |

## Packet 1: PluginFinding Contract Shim

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #150 | Define PluginFinding and FindingLocation dataclasses | P0 | S | TODO |
| #151 | Add finding normalizer at registry boundary | #150 | M | TODO |
| #152 | Migrate SARIF converter to consume PluginFinding | #151 | S | TODO |
| #153 | Migrate renderer to consume PluginFinding | #151 | S | TODO |
| #154 | Migrate json_report to consume PluginFinding | #151 | S | TODO |
| #155 | Migrate actionability classifier to consume PluginFinding | #151 | S | TODO |

## Packet 2: Separate Analyzer and Policy Contracts

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #156 | Define PolicyEnginePort and PolicyInput/PolicyDecision | P1 | M | TODO |
| #157 | Implement OPA adapter behind PolicyEnginePort | #156 | M | TODO |
| #158 | Remove depends_on=[*] convention from registry | #157 | M | TODO |

## Packet 3: Bootstrap Composition Root

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #159 | Define port protocols for scanner registry, policy, storage | P2 | M | TODO |
| #160 | Create bootstrap composition function | #159 | M | TODO |
| #161 | Wire CLI and agent through composition root | #160 | M | TODO |

## Packet 4: ToolRunnerPort and Subprocess Unification

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #162 | Define ToolInvocation, ToolResult, and ToolRunnerPort | P0 | S | TODO |
| #163 | Implement subprocess ToolRunner adapter | #162 | S | TODO |
| #164 | Route OPA and 2 scanner plugins through ToolRunnerPort | #163 | M | TODO |

## Packet 5: Immutable RepoSnapshotPort

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #165 | Define RepoSnapshotPort and implement git worktree adapter | P0 | M | TODO |

## Packet 6: PullRequestPublisherPort

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #166 | Define PullRequestPublisherPort | P0 | S | TODO |
| #167 | Implement GitHub adapter and route CLI/agent through it | #166 | M | TODO |

## Packet 7: Renderer Boundary

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #168 | Define ReviewReport model and ReportRendererPort | P1 | M | TODO |
| #169 | Migrate markdown, SARIF, JSON renderers behind port | #168 | L | TODO |

## Packet 8: Thin Entrypoints

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #170 | Extract use case layer from CLI review command | P3 | L | TODO |
| #171 | Align agent and webhook with same use case layer | #170 | M | TODO |

## Packet 9: Audit and Persistence Contract

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #172 | Define DecisionStore, EvidenceStore, AuditSink ports | P3 | M | TODO |
| #173 | Implement adapters and wire through composition root | #172 | M | TODO |

## Packet 10: Contract-Generated Docs and Drift Guards

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #174 | Contract-generated docs and drift guards | P3 | M | TODO |

## Totals

- **28 tasks** across 11 packets
- **S:** 10 tasks, **M:** 15 tasks, **L:** 3 tasks
- **Critical path:** P0 → P1 → P2 → P3 → P8/P9/P10
- **Parallel lanes after P0:** P4, P5, P6 can run alongside P1

## Research Findings

**Headline finding: this epic (#146) appears already shipped on `main`.** Every load-bearing contract named in the task list already exists in `src/caliper/`, with tests, ahead of any work being done against this TASKS.md on the `feat/pyrefly-type-checker` branch. Status columns (`TODO`) do not reflect reality — confirm with the epic owner before starting new work; most packets likely need re-scoping to "verify/extend" rather than "define from scratch," or the file should be closed out and archived.

### Packet 0: Source of Truth Cleanup (#147-#149)
- **Finding**: No duplicate `src/*` mirror trees exist. Repo root has a single `src/caliper*` tree (`src/caliperassets/`, `src/caliper/`). `#147`/`#148` inventory/removal work has nothing to act on; `#149`'s CI guard may still be worth adding defensively but there's no known regression to guard against.

### Packet 1: PluginFinding Contract Shim (#150-#155)
- **Pattern**: `PluginFinding(Contract)` already defined in `src/caliper/core/plugin.py:57`. Normalization boundary already exists: `normalize_finding()` (`core/plugin.py:128`), `normalize_findings()` (`core/normalizer.py:23`), and registry-level `_normalize_findings()` (`core/plugin_registry.py:29`).
- **Convention**: Normalization happens at the registry boundary (`PluginRegistry._normalize_findings`), consistent with the "detect-then-scribe" pattern described in CLAUDE.md — plugins emit raw dicts/dataclasses, registry normalizes to `PluginFinding` before anything downstream sees it.
- **Test coverage**: `tests/unit/test_registry_normalization.py`, `tests/unit/test_normalizer.py`, `tests/unit/test_severity_normalization.py`, `tests/unit/test_deterministic_normalizer_guards.py` (an architecture guard test specifically for the normalizer boundary — mirrors the pattern in `tests/unit/test_deterministic_architecture_guards.py`).
- **Pitfall**: Consumers (SARIF, renderer, json_report, actionability classifier) already appear wired to `PluginFinding` per the file/test layout; re-verify via `tokensave_callers` on `PluginFinding` before assuming any of #152-#155 is still open.

### Packet 2: Separate Analyzer and Policy Contracts (#156-#158)
- **Pattern**: `PolicyEnginePort(Protocol)` at `src/caliper/core/policy_port.py:69` with `evaluate(input: PolicyInput) -> PolicyDecision`. `OpaRegoAdapter` (`core/opa_adapter.py:24`) implements it; `FakePolicyEngine` (`core/fake.py:21`) is the test double.
- **Convention**: Ports are `typing.Protocol` classes, runtime-checkable (see `test_policy_engine_port_is_runtime_checkable` in `tests/unit/test_policy_port.py:202`), with a `Fake*` implementation living in `core/fake.py` for test injection — follow this same Protocol+Fake pattern for any new port.
- **Pitfall**: `#158` (remove `depends_on=[*]` convention) — `depends_on` is still present and load-bearing across plugin/registry tests (`tests/unit/test_plugin_registry.py:605`, `tests/unit/test_deterministic_plugin_guards.py:44`, `tests/unit/test_registry_no_policy.py:217`); a guard test (`test_deterministic_plugin_guards.py`) exists specifically to police this — read it before touching the convention, it likely already encodes the target end-state.

### Packet 3: Bootstrap Composition Root (#159-#161)
- **Pattern**: `bootstrap(settings: CaliperSettings) -> ApplicationContext` already implemented at `src/caliper/composition/bootstrap.py:552` (596-line file), with a `bootstrap_test()` test-only variant. CLI already wires through it: `src/caliper/cli/main.py:225` does `from caliper.composition.bootstrap import bootstrap as _bootstrap`.
- **Convention**: matches CLAUDE.md's documented composition root ("`bootstrap()` wires adapters/scribes into an `ApplicationContext`, NullRepository fallback when no DB"). `build_publisher(settings) -> PullRequestPublisherPort` (bootstrap.py:246) shows the per-port builder-function pattern used for each adapter selection.
- **Test coverage**: `tests/unit/test_bootstrap.py` covers both `bootstrap` and `bootstrap_test`.

### Packet 4: ToolRunnerPort and Subprocess Unification (#162-#164)
- **Pattern**: `ToolRunnerPort(Protocol)` at `src/caliper/core/tool_runner.py:38`, single method `run(invocation: ToolInvocation) -> ToolResult`. Already routed through in `plugins/gitleaks.py`, `plugins/swiftlint.py`, and `core/part_gate.py` (`_git`/`_jj` helpers) — i.e. more than the "2 scanner plugins" scoped in `#164`.
- **Convention**: adapters take `tool_runner: ToolRunnerPort | None = None` as a constructor default, defaulting to a real subprocess adapter when unset (see `gitleaks.py:28`) — replicate this DI-with-default-adapter shape for new callers.

### Packet 5: Immutable RepoSnapshotPort (#165)
- **Pattern**: `RepoSnapshotPort(Protocol)` at `src/caliper/core/ports.py:167` (`checkout_ref`, `cleanup`), registered via `REPO_SNAPSHOTS: Registry[RepoSnapshotPort]` in `core/port_registries.py:56`. Git worktree adapter already implemented: `src/caliper/adapters/repo_snapshot.py`.
- **Test coverage**: `tests/unit/test_repo_snapshot_adapter.py`, `tests/unit/test_port_registries.py`, `tests/unit/test_ports.py:372`.

### Packet 6: PullRequestPublisherPort (#166-#167)
- **Pattern**: `PullRequestPublisherPort(Protocol)` at `core/ports.py:176` (`post_comment`, `post_review`, `add_label`). GitHub adapter already implemented: `src/caliper/adapters/github_publisher.py`. Selected via `build_publisher()` in bootstrap and `PUBLISHERS: Registry[PullRequestPublisherPort]` (`port_registries.py:55`).

### Packet 7: Renderer Boundary (#168-#169)
- **Pattern**: `MarkdownRenderer.render(self, report)` at `core/renderer.py:310` already takes a `ReviewReport`-shaped input per its own inline comment (`# report: ReviewReport`); `ReportRendererPort` referenced in `tests/unit/test_ports.py:625` (`test_report_renderer_port_has_render_method`). `build_markdown_renderer()` factory at `renderer.py:343`.
- **Pitfall**: confirm whether SARIF/JSON renderers (`#169` scope) are already migrated behind the same port, or still take raw `PluginResult` lists directly (`_default_render(result: PluginResult)` at `renderer.py:300` suggests a legacy/fallback path may still exist alongside the `ReviewReport` path — worth a targeted diff before assuming this packet is fully done).

### Packet 8: Thin Entrypoints (#170-#171)
- **Pattern**: Use-case layer already exists: `src/caliper/core/use_cases.py` exports `ReviewOptions`, `ReviewResult`, `review_repository(...)` — exactly the extraction target described in `#170`. Extensively tested (`tests/unit/test_use_cases.py`, referenced 10+ times).
- **Pitfall**: `#171` asks to align the agent/webhook entrypoints with the same use-case layer — note the Foreman Copilot agent was removed (`git log`: `0cd48ea chore: remove the Foreman Copilot agent`), so "agent" in this task's scope is stale; only webhook (`src/caliper/webhook/`) alignment may still be relevant.

### Packet 9: Audit and Persistence Contract (#172-#173)
- **Pattern**: `DecisionStorePort`, `EvidenceStorePort`, `AuditSinkPort` (and also `DecisionRepositoryPort`, `GroundingProviderPort`, `ScannerPort`, `ScribePort`) all already defined in `core/ports.py` and imported together in `core/context.py:16`.
- **Test coverage**: `tests/unit/test_persistence_adapters.py` imports and exercises all three (`AuditSinkPort, DecisionStorePort, EvidenceStorePort`).

### Packet 10: Contract-Generated Docs and Drift Guards (#174)
- **Pattern**: no existing "contract → generated docs" tooling found under this name; the closest existing "drift" concept in the codebase is the `docker_pin_drift` config detector (`src/caliper/detectors/config/docker_pin_drift.py`), which is unrelated (Docker image tag pinning, not architecture-contract drift). `#174` looks like a genuinely open task — CLAUDE.md's `docs/CAPABILITIES.md` ("single source of truth... update whenever you add/remove/modify...") is the closest existing manual-discipline mechanism it would presumably automate/guard.
- **Convention**: the existing guard-test pattern to model this on is `tests/unit/test_deterministic_architecture_guards.py` (AST-walking import-direction enforcement, `core/tier_map.py`) — an analogous AST/graph-walking guard keyed off the port Protocols in `core/ports.py` would fit the same style.

### Cross-cutting
- **Convention**: every new Protocol-based port in this codebase follows: `XPort(Protocol)` in `core/ports.py` (or a dedicated `core/x_port.py` for larger contracts like `policy_port.py`) → concrete adapter in `adapters/` or `plugins/` → `Registry[XPort]` entry in `core/port_registries.py` → `Fake`/test-double in `core/fake.py` or inline in the test file → runtime-checkable Protocol test asserting `isinstance` works.
- **Pitfall**: several task IDs in this TASKS.md (#150, #156, #159, #162, #165, #166, #168, #170, #172) describe "define" work for contracts that already exist under the exact same names. Before implementing any task here, run `tokensave_search` for the contract name first — high risk of duplicate/conflicting definitions if an agent implements blind from the task description alone.
