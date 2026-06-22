<div align="center">
  <img src="../assets/hero.svg" alt="Eagle Eyed Dom" width="900">
  <br>
  <strong>Fully deterministic dependency review for CI.</strong><br>
  19 plugins. 6 OPA policy rules. 18 ecosystems. Zero LLM in the decision path.
  <br><br>

  <a href="../README.md#quick-start"><img src="https://img.shields.io/badge/get_started-→-d4251a?style=flat-square" alt="Get Started"></a>
  <a href="../README.md#the-19-plugins"><img src="https://img.shields.io/badge/19_plugins-deterministic-f2c14a?style=flat-square&labelColor=0e0706" alt="19 Plugins"></a>
  <a href="../README.md#opa-policy-rules"><img src="https://img.shields.io/badge/OPA-6_rules-1e3a8a?style=flat-square" alt="OPA Rules"></a>
  <a href="../LICENSE"><img src="https://img.shields.io/badge/license-PolyForm_Shield-7ae582?style=flat-square" alt="PolyForm Shield License"></a>
</div>

<br>

---

## The problem

Your senior engineers spend hours per week reviewing PRs for the same categories of issues: unpinned dependencies, known CVEs, leaked secrets, copy-pasted code, complexity spikes, license violations, K8s misconfigs. These are mechanical checks — they don't require judgment, but they consume attention. Every hour a senior engineer spends on a mechanical review is an hour not spent on architecture, mentoring, or shipping.

Meanwhile, the things that slip through — an unpinned dependency with a known CVE, a secret in a config file, a GPL-licensed transitive dep — are the ones that page you at 2am or show up in an audit.

## What eedom does

Drop it into your CI pipeline. It runs 19 scanners on every PR, evaluates findings against policy rules you control, and posts a clear verdict: **BLOCKED**, **WARNINGS**, or **ALL CLEAR** with a 0-100 health score.

Your engineers open the PR. The review is already there. They read the verdict, focus on the business logic, and skip the mechanical checklist. The cognitive burden shifts from "did anyone check the deps" to "the tool checked the deps, here's what it found."

**What it catches:**

| Category | What it finds |
|----------|--------------|
| Vulnerabilities | Known CVEs across 18 ecosystems (npm, pip, Go, Rust, Java, ...) |
| Secrets | API keys, tokens, passwords — 800+ patterns |
| License risk | GPL, AGPL, SSPL in your dependency tree |
| Supply chain | Unpinned deps, missing lockfiles, packages published < 30 days ago, malware |
| Code quality | Cyclomatic complexity, copy-paste, naming conventions, spelling |
| Infrastructure | K8s resource limits, privileged containers, latest tags |
| Code structure | Blast radius (what breaks if you change this), layer violations, dead code |

**What it produces:**

- A PR comment with the verdict, severity score, and per-category findings
- SARIF output for the GitHub Security tab
- A tamper-evident evidence log (SHA-256 sealed, Parquet audit trail, DuckDB-queryable)

## Why it's not another noisy scanner

Most scanning tools produce a wall of findings and leave the engineer to triage. Eedom is different:

1. **Policy decides, not the tool.** OPA rules define what blocks, what warns, and what passes. Your team writes the policy. The scanner enforces it. No ambiguous "medium confidence" — either it trips a rule or it doesn't.

2. **Deterministic.** Same code, same findings, every time. No model inference. No probabilistic scoring. No "AI detected a potential issue." The decision path is OPA + scanner output, fully reproducible, fully auditable.

3. **Fail-open, fail-loud.** If a scanner times out or a binary is missing, the PR is NOT blocked. But the failure is visible in the comment — `[TIMEOUT] scancode timed out after 60s`. No silent passes. No phantom cleans.

4. **One comment, not nineteen.** All 19 scanners produce one unified PR comment with a single verdict. Your engineers read one thing, not one alert per tool.

## How to adopt it

**Option 1 — GitHub Action (5 minutes)**

```yaml
- uses: org/eedom@main
  with:
    operating-mode: advise    # comment on PRs, don't block builds
    team: platform
```

Start in `advise` mode. It comments but doesn't block. Your team sees the findings for a sprint, tunes the policy (`.eagle-eyed-dom.yaml`), disables noisy plugins, adjusts thresholds. When confident: switch to `block`.

**Option 2 — Self-hosted container**

```bash
podman run --rm -v $(pwd):/workspace eedom:latest \
  review --repo-path /workspace --all
```

**Option 3 — GitHub Copilot Extension**

GATEKEEPER wraps the same pipeline as an interactive Copilot agent — ask it about a specific package, run a targeted scan, get findings in chat.

## What your team controls

Everything. No vendor lock-in on policy.

- **`.eagle-eyed-dom.yaml`** — enable/disable any of the 19 plugins, set thresholds, configure per-repo
- **OPA rules** — 6 Rego rules, version-controlled, individually toggleable. Add your own.
- **`--disable clamav,cspell`** — turn off plugins per-run from the CLI
- **Monorepo support** — auto-discovers packages, runs per-package, respects per-directory config overrides

## What it costs

Nothing. PolyForm Shield 1.0.0 — free for internal use at any scale. No per-seat fees. No usage limits. No telemetry unless you opt in.

The only restriction: you can't build a competing code review product on top of it.

## What it doesn't do

It doesn't auto-fix. It finds and reports. Your engineers make the decisions.

It doesn't replace your SAST/DAST. It covers dependencies, supply chain, code quality, and infrastructure — not runtime testing, fuzzing, or auth flows.

It doesn't phone home by default. Telemetry is opt-in (`telemetry: {enabled: true}` in config) and collects only operational signals — never source code, file paths, or package names.

**Why telemetry exists:** Eedom dogfoods itself. Every scan is a data point about the tool's own reliability. When a plugin times out for 12% of users, when a parser chokes on a specific manifest format, when an error code fires that we've never seen before — telemetry surfaces it. A human triages the signal, files the bug, and an engineer fixes it. The tool gets better because it's watching itself fail in the real world, not in a test suite. Your opt-in telemetry makes the scanner more reliable for everyone — including you.

**You choose the feedback loop.** Telemetry has two modes, configurable per install:

- **`community`** (default when enabled) — operational signals flow back to the eedom project. Bugs found across the community are triaged, fixed, and shipped in the next release. You benefit from every other team's edge cases.
- **`self-heal`** — signals stay within your infrastructure. Your eedom instance detects its own failures, files internal issues, and your team fixes them. The community version doesn't see your data, and you don't get community fixes automatically. For teams with strict data residency requirements or air-gapped environments.

Both modes collect the same 9 signals. The only difference is where the data goes.

## One more thing

Every scan produces a sealed evidence bundle — `decision.json` + `memo.md`, SHA-256 chained to the previous run. If someone asks "was this PR reviewed before it shipped?" — you can prove it. Cryptographically.

The audit log is a 27-column Parquet file. Point DuckDB at it:

```sql
SELECT package_name, decision, vuln_critical
FROM 'evidence/decisions.parquet'
WHERE team = 'platform' AND decision = 'reject'
```

---

Questions? Run `eedom review --repo-path . --all` against your own repo. If the findings aren't useful, don't adopt it. If they are — that's the pitch.
