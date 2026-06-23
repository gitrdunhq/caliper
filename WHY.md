# Caliper

Caliper (caliper) is a fully deterministic dependency and code review engine for CI — it does the mechanical half of every PR review so engineers can focus on the half that requires judgment.

Every PR that touches a dependency manifest or source file triggers the same tedious checklist: known CVEs, license compatibility, package age, leaked secrets, copy-paste duplication, cyclomatic complexity — caliper runs all of it in under ten minutes, without a human.

The pipeline detects changed packages across 18 ecosystems, fans out across 19 specialist plugins in parallel (Syft, OSV-Scanner, Trivy, ScanCode, Semgrep, Gitleaks, ClamAV, and more), deduplicates overlapping findings by advisory ID with highest-severity-wins logic, then hands the normalized result set to an OPA policy engine that makes the accept/reject decision in pure Rego — no prompts, no probability, no "it depends on the model's mood today."

What makes caliper different is the constraint it refuses to break: **zero LLM in the decision path.** The build passes or fails on deterministic rules that any engineer can read, audit, and debate — not on a language model's interpretation of those rules.

It's also **fail-open by design**: every scanner runs in its own timeout envelope, every failure returns a typed `ScanResult` and the pipeline continues, so a missing binary or a PyPI timeout never silently blocks a deploy.

Two entry points drive the same pipeline — a CLI for CI and a GitHub Copilot Agent (Foreman) for reactive PR review — and every run writes tamper-evident evidence sealed with a SHA-256 hash chain and appended to a Parquet audit lake queryable with DuckDB.

---

## How caliper Compares

Data sourced from vendor sites on 2026-04-27.

### Feature Matrix

| Feature | caliper | Snyk | Sonatype | Checkmarx | Trivy | OWASP DC |
|---------|-------|------|----------|-----------|-------|----------|
| Vulnerability scanning | **GA** | GA | GA | GA | GA | GA |
| License scanning | **GA** | Paid | GA | GA | GA | -- |
| SBOM generation | **GA** | Paid | GA | GA | GA | GA |
| Policy engine (OPA/Rego) | **GA** | Enterprise | Proprietary | Proprietary | IaC only | -- |
| Custom policy rules | **GA** | Enterprise | GA | GA | IaC only | -- |
| Secret scanning | **GA** | GA | -- | GA | GA | -- |
| IaC scanning | **GA** | GA | -- | GA | GA | -- |
| Malware scanning | **GA** | -- | GA | GA | -- | -- |
| Code quality (complexity) | **GA** | -- | -- | -- | -- | -- |
| Code graph analysis | **GA** | -- | -- | -- | -- | -- |
| Copy-paste detection | **GA** | -- | -- | -- | -- | -- |
| Custom semgrep rules | **GA** | -- | -- | -- | -- | -- |
| Type checking | **GA** | -- | -- | -- | -- | -- |
| Audit trail (sealed) | **GA** | Enterprise | GA | GA | -- | -- |
| SARIF output | **GA** | GA | Partial | GA | GA | GA |
| Deterministic (no LLM) | **GA** | No | GA | No | GA | GA |
| Container scanning | -- | GA | Partial | GA | GA | -- |
| Self-hosted | **GA** | Partial | GA | GA | GA | GA |

### Coverage

| Tool | GA features (of 18) | Coverage |
|------|---------------------|----------|
| **caliper** | **17** | **94%** |
| Snyk | 9 | 50% |
| Checkmarx | 9 | 50% |
| Trivy | 8 | 44% |
| Sonatype | 7 | 39% |
| OWASP DC | 4 | 22% |

### What It Costs

| | caliper | Snyk | Sonatype | Checkmarx | Trivy | OWASP DC |
|---|---|---|---|---|---|---|
| **Free tier** | Full | 200 tests/mo | None | None | Full | Full |
| **Entry** | $0 | $25/dev/mo | $57.50/user/mo | Sales call | $0 | $0 |
| **100-dev team/yr** | **$0** | **$126K** | **$69K** | **$80-150K** | **$0** | **$0** |

Sources: [snyk.io/plans](https://snyk.io/plans/), [sonatype.com/products/pricing](https://www.sonatype.com/products/pricing). Checkmarx pricing estimated (sales-gated).

---

## Extensibility: Write Rules, Not Tickets

caliper is designed to be extended by the teams that use it. When you see a recurring anti-pattern in code review, you encode it as a rule — and Caliper catches it on every PR from that point forward.

### Custom Semgrep Rules (61 and growing)

Drop a YAML file in `policies/semgrep/` and caliper picks it up automatically. Real examples from the repo:

```yaml
# Catch subprocess calls without timeouts
- id: org.reliability.subprocess-no-timeout
  pattern: subprocess.run(...)
  pattern-not: subprocess.run(..., timeout=..., ...)
  message: "subprocess.run() without timeout — add explicit timeout"
  severity: WARNING

# Block eval() in production code
- id: org.security.eval-call
  pattern: eval(...)
  message: "eval() is a code injection vector"
  severity: ERROR

# Catch hardcoded localhost in non-test files
- id: org.python.no-hardcoded-localhost
  pattern: |
    "localhost"
  message: "Hardcoded localhost — use config or env var"
  severity: WARNING
```

61 rules ship out of the box across 8 categories: security, reliability, code smells, SOLID violations, testing anti-patterns, contract enforcement, architecture constraints, and banned patterns. Each rule covers 14 file extensions (Python, TypeScript, JavaScript, Go, Ruby, Java, Terraform, Kubernetes, Shell, Docker, and more).

### Custom Code Graph Checks (12 and growing)

The blast-radius plugin builds an AST-to-SQLite code graph, then runs SQL checks against it. Add your own:

### More Custom Checks

```yaml
# Flag functions that call too many other functions
- name: high_fan_out
  severity: medium
  description: Function calls >8 other functions (god function)
  query: |
    SELECT s.name, s.file, s.line, COUNT(e.id) as calls_out
    FROM symbols s
    JOIN edges e ON e.source_id = s.id AND e.kind = 'calls'
    WHERE s.file IN ({changed_files})
    GROUP BY s.id
    HAVING calls_out > 8

# Enforce three-tier architecture
- name: layer_violation
  severity: high
  description: core/ symbol imports from data/ (tier violation)
  query: |
    SELECT s.name, s.file, s.line, t.name as imported
    FROM edges e
    JOIN symbols s ON e.source_id = s.id
    JOIN symbols t ON e.target_id = t.id
    WHERE e.kind = 'imports'
      AND s.file LIKE '%/core/%'
      AND t.file LIKE '%/data/%'
```

Or register checks programmatically:

```python
graph.register_check(
    name="my_custom_check",
    query="SELECT ...",
    severity="medium",
    description="What this catches"
)
```

### Deterministic Bug Detectors (21 and growing)

Beyond semgrep, caliper ships **21 deterministic AST bug detectors** (`CAL-001`…`CAL-021`) in `src/caliper/detectors/` — SQL injection via string formatting, JWT tokens with no audience claim, secrets typed as plain `str` instead of `SecretStr`, subprocess calls without a timeout, unbounded caches, non-atomic file writes, and more. They fire with no LLM, never crash a scan (fail-safe), and are suppressible per-line with `# noqa: CAL-NNN`. Full reference: [`docs/detectors.md`](docs/detectors.md).

### OPA Policy Rules (6 rules, pure Rego)

The policy engine consumes findings from all plugins and makes the accept/reject decision. Every rule is individually toggleable:

```rego
deny[msg] {
    input.findings[_].severity == "critical"
    input.findings[_].category == "vulnerability"
    msg := sprintf("Critical vulnerability: %s", [input.findings[_].id])
}

deny[msg] {
    input.findings[_].first_published_days < input.config.min_package_age_days
    msg := sprintf("Package too new: %s (%d days old)",
        [input.pkg.name, input.findings[_].first_published_days])
}
```

### Per-Repo Configuration

Drop `.caliper.yaml` at the repo root:

```yaml
plugins:
  disabled: [clamav, cspell]    # skip heavy scanners locally
  enabled: [gitleaks]           # always on, even if globally disabled

thresholds:
  package_age_days: 14          # stricter than default 30
  transitive_count: 100         # stricter than default 200
  complexity_threshold: 15      # cyclomatic complexity limit
```

---

## What Only caliper Does

No other tool — free or paid — offers these capabilities:

- **Code graph analysis** — 12 SQL checks against an AST-derived call graph: blast radius, fan-out, layer violations, circular dependencies, inheritance depth, orphan symbols, SRP violations
- **Actionability classification** — every finding is classified as fixable (upgrade available) or blocked (no upstream fix), so teams know what they can actually act on
- **Sealed evidence chain** — SHA-256 hash chain over every scan artifact, appended to a Parquet audit lake queryable with DuckDB. Tamper with any artifact and the chain breaks
- **61 custom semgrep rules** — security, reliability, SOLID, testing, architecture, and contract enforcement patterns that catch what generic rulesets miss
- **21 deterministic bug detectors** — AST rules that catch SQL injection, missing JWT claims, secrets as plain strings, subprocess timeouts, unbounded caches, and more — no LLM, suppressible per-line
- **Natural language code queries** — 12 templates: "what has the highest fan-out?", "show me layer violations", "what depends on X?" — all against the code graph, no LLM required
- **Deterministic + free** — the only tool in the "broad scan + policy engine" quadrant that costs $0

---

## Who It's For

- **Solo developers shipping with AI** — LLMs write code fast but they don't check their own work. caliper is the deterministic backstop that catches what Copilot, Cursor, and Claude miss: vulnerable deps, leaked secrets, complexity creep, copy-paste duplication, broken architecture constraints. You shouldn't have to hold the entire security and quality checklist in your head while you're also reviewing AI-generated code — that's cognitive burden you can delete
- **Platform engineering teams** building internal developer platforms who need a CI gate with a defensible audit trail
- **Security teams** tired of paying $69K-$126K/year for tools whose decisions they can't audit
- **Compliance-driven organizations** (SOC2, FedRAMP, SLSA) that need chain-of-custody from PR to production image
- **Engineering leaders** who want their senior engineers reviewing architecture and design intent, not checking if a dependency has a known CVE
