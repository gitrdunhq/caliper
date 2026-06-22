# Security Plugins

These plugins gate merges. Any finding at **Critical** or **High** blocks the PR.

---

## gitleaks

Scans diffs and history for secrets and credentials using 800+ built-in patterns; supports custom rules via `.caliper/gitleaks.toml` for org-specific PII patterns.

| Severity | Condition |
|----------|-----------|
| Critical | Hardcoded API key, password, or token with high-confidence pattern match |
| High | Potential secret — pattern match with lower confidence |

Blocks because a leaked credential is an immediate, irreversible blast radius — the key is already in git history the moment the commit lands.

---

## semgrep

Runs AST-based code pattern analysis to catch injection flaws, insecure APIs, and missing error handling without executing the code.

| Severity | Condition |
|----------|-----------|
| Critical | SQL injection, OS command injection |
| High | XSS, insecure deserialization |
| Warning | Deprecated API usage, missing error handling |

Blocks because injection vulnerabilities are exploitable in production and cannot be mitigated after merge without a targeted patch.

---

## trivy

Scans container images and filesystems for known CVEs, matching against NVD and vendor advisories.

| Severity | Condition |
|----------|-----------|
| Critical | CVE with a public exploit or CVSS 9+ |
| High | CVSS >= 7.0 |
| Medium | CVSS 4.0–6.9 |

Blocks because shipping a Critical or High CVE into production creates a documented, weaponizable attack surface.

---

## osv-scanner

Checks declared and transitive dependencies against the [OSV.dev](https://osv.dev) vulnerability database.

| Severity | Condition |
|----------|-----------|
| Critical | CVE with public exploit in a direct or transitive package |
| High | CVSS >= 7.0 in any resolved package |
| Medium | CVSS 4.0–6.9 |

Blocks for the same reason as trivy: a known vulnerable package in the dependency graph is an open door that only grows harder to close after merge.

---

## clamav

Scans committed files for malware signatures using the ClamAV engine and signature database.

| Severity | Condition |
|----------|-----------|
| Critical | Any positive malware signature match |

Blocks unconditionally — a malware detection in source code or bundled assets means the commit must not land under any circumstances.

---

## supply-chain

Validates package provenance: rejects newly published packages, unpinned versions, and missing lockfiles before they enter the dependency graph.

| Severity | Condition |
|----------|-----------|
| Critical | Package published < 30 days ago (typosquatting / takeover window) |
| High | Lockfile missing for a package manager with lock support |
| Warning | Unpinned dependency (range or `latest`) |

Blocks because a brand-new or unpinned package is the primary vector for supply-chain compromise — the risk window is widest in the first 30 days after publication.

---

## opa

Evaluates commits and PR metadata against custom Rego policies defined by the team.

| Severity | Condition |
|----------|-----------|
| Varies | Determined entirely by the policy definition |

Blocks when a policy explicitly sets `deny` with a Critical or High severity — policies encode org-specific invariants (compliance rules, deploy gates, required approvals) that no generic scanner can capture.

---

## scancode

Identifies SPDX license identifiers in source files and dependency manifests to enforce license compatibility.

| Severity | Condition |
|----------|-----------|
| Critical | GPL / AGPL / SSPL found in a proprietary codebase |
| High | License is unrecognized or absent |
| Warning | Weak copyleft (LGPL, MPL) requiring attention |

Blocks because a GPL file in a proprietary repo creates an immediate legal obligation to open-source the product — that cannot be undone by a follow-up PR.

---

## kube-linter

Lints Kubernetes manifests for security misconfigurations before they reach a cluster.

| Severity | Condition |
|----------|-----------|
| Critical | Container running as root, no CPU/memory limits |
| High | Missing liveness/readiness probes, privileged container |
| Warning | Missing recommended labels |

Blocks because root containers and unlimited resources are trivially exploitable for node breakout and denial-of-service; fixing them post-deploy requires a rolling restart under live traffic.

---

## cfn-nag

Scans CloudFormation templates for security misconfigurations: IAM wildcards, open security groups, unencrypted resources.

| Severity | Condition |
|----------|-----------|
| Critical | IAM policy with "Resource": "*" + "Action": "*" (overly permissive) |
| High | Security group open to 0.0.0.0/0, S3 bucket without encryption, EBS volume without encryption |

Blocks because overly permissive IAM roles and open network endpoints are trivial escalation paths that cannot be remediated post-deploy without a full stack rebuild.

---

## cdk-nag

Scans AWS CDK synthesized templates for security violations. Always runs `cdk synth` first — never uses a stale `cdk.out/`.

| Severity | Condition |
|----------|-----------|
| Critical | Overly permissive IAM grants or publicly accessible resources |
| High | Unencrypted storage, missing encryption keys, privileged container settings |

Blocks for the same reason as cfn-nag: CDK violations represent infrastructure-as-code bugs that manifest at synthesis time and are security-critical at scale.

---

## See also

- [Deterministic detectors](../detectors.md) — 21 AST-based bug-pattern rules (CAL-001..CAL-021) that run alongside the plugins.
