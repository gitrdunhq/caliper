## 🦅 Caliper — org/repo#1
**golden**


> 🔴 **BLOCKED**



> **Security: 77/100** · Quality: 92/100


| Plugin | Findings |
|--------|----------|
| Files scanned | 0 |
| trivy | error: not installed |
| osv-scanner | 2 |
| semgrep | 3 |
| detectors | 3 |


### Actionability

> 1 findings have available fixes. 7 are blocked on upstream.


**1 fixable** — upgrade available:

- `requests` 2.19.0 → **2.32.0** (critical) — [GHSA-xxxx-crit1](https://osv.dev/GHSA-xxxx-crit1)




**7 blocked** — no fix available:

- **semgrep**: 3 findings (medium, high)
- **detectors**: 3 findings (medium, high, low)
- **osv-scanner**: 1 findings (low)




### osv-scanner
**osv-scanner**: 2 findings
- 🔴 `requirements.txt:4` — requests 2.19.0: remote code execution
- 🔵 `requirements.txt:12` — leftpad 1.0.0: minor information disclosure

### semgrep
**semgrep**: 3 findings
- 🟠 `src/app/cli.py:88` `python.security.subprocess-shell` — subprocess called with shell=True
- 🟠 `src/app/db.py:42` `python.security.sql-injection` — SQL query built with string formatting
  - **Fix:** use a parameterized query
- 🟡 `src/app/auth.py:15` `python.security.weak-hash` — MD5 is cryptographically weak

### detectors
**detectors**: 3 findings
- 🟠 `src/app/db.py:120` `CAL-001` — bare except swallows every error
- 🟡 `src/app/models.py:9` `CAL-004` — mutable default argument
  - **Fix:** default to None and build the list inside the function
- 🔵 `src/app/util.py:51` `CAL-009` — f-string without placeholders

*skipped: typos (no .typos.toml)*

<details>
<summary>Notes (below severity floor)</summary>

- ⚪ `src/app/util.py:3` `python.lang.best-practice.unused-import` — unused import `os`

</details>

---
*Caliper v0.0.0+golden · 3 semgrep · 3 detectors · 2 osv-scanner*
