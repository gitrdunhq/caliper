# Caliper — Copilot Context

This repo is a deterministic dependency and code review tool for CI. 16 scanner plugins, 900+ tests, zero LLM in the decision path.

## Architecture

Three-tier (cli → core → data). Imports flow downward only. Plugins auto-discover via `PluginRegistry`. All external calls have timeouts. Fail-open: no scanner failure blocks a build.

## Conventions

- Python 3.12+, structlog for logging, Pydantic models at boundaries
- Enums for all state fields, never raw strings
- Every source file has a `# tested-by:` annotation
- TDD red-green mandatory — test must fail before implementation
- Tests run in containers only (`make test`)

## What caliper already covers — do not duplicate

The Foreman Review CI job runs 16 deterministic plugins. Its findings appear as inline PR comments. Do not restate them.

| Plugin | Catches |
|--------|---------|
| OSV-Scanner, Trivy | Known CVEs |
| ScanCode | Forbidden licenses |
| Gitleaks | Secrets and credentials |
| Supply Chain | Unpinned deps, package age, malware |
| Lizard + Radon | Cyclomatic complexity |
| PMD CPD | Copy-paste duplication |
| cspell | Spelling |
| ls-lint | File naming conventions |
| kube-linter | K8s security |
| Semgrep | AST code patterns |
| Mypy/Pyright | Cross-file type errors |
| Blast Radius | Fan-out, layer violations |
| OPA | Policy verdict (6 Rego rules) |
| Syft | SBOM generation |
| ClamAV | Malware scanning |
