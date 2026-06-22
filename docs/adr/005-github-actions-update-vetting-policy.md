# ADR-005: GitHub Actions Update Vetting Policy

## Status

Accepted

## Context

GitHub Actions updates are CI supply-chain changes. A compromised or unsafe
action can run with repository credentials, publish artifacts, or influence the
result of a protected check. Dependabot should still propose updates, but those
updates need deterministic review gates before they land.

The repository already pins third-party actions to full commit SHAs. That is the
right baseline, but it needs supporting policy so updates stay reviewable:

1. reviewers need to know which actions are approved for use,
2. SHA pins need a human-readable upstream version comment,
3. `pull_request_target` workflows must not checkout or execute untrusted PR
   head code, and
4. the policy check itself must run read-only.

Dependabot supports delaying version updates with `cooldown`, but security
updates bypass cooldown. Dependabot configuration also does not provide a CVSS
threshold that would express "only bypass delay for CVE 10" in this file.

## Decision

Dependabot will open GitHub Actions update PRs for the repository root. Those
PRs must pass a read-only `Workflow Policy` check before review.

The policy requires:

- every remote action reference to be listed in `.github/actions-allowlist.yml`,
- every remote action reference to be pinned to a full 40-character commit SHA,
- every SHA-pinned action line to include a same-line version comment such as
  `# v4`,
- GitHub Actions Dependabot updates to use the `github-actions` label and a
  14-day cooldown for version updates,
- `pull_request_target` workflows to avoid checkout and PR head execution
  patterns, and
- workflow policy files and tests to be owned in `CODEOWNERS`.

Branch protection should require the `Workflow Policy` status check and
CODEOWNERS review for changes to workflow policy files. That setting lives in
GitHub repository configuration rather than in this source tree.

## Consequences

- GitHub Actions updates are slower, but they are reviewable and deterministic.
- Adding a new third-party action requires an allowlist change in the same PR.
- Version comments make SHA-only diffs auditable by humans.
- The workflow policy check can run on untrusted PRs because it has read-only
  permissions and only executes repository tests.
- The existing Foreman workflow still mixes `pull_request`, self-hosted
  runners, and write scopes. Fixing that requires a workflow split and should be
  handled as a separate CI hardening task rather than hidden inside this policy
  PR.
