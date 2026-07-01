# OPA Policy — Input Schema

The `policy` package expects a single JSON input object with three top-level keys:
`findings`, `pkg`, and `config`.

> **Note:** The OPA adapter must emit `"pkg"` as the key — not `"package"` (reserved
> in Rego v1) and not `"packages"`. See #202 for the adapter bug that used `"packages"`.

## `input.findings` — array of scanner findings

Each element represents a single finding from a security scanner.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `severity` | string | yes | One of `"critical"`, `"high"`, `"medium"`, `"low"`, `"info"` |
| `category` | string | yes | Finding type: `"vulnerability"`, `"license"`, `"malware"` |
| `description` | string | yes | Human-readable description of the finding |
| `package_name` | string | yes | Name of the affected package |
| `version` | string | yes | Version of the affected package |
| `advisory_id` | string | yes | Advisory identifier (e.g. `CVE-2024-1234`, `MAL-2024-5678`) |
| `source_tool` | string | yes | Scanner that produced this finding (e.g. `osv-scanner`, `trivy`) |
| `license_id` | string | conditional | SPDX license identifier. Required when `category` is `"license"` |
| `link_type` | string | conditional | One of `"static"`, `"dynamic"`, `"unknown"`. Defaults to `"unknown"` upstream (`Finding.link_type`); no scanner in caliper currently detects real linkage type, so `"unknown"` is treated identically to `"static"` — the conservative default. Used by the copyleft-propagation rule |

## `input.pkg` — metadata about the package under evaluation

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Package name |
| `version` | string | yes | Package version |
| `ecosystem` | string | yes | Package ecosystem (e.g. `pypi`, `npm`) |
| `scope` | string | yes | Dependency scope: `"runtime"` or `"dev"` |
| `environment_sensitivity` | string | yes | Deployment context (e.g. `"internet-facing"`, `"internal"`) |
| `first_published_date` | string (RFC 3339) | yes | When the package was first published. Used by the package-age rule |
| `last_release_date` | string (RFC 3339) | conditional | When the package's most recent version was published. Used by the unmaintained-package rule; absent/null fails that rule open |
| `transitive_dep_count` | integer | yes | Number of transitive dependencies this package pulls in |

## `input.config` — policy configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `forbidden_licenses` | array of string | `[]` | SPDX license IDs that are not allowed |
| `max_transitive_deps` | integer | `200` | Maximum transitive dependency count before a warning fires |
| `min_package_age_days` | integer | `90` | Minimum age in days a package must have been published |
| `kev_ids` | array/set of string | `[]` | Operator-supplied CVE IDs known to be in CISA's Known Exploited Vulnerabilities catalog. No caliper-shipped default — the operator must supply this list |
| `max_days_since_release` | integer | `365` | Maximum days since `input.pkg.last_release_date` before the unmaintained-package rule warns |
| `copyleft_strong` | array of string | `[]` | Operator-supplied SPDX IDs for strong-copyleft licenses (e.g. `GPL-3.0-only`, `AGPL-3.0-only`). No caliper-shipped default |
| `copyleft_weak` | array of string | `[]` | Operator-supplied SPDX IDs for weak-copyleft licenses (e.g. `LGPL-3.0-only`, `MPL-2.0`). No caliper-shipped default |
| `rules_enabled` | object | (see below) | Per-rule toggle; see below |

### `input.config.rules_enabled`

Each key toggles a specific policy rule. Set to `false` to disable (or, for
`dev_scope_exemption`/`cisa_kev`, `true` to opt in).

| Key | Controls | Default |
|-----|----------|---------|
| `critical_vuln` | Critical/high deny + medium warn for vulnerabilities | `true` |
| `forbidden_license` | Forbidden license deny | `true` |
| `package_age` | Package age deny | `true` |
| `malicious_package` | MAL- prefix advisory deny | `true` |
| `transitive_count` | Transitive dependency count warn | `true` |
| `dev_scope_exemption` | Downgrades `critical_vuln`/`forbidden_license` deny to warn when `input.pkg.scope == "dev"`. A `MAL-` prefixed advisory (known-malicious package) always denies regardless of this setting. | `false` |
| `cisa_kev` | Denies vulnerability findings whose `advisory_id` is in `input.config.kev_ids` (CISA KEV catalog). Never downgraded by `dev_scope_exemption` — an actively-exploited CVE always denies. | `false` |
| `unmaintained_package` | Warns when `input.pkg.last_release_date` is older than `max_days_since_release`. Fails open (no warn) when `last_release_date` is absent or null. | `false` |
| `copyleft_propagation` | link_type-aware copyleft enforcement: denies a `copyleft_strong`-listed license when `link_type` is `"static"` or `"unknown"` (treated identically — the conservative default), warns when `"dynamic"`. Any `copyleft_weak`-listed license always warns, regardless of `link_type`. | `false` |

## Output Shape

The policy produces three fields:

| Field | Type | Description |
|-------|------|-------------|
| `deny` | set of string | Denial messages. Non-empty means the package is rejected |
| `warn` | set of string | Warning messages. Non-empty (with empty deny) means approve with constraints |
| `decision` | string | `"reject"` if deny is non-empty, `"approve_with_constraints"` if only warn is non-empty, `"approve"` otherwise |
