# Caliper Enterprise Architecture Assessment

**Date:** 2026-04-24
**Scope:** Self-hosted, business, and enterprise deployment readiness
**Codebase version:** v1.2.0 (commit aaf3200)

---

## 1. Current State Assessment

### What Is Enterprise-Ready Today

Caliper has a surprisingly solid foundation for a tool at its maturity stage. These areas are already enterprise-grade or close to it:

**Deterministic decision path.** Zero LLM in the core pipeline. Every verdict is reproducible given the same inputs. This is a hard requirement for SOC2/ISO 27001 audit trails and most enterprises will not adopt a security tool where the decision logic is non-deterministic.

**Fail-open contract.** Every subsystem has an explicit failure recovery path documented and implemented. No scanner failure blocks a build. This is the correct default for enterprise adoption -- security teams can roll out in `monitor` mode without developer pushback.

**Evidence chain.** SHA-256 sealed evidence bundles with append-only Parquet audit log. The `create_seal()` / `verify_seal()` chain in `src/caliper/core/seal.py` provides tamper-detection. This is the kind of artifact compliance auditors ask for.

**OPA policy engine.** Externalized policy in Rego (`policies/policy.rego`) with 6 rules. Policy-as-code is table stakes for enterprise adoption and OPA is the industry standard.

**Container-first distribution.** Multi-stage Dockerfile with SHA-256 verified binaries, SLSA provenance attestation via `actions/attest@v4`, and GHCR publishing. The build pipeline in `.github/workflows/build-container.yml` already produces attested images.

**SARIF output.** Standard SARIF v2.1.0 output (`src/caliper/core/sarif.py`) compatible with GitHub Security tab and any SARIF-consuming tool. This is the integration lingua franca.

**Structured logging.** Consistent use of `structlog` throughout. No `print()` statements. Correlation via `request_id`. DSN credential masking in `src/caliper/data/db.py:_safe_dsn()`.

**Plugin architecture.** 19 scanner plugins (+ OPA policy plugin) with auto-discovery, category filtering, and dependency ordering. The `ScannerPlugin` ABC in `src/caliper/core/plugin.py` is a clean extension point.

### What Is Not Enterprise-Ready

The sections below detail each gap. The summary:

| Dimension | Current State | Enterprise Requirement | Gap Severity |
|-----------|--------------|----------------------|--------------|
| Multi-tenancy | None -- single org, shared DB | Tenant-isolated data, policy, config | Critical |
| Scalability | Single-runner, in-process | Distributed scanning, queue-based | Critical |
| High availability | Single Postgres, local evidence | Redundant DB, object storage | High |
| Centralized management | Per-repo `.caliper.yaml` | Org-wide policy hierarchy with inheritance | High |
| RBAC | No auth layer | Role-based access, verdict override controls | High |
| Compliance | Evidence exists but no retention policy | Retention, export, deletion, immutability | Medium |
| Integration | PR comments only | Webhooks, SIEM, ticketing, chat | Medium |
| Deployment models | Container on self-hosted runner | Helm chart, operator, air-gapped | Medium |

---

## 2. Gap Analysis by Dimension

### 2.1 Multi-Tenancy

**Current state:** The database schema has no tenant isolation. All `review_requests`, `review_decisions`, `package_catalog`, and `scan_queue` rows share a single namespace. The `team` field on `ReviewRequest` is a free-form string used for labeling, not for access control or data isolation.

**What breaks:** When Company A and Company B share an caliper instance, their scan results, policy evaluations, and evidence bundles are co-mingled. A query against `package_catalog` returns packages from all tenants. The `bypass_records` table has no tenant scoping, so a bypass audit for one org includes another's data.

**Required changes:**

1. **Add `tenant_id` column to all tables.** Every table in `migrations/001_initial_schema.sql` and `migrations/002_package_catalog.sql` needs a `tenant_id UUID NOT NULL` column with a foreign key to a new `tenants` table. Row-level security (RLS) policies on PostgreSQL enforce isolation at the database level.

   Files affected:
   - `migrations/003_multi_tenancy.sql` (new) -- add `tenants` table, add `tenant_id` to all existing tables, create RLS policies
   - `src/caliper/data/db.py` -- `DecisionRepository.__init__()` accepts `tenant_id`, all queries include `WHERE tenant_id = %s`, connection sets `SET app.current_tenant = %s` for RLS
   - `src/caliper/data/catalog.py` -- `PackageCatalog.__init__()` accepts `tenant_id`, all queries scoped
   - `src/caliper/core/config.py` -- `CaliperSettings` gains `tenant_id: str | None = None`
   - `src/caliper/core/pipeline.py` -- `ReviewPipeline` passes `tenant_id` through to all data-tier calls

2. **Evidence isolation.** `EvidenceStore` in `src/caliper/data/evidence.py` currently writes to `<root>/<run_id>/`. For multi-tenancy, the layout becomes `<root>/<tenant_id>/<run_id>/`. The path traversal guard already prevents escaping the root, but it must also prevent cross-tenant access.

3. **Policy isolation.** Each tenant needs its own OPA policy bundle. `OpaEvaluator` in `src/caliper/core/policy.py` currently reads from a single `opa_policy_path`. For multi-tenancy, this becomes `<policy_root>/<tenant_id>/policy.rego` with a fallback to a global default policy.

**Recommended approach:** Start with schema-level tenant isolation (not separate databases). PostgreSQL RLS provides strong isolation without operational complexity. Separate databases per tenant is only warranted for regulatory requirements (FedRAMP, data residency).

### 2.2 Scalability

**Current state:** Scanning is in-process via `ThreadPoolExecutor` in `src/caliper/core/orchestrator.py`. The `ScanOrchestrator` runs all scanners in the same process as the pipeline. The pipeline processes packages sequentially in a `for req in requests` loop in `src/caliper/core/pipeline.py:165`. The `scan_queue` table exists in `migrations/002_package_catalog.sql` but there is no worker that consumes it.

**What breaks at 100 repos:** Scanner binary execution (syft, trivy, osv-scanner, gitleaks, semgrep) is CPU and I/O intensive. Running 19 plugins in-process for 100 concurrent PRs on a single runner will exhaust CPU, memory, and subprocess limits. The 300s pipeline timeout (`config.py:69`) means at most ~12 concurrent evaluations per runner before queueing.

**What breaks at 1000 repos:** The single PostgreSQL instance becomes a bottleneck for write throughput. Evidence storage on local disk runs out of space. The Parquet audit log (`src/caliper/data/parquet_writer.py`) does append-only writes to a single file, which becomes a contention point and eventually a multi-GB file that is slow to read.

**Required changes:**

1. **Extract scanning to a worker model.**

   Architecture: `API/CLI -> Message Queue -> Scanner Workers -> Results DB`

   - New module: `src/caliper/worker/` -- a separate process that pulls from `scan_queue`, runs scanners, writes results back to DB and evidence store
   - `src/caliper/core/orchestrator.py` gains an `AsyncScanOrchestrator` variant that submits to the queue and polls for completion instead of running in-process
   - Queue backend: Redis Streams or PostgreSQL `LISTEN/NOTIFY` + `scan_queue` table (already exists). Redis is preferred for throughput; Postgres queue is acceptable for <500 repos
   - Worker concurrency: each worker handles one scan at a time (scanner binaries are not safe to run concurrently on the same filesystem)

2. **Partition the Parquet audit log.**

   - `src/caliper/data/parquet_writer.py:append_decisions()` currently writes to a single `decisions.parquet`. Change to date-partitioned files: `decisions/year=2026/month=04/day=24/<run_id>.parquet`
   - This enables time-range queries without reading the full history and allows parallel writes from multiple workers

3. **Object storage for evidence.**

   - `src/caliper/data/evidence.py:EvidenceStore` needs an S3-compatible backend alongside the filesystem backend
   - New class: `S3EvidenceStore` implementing the same interface, writing to `s3://<bucket>/<tenant_id>/<run_id>/`
   - Selection via `CaliperSettings.evidence_backend: str = "filesystem"` (filesystem | s3)
   - S3 provides durability, horizontal scalability, and lifecycle policies for retention

4. **Connection pooling for high concurrency.**

   - `src/caliper/data/db.py:DecisionRepository` currently creates a pool with `min_size=1, max_size=10`. For distributed workers, use PgBouncer or a shared pool configuration
   - Add `db_pool_min: int = 1` and `db_pool_max: int = 10` to `CaliperSettings`

### 2.3 High Availability

**Current state:** Single PostgreSQL instance (`docker-compose.yml`), local filesystem evidence storage, single-runner GitHub Actions workflow.

**Single points of failure:**

| Component | SPOF? | Impact of failure |
|-----------|-------|-------------------|
| PostgreSQL | Yes | Pipeline falls back to `NullRepository` -- scans run but decisions are not persisted |
| Evidence filesystem | Yes | Evidence not written, seals not created -- pipeline continues but audit trail has gaps |
| OPA binary | Yes | Policy eval degrades to `needs_review` -- false-positive reviews |
| Scanner binaries | Partial | Individual scanner failure is handled; if all fail, no findings are produced |
| GitHub Actions runner | Yes | No PR reviews posted until runner recovers |

For the `NullRepository` fallback and the DB-free `caliper review` command,
see README.md's "Running without a database (scanner-only mode)" section.

**Required changes:**

1. **PostgreSQL HA.** Standard Postgres HA: primary + streaming replica with automatic failover (Patroni, or managed Postgres like RDS/CloudSQL). No code changes needed -- `db_dsn` points to the primary, failover is transparent.

2. **Evidence on object storage.** Addressed in 2.2 above. S3/GCS/MinIO provides built-in durability and replication.

3. **Multiple runners.** The `foreman.yml` workflow uses `runs-on: self-hosted`. For HA, use a runner group with multiple runners and a shared caliper container image. No code changes -- this is infrastructure configuration.

4. **Health check endpoint.** The CLI has `check-health` (`src/caliper/cli/main.py`) which probes scanner binaries and DB connectivity. For a deployed service, expose this as an HTTP endpoint via the agent module or a new lightweight health server.

### 2.4 Centralized Policy Management

**Current state:** Policy is managed in two places:

1. OPA policy in `policies/policy.rego` -- baked into the container image
2. Per-repo config in `.caliper.yaml` -- managed by each repo's maintainers

`load_merged_config()` in `src/caliper/core/repo_config.py:41` supports root + package-level config merging, but there is no org-level or team-level config hierarchy.

**What breaks at 500 repos:** Each repo has its own `.caliper.yaml` with its own `thresholds`, `plugins.enabled`, and `plugins.disabled`. When the security team wants to enforce a new policy (e.g., block all packages with critical vulns), they must update 500 files. Config drift is inevitable.

**Required changes:**

1. **Three-tier config hierarchy: org -> team -> repo.**

   ```
   Org policy (enforced, cannot be overridden)
     -> Team policy (defaults, can be tightened by repo)
       -> Repo config (.caliper.yaml, can only disable non-mandatory plugins)
   ```

   - New table: `org_policies` with `tenant_id`, `policy_rego TEXT`, `config_yaml TEXT`, `updated_at`, `updated_by`
   - New table: `team_policies` with `tenant_id`, `team_name`, `config_yaml TEXT`, inheriting from org
   - `src/caliper/core/repo_config.py` gains `load_hierarchical_config(tenant_id, team, repo_path)` that merges org -> team -> repo with precedence rules
   - Org-level policy can mark plugins as `mandatory` (cannot be disabled at repo level) or `forbidden` (cannot be enabled)

2. **Policy versioning and rollback.**

   - `org_policies` table includes `version INT`, `previous_version_id UUID`
   - `OpaEvaluator` logs `policy_bundle_version` (already exists in `PolicyEvaluation.policy_bundle_version`) -- extend to include org policy version

3. **Policy distribution.**

   - When the pipeline starts, it fetches the current org policy from the DB (or a policy server) rather than reading from the local filesystem
   - `src/caliper/core/policy.py:OpaEvaluator.__init__()` gains an alternative constructor `from_db(tenant_id, pool)` that loads policy from the database
   - Local filesystem policy remains as fallback for air-gapped deployments

### 2.5 RBAC (Role-Based Access Control)

**Current state:** No authentication or authorization layer. The `bypass_records` table in `migrations/001_initial_schema.sql` has an `invoked_by` free-text field but no identity verification. The `OperatingMode` (monitor/advise) is set globally via `CALIPER_OPERATING_MODE` -- there is no per-user or per-role control.

**Required changes:**

1. **Define roles.**

   | Role | Permissions |
   |------|------------|
   | `viewer` | Read scan results, view decisions, view evidence |
   | `developer` | All viewer permissions + trigger manual scans |
   | `team_lead` | All developer permissions + override verdicts (with bypass record) |
   | `security_admin` | All team_lead permissions + manage org/team policies, manage plugins |
   | `tenant_admin` | All security_admin permissions + manage users, manage tenant config |

2. **Implementation approach.**

   - Do NOT build a custom auth system. Integrate with existing identity providers via OIDC/SAML
   - New module: `src/caliper/core/auth.py` -- `AuthContext` dataclass with `user_id`, `tenant_id`, `roles: list[str]`
   - `ReviewPipeline` and `PackageCatalog` accept `AuthContext` and check permissions before mutations
   - The agent module (`src/caliper/agent/`) already has `FOREMAN_GITHUB_TOKEN` -- extend to map GitHub identities to caliper roles
   - Verdict overrides: `bypass_records.invoked_by` becomes a verified `user_id` from `AuthContext`, not a free-text string

3. **Audit trail for access.**

   - New table: `access_log` with `user_id`, `tenant_id`, `action`, `resource`, `timestamp`
   - All policy changes, verdict overrides, and config modifications are logged

### 2.6 Compliance

**Current state strengths:**
- SHA-256 evidence chain with tamper detection (`src/caliper/core/seal.py`)
- Append-only Parquet audit log (`src/caliper/data/parquet_writer.py`)
- Structured logging with correlation IDs
- All decisions persisted with full provenance

**Gaps for SOC2 / ISO 27001 / FedRAMP:**

1. **Retention policy.** No mechanism to enforce data retention periods or auto-delete expired records. Evidence accumulates forever.

   - Add `retention_days: int = 365` to `CaliperSettings`
   - New CLI command: `caliper admin purge --older-than 365d` that deletes evidence and DB records older than the threshold
   - For FedRAMP: evidence must be retained for a minimum period AND deletable after the maximum period. Both bounds must be configurable.

2. **Immutability enforcement.** Evidence files are written atomically but nothing prevents deletion or modification after the fact on a local filesystem.

   - S3 object lock (WORM) provides immutability guarantees
   - For on-prem: evidence directory should be on a write-once mount or use filesystem-level immutability (e.g., `chattr +i`)

3. **Data export.** No bulk export capability for compliance audits.

   - New CLI command: `caliper admin export --tenant <id> --from <date> --to <date> --format json|csv|parquet`
   - Export includes: decisions, findings, policy evaluations, bypass records, evidence manifests

4. **Encryption at rest.** No encryption of evidence files or database fields.

   - Database: use Postgres TDE or volume-level encryption (this is infrastructure, not code)
   - Evidence: S3 SSE-S3 or SSE-KMS for object storage; for filesystem, use LUKS or equivalent
   - `CaliperSettings` gains `evidence_encryption: bool = False` and `evidence_kms_key: str | None = None`

5. **SOC2 specific:** Type II requires evidence of controls operating over time. The existing Parquet audit log provides this for scan decisions. Missing: evidence of policy enforcement continuity (did the policy change? when? who approved it?).

### 2.7 Integration

**Current state:** PR comments via GitHub API (in `foreman.yml` workflow). SARIF upload to GitHub Security tab. Copilot handoff comment. No webhooks, no SIEM integration, no ticketing integration.

**Required integrations for enterprise:**

1. **Webhook notifications.** Post-decision webhook for arbitrary consumers.

   - New module: `src/caliper/data/webhook.py` -- `WebhookDispatcher` that POSTs decision payloads to configured URLs
   - `CaliperSettings` gains `webhook_urls: list[str] = []` and `webhook_secret: SecretStr | None = None` (HMAC signing)
   - Called from `ReviewPipeline` after `assemble_decision()` -- fail-open, non-blocking

2. **SIEM export.** Security teams need findings in their SIEM (Splunk, Elastic, Sentinel).

   - Structured log output is already compatible with log-based SIEM ingestion (structlog JSON)
   - For direct integration: SARIF output can be forwarded to SIEM via the webhook
   - For high-volume: Parquet files can be ingested into Splunk via S3-based inputs or Elastic Filebeat

3. **Ticketing (Jira, ServiceNow).** Auto-create tickets for `reject` or `needs_review` verdicts.

   - New module: `src/caliper/data/ticketing.py` -- `TicketingAdapter` with pluggable backends (Jira REST API, ServiceNow API)
   - `CaliperSettings` gains `ticketing_enabled: bool = False`, `ticketing_provider: str | None = None`, `ticketing_url: str | None = None`, `ticketing_api_key: SecretStr | None = None`
   - Ticket creation is fail-open and idempotent (check if ticket already exists for this `decision_id`)

4. **Chat (Slack, Teams).** Notify channels on blocked PRs.

   - New module: `src/caliper/data/notifiers.py` -- `SlackNotifier`, `TeamsNotifier` using incoming webhook URLs
   - Simpler than ticketing -- just POST a formatted message
   - `CaliperSettings` gains `slack_webhook_url: str | None = None`, `teams_webhook_url: str | None = None`

5. **PagerDuty.** Alert on-call when critical vulnerabilities are found in production dependencies.

   - Triggered when `reject` verdict fires on a package that is in the `package_catalog` with `status = 'active'` and has consumers in production repos
   - New module: `src/caliper/data/alerting.py` -- `PagerDutyAdapter` using Events API v2

### 2.8 Deployment Models

**Current state:** Single Dockerfile, single `docker-compose.yml` with Postgres. GitHub Actions workflow for CI integration. No Helm chart, no Kubernetes operator, no air-gapped support.

**Required for each deployment model:**

#### Self-Hosted On-Prem

- **Helm chart.** Package caliper as a Helm chart with: caliper worker deployment, PostgreSQL StatefulSet (or external DB reference), PersistentVolumeClaim for evidence, ConfigMap for OPA policies, Secret for credentials.
  - New directory: `deploy/helm/caliper/` with `Chart.yaml`, `values.yaml`, templates for Deployment, Service, ConfigMap, Secret, PVC, ServiceAccount
  - `values.yaml` exposes all `CaliperSettings` fields as Helm values
  - ClamAV signature updates via init-container or sidecar

- **Air-gapped support.** Scanner binaries and vulnerability databases must work offline.
  - Trivy: `TRIVY_OFFLINE_SCAN=true` + pre-loaded DB
  - OSV-Scanner: local mirror of OSV database
  - ClamAV: pre-loaded signature database
  - `CaliperSettings` gains `offline_mode: bool = False`
  - `src/caliper/data/pypi.py:PyPIClient` returns `{"available": False}` in offline mode (already handles this gracefully)

#### Private Cloud (AWS/GCP/Azure)

- **Managed services substitution.** Replace self-managed Postgres with RDS/CloudSQL/Azure Database. Replace filesystem evidence with S3/GCS/Azure Blob. Replace self-hosted runners with managed compute (ECS/Cloud Run/ACI).
  - No code changes needed for DB (DSN-based)
  - Evidence store needs S3 backend (see 2.2)
  - Worker deployment via ECS task definition or Cloud Run service

- **Terraform/Pulumi modules.** Infrastructure-as-code for the full stack.
  - New directory: `deploy/terraform/` with modules for VPC, RDS, S3, ECS, IAM

#### Hybrid

- **Split-plane architecture.** Control plane (policy, config, dashboard) in cloud. Data plane (scanning) on-prem.
  - Worker runs on-prem, connects to cloud-hosted Postgres and S3 via VPN/PrivateLink
  - Policy is pulled from cloud at scan time
  - Evidence can be written to either local or cloud storage based on data residency requirements
  - `CaliperSettings` gains `control_plane_url: str | None = None` for API-based config fetching

---

## 3. Recommended Architecture Evolution

### Phase 1: Foundation (Weeks 1-4)

**Goal:** Multi-tenancy and centralized config without breaking existing single-tenant usage.

| Task | Files | Effort |
|------|-------|--------|
| Add `tenant_id` to all DB tables with RLS | `migrations/003_multi_tenancy.sql` (new) | 3 days |
| Thread `tenant_id` through `DecisionRepository` | `src/caliper/data/db.py` | 2 days |
| Thread `tenant_id` through `PackageCatalog` | `src/caliper/data/catalog.py` | 1 day |
| Add `tenant_id` to `CaliperSettings` | `src/caliper/core/config.py` | 0.5 days |
| Pass `tenant_id` in pipeline | `src/caliper/core/pipeline.py` | 1 day |
| Tenant-scoped evidence paths | `src/caliper/data/evidence.py` | 1 day |
| Org/team policy tables + hierarchy | `migrations/003_multi_tenancy.sql`, `src/caliper/core/repo_config.py` | 3 days |
| Backward compat: default tenant for single-tenant mode | All above files | 1 day |
| Tests | `tests/unit/test_db.py`, `tests/unit/test_catalog.py`, `tests/unit/test_evidence.py`, `tests/unit/test_pipeline.py` (existing + new) | 3 days |

**Design constraint:** When `CALIPER_TENANT_ID` is not set, the system operates in single-tenant mode with a default tenant UUID. All existing behavior is preserved. Zero breaking changes for current users.

### Phase 2: Scalability (Weeks 5-8)

**Goal:** Distributed scanning and durable storage.

| Task | Files | Effort |
|------|-------|--------|
| Scanner worker process | `src/caliper/worker/__init__.py`, `src/caliper/worker/scanner_worker.py` (new) | 5 days |
| Queue consumer (Postgres-based, upgradeable to Redis) | `src/caliper/worker/queue.py` (new) | 3 days |
| `AsyncScanOrchestrator` (queue-based variant) | `src/caliper/core/orchestrator.py` (extend) | 2 days |
| S3 evidence backend | `src/caliper/data/evidence_s3.py` (new), `src/caliper/data/evidence.py` (factory) | 3 days |
| Partitioned Parquet writes | `src/caliper/data/parquet_writer.py` | 2 days |
| Config additions | `src/caliper/core/config.py` -- `evidence_backend`, `queue_backend`, `redis_url`, S3 settings | 1 day |
| Worker Dockerfile | `Dockerfile.worker` (new) | 1 day |
| Docker Compose with worker | `docker-compose.yml` (extend), `docker-compose.prod.yml` (new) | 1 day |
| Tests | New test files for worker, queue, S3 evidence | 4 days |

**Design constraint:** In-process scanning remains the default. Queue-based scanning is opt-in via `CALIPER_SCAN_MODE=distributed`. This allows gradual migration.

### Phase 3: Enterprise Features (Weeks 9-14)

**Goal:** RBAC, compliance, integrations.

| Task | Files | Effort |
|------|-------|--------|
| Auth context model | `src/caliper/core/auth.py` (new) | 2 days |
| OIDC integration | `src/caliper/core/auth_oidc.py` (new) | 3 days |
| Role enforcement on pipeline | `src/caliper/core/pipeline.py`, `src/caliper/data/db.py` | 2 days |
| Bypass record identity verification | `src/caliper/data/db.py:save_bypass()` | 1 day |
| Access audit log | `migrations/004_rbac.sql` (new), `src/caliper/data/access_log.py` (new) | 2 days |
| Webhook dispatcher | `src/caliper/data/webhook.py` (new) | 2 days |
| Slack/Teams notifiers | `src/caliper/data/notifiers.py` (new) | 2 days |
| Jira/ServiceNow adapter | `src/caliper/data/ticketing.py` (new) | 3 days |
| Data retention + purge CLI | `src/caliper/cli/admin.py` (new), `src/caliper/core/retention.py` (new) | 3 days |
| Data export CLI | `src/caliper/cli/admin.py` (extend) | 2 days |
| Config additions | `src/caliper/core/config.py` -- all integration settings | 1 day |
| Tests | New test files for all above | 5 days |

### Phase 4: Deployment Packaging (Weeks 15-18)

**Goal:** Production-ready deployment for all models.

| Task | Files | Effort |
|------|-------|--------|
| Helm chart | `deploy/helm/caliper/` (new directory tree) | 5 days |
| Terraform AWS module | `deploy/terraform/aws/` (new) | 5 days |
| Air-gapped mode | `src/caliper/core/config.py`, scanner modules, `Dockerfile` | 3 days |
| Health check HTTP endpoint | `src/caliper/agent/health.py` (new) or `src/caliper/cli/main.py` (extend) | 1 day |
| Horizontal pod autoscaler config | `deploy/helm/caliper/templates/hpa.yaml` | 1 day |
| Documentation | `docs/deployment/` (new directory) | 3 days |

---

## 4. Specific Module Changes Summary

### Existing files that need modification

| File | Changes |
|------|---------|
| `src/caliper/core/config.py` | Add: `tenant_id`, `evidence_backend`, `queue_backend`, `redis_url`, `s3_*` settings, `webhook_urls`, `slack_webhook_url`, `teams_webhook_url`, `ticketing_*` settings, `retention_days`, `offline_mode`, `db_pool_min`, `db_pool_max`, `scan_mode` |
| `src/caliper/core/pipeline.py` | Thread `tenant_id` and `AuthContext` through all calls. Add webhook dispatch after decision assembly. Support queue-based scan mode. |
| `src/caliper/core/orchestrator.py` | Add `AsyncScanOrchestrator` class for queue-based scanning alongside existing `ScanOrchestrator` |
| `src/caliper/core/repo_config.py` | Add `load_hierarchical_config()` for org -> team -> repo merging. Add `mandatory_plugins` and `forbidden_plugins` enforcement. |
| `src/caliper/core/policy.py` | Add `OpaEvaluator.from_db()` constructor for DB-stored policies. Add tenant-scoped policy loading. |
| `src/caliper/data/db.py` | Add `tenant_id` to all queries. Add `db_pool_min`/`db_pool_max` to pool config. Add RLS session variable setting. |
| `src/caliper/data/catalog.py` | Add `tenant_id` scoping to all queries. |
| `src/caliper/data/evidence.py` | Add tenant-scoped path layout. Add factory method to select filesystem vs S3 backend. |
| `src/caliper/data/parquet_writer.py` | Change to date-partitioned writes instead of single-file append. |
| `src/caliper/cli/main.py` | Add `admin` command group for purge and export. |
| `docker-compose.yml` | Add Redis service (optional), worker service, MinIO service (for local S3). |
| `.github/workflows/foreman.yml` | Add `CALIPER_TENANT_ID` env var. |
| `Dockerfile` | No changes needed for Phase 1. Worker Dockerfile added separately. |

### New files to create

| File | Purpose |
|------|---------|
| `migrations/003_multi_tenancy.sql` | Tenant table, tenant_id columns, RLS policies, org/team policy tables |
| `migrations/004_rbac.sql` | Roles table, access_log table, user_roles mapping |
| `src/caliper/worker/__init__.py` | Worker package |
| `src/caliper/worker/scanner_worker.py` | Queue consumer that runs scans |
| `src/caliper/worker/queue.py` | Queue abstraction (Postgres + Redis backends) |
| `src/caliper/core/auth.py` | `AuthContext` model, role definitions, permission checks |
| `src/caliper/core/auth_oidc.py` | OIDC token validation |
| `src/caliper/core/retention.py` | Retention policy enforcement logic |
| `src/caliper/data/evidence_s3.py` | S3-compatible evidence backend |
| `src/caliper/data/webhook.py` | Post-decision webhook dispatcher |
| `src/caliper/data/notifiers.py` | Slack/Teams notification adapters |
| `src/caliper/data/ticketing.py` | Jira/ServiceNow ticket creation |
| `src/caliper/data/alerting.py` | PagerDuty incident creation |
| `src/caliper/data/access_log.py` | Access audit logging |
| `src/caliper/cli/admin.py` | Admin CLI commands (purge, export, policy management) |
| `Dockerfile.worker` | Scanner worker container |
| `deploy/helm/caliper/` | Full Helm chart tree |
| `deploy/terraform/aws/` | AWS infrastructure module |

---

## 5. Priority Ordering

Ranked by: (a) how many enterprise prospects this unblocks, (b) how much existing architecture it builds on, (c) risk of getting it wrong if deferred.

1. **Multi-tenancy** -- foundational. Every other enterprise feature depends on tenant isolation. If you add RBAC or policy hierarchy without multi-tenancy, you have to retrofit tenant scoping later, which is a migration nightmare.

2. **Centralized policy management** -- the #1 feature request from security teams. Without it, adopting caliper at 50+ repos is an operational burden that kills adoption.

3. **S3/object storage evidence** -- prerequisite for compliance (immutability, retention) and scalability (multiple workers writing evidence). Also unblocks Helm/K8s deployment where local PVCs are not ideal for long-term storage.

4. **Distributed scanning** -- unblocks scale beyond a single runner. The `scan_queue` table already exists, which means the data model anticipated this. The worker is the missing piece.

5. **RBAC** -- required for any deployment where more than one team uses the system. Can be deferred if the first enterprise customers are single-team.

6. **Webhook/notification integrations** -- high value, low effort. Each adapter is a standalone module with no impact on the core pipeline. Ship incrementally.

7. **Compliance tooling** (retention, export, encryption) -- required for regulated industries. Can be delivered alongside or after RBAC.

8. **Helm chart and Terraform modules** -- packaging. Do this last because the deployment target stabilizes after the architecture changes above.

---

## 6. What NOT to Do

- **Do not rewrite the pipeline.** The current `ReviewPipeline` in `src/caliper/core/pipeline.py` is clean, linear, and well-tested. Enterprise features are additive (pass tenant_id, add webhook call, support queue mode). The pipeline structure stays the same.

- **Do not build a custom API server.** The agent module (`src/caliper/agent/`) already provides an HTTP surface via the Copilot SDK. For a management API, use a thin FastAPI or Litestar wrapper around the existing core modules. Do not duplicate logic.

- **Do not add an `enforce` operating mode yet.** The current `monitor` / `advise` modes are sufficient for enterprise rollout. An `enforce` mode (hard-block PRs) is a liability until RBAC and override workflows are in place. Ship RBAC first, then enforce.

- **Do not over-abstract the data layer.** The `RepositoryProtocol` in `src/caliper/data/db.py` and `NullRepository` fallback are the right level of abstraction. Adding a full ORM or repository pattern framework adds complexity without value.

- **Do not move away from OPA.** OPA is the right policy engine for this use case. It is enterprise-proven, supports hierarchical bundles, and has a large ecosystem. Do not replace it with a custom rules engine.
