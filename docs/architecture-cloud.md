# Caliper Cloud SaaS Architecture

Cloud deployment readiness assessment and migration plan for Caliper.

## 1. Current State Assessment

### What Is Cloud-Ready Today

**Stateless pipeline core.** `ReviewPipeline` (`src/caliper/core/pipeline.py`) is
stateless per call -- it accepts inputs, wires subsystems, returns
`list[ReviewDecision]`. No in-memory state survives between invocations. This is
the single most important property for cloud deployment: each pipeline invocation
can run on a different machine without coordination.

**Fail-open contract.** Every subsystem failure degrades gracefully
(ARCHITECTURE.md Section 13). Scanner timeouts produce `ScanResult.skipped`,
OPA failures produce `needs_review`, DB failures fall back to `NullRepository`.
This means a cloud worker that loses its backing store mid-scan will not produce
a false-positive build failure -- it will degrade to manual review.

**Timeout budget already defined.** All timeout values are centralized in
`CaliperSettings` (`src/caliper/core/config.py:65-71`): scanner=60s, combined=180s,
OPA=10s, pipeline=300s. These translate directly to Lambda/Cloud Run timeout
configuration without guesswork.

**Container image production-ready.** The Dockerfile is a hardened multi-stage
build with SHA-256 verified binaries, SLSA provenance attestation
(`.github/workflows/build-container.yml`), and all 19 scanner plugins baked in.
This image can deploy to any container runtime (ECS Fargate, Cloud Run, EKS)
without modification.

**SARIF output for GitHub integration.** `core/sarif.py` produces SARIF v2.1.0
compatible with GitHub's Security tab. A cloud service can upload SARIF via the
GitHub Code Scanning API without custom formatting.

**Database fallback pattern.** The `NullRepository` pattern
(`src/caliper/data/db.py:412`) means the pipeline can run without a database. This
is useful during the migration: cloud workers can start with no DB and add
persistence incrementally. See README.md's "Running without a database
(scanner-only mode)" section for the CLI-level detail (`NullRepository`
trigger conditions, the DB-free `caliper review` command).

**Pydantic-typed boundaries everywhere.** Every data exchange uses typed Pydantic
models (`src/caliper/core/models.py`). These serialize to JSON natively, which
means queue messages, API responses, and webhook payloads all have
machine-validated schemas from day one.

### What Is NOT Cloud-Ready

**Local filesystem evidence.** `EvidenceStore` (`src/caliper/data/evidence.py`)
writes to local disk via `os.rename`. The `root_path` is a local directory
(default `./evidence`). Cloud workers are ephemeral -- local disk is lost on
termination.

**Local Parquet audit log.** `append_decisions()`
(`src/caliper/data/parquet_writer.py`) reads the full existing Parquet file, appends
rows, and overwrites. This is fundamentally incompatible with concurrent cloud
workers -- two workers appending simultaneously will produce data loss.

**Seal chain assumes local directory scan.** `find_previous_seal_hash()`
(`src/caliper/core/seal.py`) walks the local filesystem to find prior `seal.json`
files. This requires all evidence to be on the same filesystem.

**Self-hosted runner assumption.** Both GitHub Actions workflows
(`.github/workflows/foreman.yml`, `build-container.yml`) use
`runs-on: self-hosted`. The foreman workflow expects the container image to be
locally available (`podman image exists caliper:latest`).

**Direct GitHub API calls.** The Foreman agent (`src/caliper/agent/main.py`)
posts comments and sets commit statuses using raw `httpx` calls with a
`GITHUB_TOKEN`. A cloud service needs GitHub App authentication (installation
tokens, JWT signing) instead of PATs.

**Single-process scanner parallelism.** `ScanOrchestrator`
(`src/caliper/core/orchestrator.py`) uses `ThreadPoolExecutor` within a single
process. For cloud-scale scanning, scanner execution should be distributable
across separate containers.

**No tenant isolation.** The pipeline scans whatever repository path it receives.
There is no concept of tenant ID, organization boundary, or resource quota.
Scanner plugins shell out to binaries (Syft, Trivy, Semgrep) that have full
filesystem access within the container.

**No usage metering.** No scan-count tracking, no per-org billing signals, no
rate limiting. `CaliperSettings` has no fields for tenant context.

**Hardcoded PostgreSQL.** `DecisionRepository` (`src/caliper/data/db.py`) uses
`psycopg3` directly. The catalog (`src/caliper/data/catalog.py`) requires
pgvector. There is no storage abstraction layer.


## 2. Cloud Architecture Proposal

### Target: Event-Driven, Stateless Workers

```
GitHub App (webhook receiver)
        |
        v
   API Gateway (REST)
        |
        v
   Webhook Handler (Lambda/Cloud Function)
        |
        +---> Validate webhook signature
        +---> Extract PR metadata + diff URL
        +---> Enqueue scan job
        |
        v
   Job Queue (SQS / Cloud Tasks / Pub/Sub)
        |
        v
   Scan Worker (Cloud Run / ECS Fargate)
        |
        +---> Pull repo snapshot (shallow clone)
        +---> Run ReviewPipeline / PluginRegistry
        +---> Write evidence to object storage
        +---> Write decision to PostgreSQL
        +---> Post results via GitHub App API
        +---> Emit usage event to metering stream
        |
        v
   Results (GitHub PR comment + SARIF upload + dashboard)
```

### Key Design Decisions

**GitHub App, not GitHub Actions.** The current model requires a self-hosted
runner per customer. A GitHub App receives webhooks for `pull_request` events
across all installations. One webhook handler serves all tenants.

**Container-per-scan, not Lambda.** The scanner container is 800MB+ with 6 Go
binaries, Semgrep, ScanCode, ClamAV, and Python packages. Lambda's 10GB
uncompressed limit fits, but cold start time for this image would be 15-30
seconds. Cloud Run or ECS Fargate with min-instances=1 keeps warm containers and
matches the 300s pipeline timeout naturally.

**Object storage for evidence, not local filesystem.** Evidence artifacts
(decision JSON, memos, SBOMs, SARIF) go to S3/GCS/R2. The Parquet audit log
becomes a partitioned dataset in object storage, queryable by DuckDB or Athena.

**PostgreSQL stays.** The existing schema (5 tables + catalog + pgvector) is
well-designed. For multi-tenant cloud, add a `tenant_id` column and use
row-level security. Managed PostgreSQL (RDS, Cloud SQL, Neon) with pgvector
extension.


## 3. Service Decomposition

### What Stays Monolithic (the scan worker)

The entire scan pipeline runs as a single unit of work per PR event. Breaking
scanners into separate microservices adds latency (network hops per scanner),
complexity (partial failure coordination), and infrastructure cost (6+ container
types instead of 1) with no proportional benefit. The current
`ScanOrchestrator.run()` parallelism within a single container is correct.

**One container image. One scan job. One result.**

The scan worker IS the current `caliper:latest` container with a thin HTTP/queue
adapter replacing the CLI entry point.

### What Becomes a Separate Service

| Service | Responsibility | Runtime |
|---------|---------------|---------|
| **Webhook Receiver** | Validate GitHub App webhooks, enqueue scan jobs | Lambda / Cloud Function |
| **Scan Worker** | Run the full pipeline per PR event | Cloud Run / ECS Fargate |
| **API Server** | REST API for dashboard, org settings, scan history | Cloud Run / ECS |
| **Background Catalog Worker** | Process `scan_queue`, refresh stale catalog entries | Cloud Run (scheduled) |
| **Metering Collector** | Aggregate usage events for billing | Kinesis / Pub/Sub + Lambda |

### New Modules Required

| Module | Location | Purpose |
|--------|----------|---------|
| `src/caliper/cloud/webhook.py` | New | GitHub App webhook validation, event parsing |
| `src/caliper/cloud/worker.py` | New | Queue consumer, invokes `ReviewPipeline` |
| `src/caliper/cloud/github_app.py` | New | GitHub App JWT signing, installation token management |
| `src/caliper/cloud/tenant.py` | New | Tenant context, org settings, rate limiting |
| `src/caliper/cloud/metering.py` | New | Usage event emission (scans, findings, duration) |
| `src/caliper/data/object_store.py` | New | S3/GCS/R2 abstraction for evidence storage |
| `src/caliper/api/` | New | REST API presentation tier (FastAPI) |


## 4. Data Architecture

### Evidence Storage: Local Filesystem to Object Storage

**Current:** `EvidenceStore` writes to `<evidence_path>/<run_id>/<pkg>/decision.json`.

**Cloud:** Replace with an object storage adapter behind the same interface.

```
Bucket: caliper-evidence-{region}
Prefix: {tenant_id}/{run_id}/{artifact_name}

Examples:
  org-acme/abc123def012-202604241530/requests-2.32.0/decision.json
  org-acme/abc123def012-202604241530/requests-2.32.0/memo.md
  org-acme/abc123def012-202604241530/seal.json
```

**Implementation:** Create `src/caliper/data/object_store.py` implementing the same
`store()` / `store_file()` / `get_path()` / `list_artifacts()` interface as
`EvidenceStore`. The pipeline receives an `EvidenceStoreProtocol` (new protocol
in `src/caliper/data/evidence.py`) and works identically with either backend.

```python
# src/caliper/data/evidence.py — add protocol
class EvidenceStoreProtocol(Protocol):
    def store(self, key: str, artifact_name: str, content: bytes | str) -> str: ...
    def store_file(self, key: str, artifact_name: str, source_path: Path) -> str: ...
    def get_path(self, key: str, artifact_name: str) -> str: ...
    def list_artifacts(self, key: str) -> list[str]: ...
```

```python
# src/caliper/data/object_store.py — new module
class S3EvidenceStore:
    """Evidence storage backed by S3-compatible object storage."""
    def __init__(self, bucket: str, prefix: str, client: S3Client) -> None: ...
    def store(self, key: str, artifact_name: str, content: bytes | str) -> str: ...
```

### Parquet Audit Log: Local File to Partitioned Dataset

**Current:** Single `decisions.parquet` file, read-modify-write on every run.

**Cloud:** Write one Parquet file per run, partitioned by tenant and date:

```
s3://caliper-audit-{region}/
  tenant_id=org-acme/
    year=2026/
      month=04/
        day=24/
          run-abc123def012-202604241530.parquet
```

Query with Athena/DuckDB:
```sql
SELECT * FROM caliper_audit
WHERE tenant_id = 'org-acme'
  AND year = 2026 AND month = 4
  AND decision = 'reject'
ORDER BY timestamp DESC
```

**Implementation change in `src/caliper/data/parquet_writer.py`:**
- `append_decisions()` writes a new Parquet file per run (no read-modify-write)
- File goes to object storage via `S3EvidenceStore`
- The read-modify-write append pattern is removed entirely

### Seal Chain: Local Walk to Object Storage Index

**Current:** `find_previous_seal_hash()` scans local directories for `seal.json`
files.

**Cloud:** Store a seal index in PostgreSQL:

```sql
CREATE TABLE seal_index (
    tenant_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    seal_hash TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    previous_seal_hash TEXT,
    commit_sha TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (tenant_id, run_id)
);
CREATE INDEX idx_seal_latest ON seal_index (tenant_id, created_at DESC);
```

`find_previous_seal_hash()` becomes a DB query:
```sql
SELECT seal_hash FROM seal_index
WHERE tenant_id = %s
ORDER BY created_at DESC LIMIT 1
```

### Database: Multi-Tenant Schema

Add `tenant_id` to every table:

```sql
-- Migration 003: multi-tenancy
ALTER TABLE review_requests ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE scan_results ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE policy_evaluations ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE review_decisions ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE package_catalog ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE repo_inventory ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE repo_packages ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE scan_queue ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';

-- Row-level security
ALTER TABLE review_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON review_requests
    USING (tenant_id = current_setting('app.tenant_id'));
-- Repeat for all tables

-- New tables
CREATE TABLE tenants (
    tenant_id TEXT PRIMARY KEY,
    github_installation_id BIGINT UNIQUE,
    org_name TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'team', 'enterprise')),
    scan_quota_monthly INT NOT NULL DEFAULT 100,
    scans_used_this_month INT NOT NULL DEFAULT 0,
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE scan_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    run_id TEXT NOT NULL,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('dependency', 'review')),
    plugin_count INT NOT NULL DEFAULT 0,
    finding_count INT NOT NULL DEFAULT 0,
    pipeline_duration_seconds FLOAT,
    billable BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_scan_events_billing ON scan_events (tenant_id, created_at)
    WHERE billable = true;
```


## 5. GitHub App Model

### Current: Self-Hosted Runner

```
Developer opens PR
  -> GitHub Actions triggers foreman.yml
  -> Self-hosted runner pulls code
  -> Runner executes caliper CLI
  -> Runner posts PR comment via GITHUB_TOKEN
```

### Cloud: GitHub App Webhook

```
Developer opens PR
  -> GitHub sends webhook to caliper cloud
  -> Webhook handler validates signature
  -> Handler enqueues scan job with PR metadata
  -> Worker clones repo at PR HEAD (shallow, read-only)
  -> Worker runs pipeline
  -> Worker posts comment via GitHub App installation token
  -> Worker uploads SARIF via Code Scanning API
```

### New Module: `src/caliper/cloud/github_app.py`

```python
class GitHubAppAuth:
    """GitHub App authentication — JWT signing and installation tokens."""

    def __init__(self, app_id: int, private_key: str) -> None: ...

    def generate_jwt(self) -> str:
        """Sign a JWT for the GitHub App (10-minute TTL)."""
        ...

    async def get_installation_token(self, installation_id: int) -> str:
        """Exchange JWT for a scoped installation token."""
        ...

    async def post_pr_comment(
        self, installation_id: int, repo: str, pr_number: int, body: str
    ) -> None: ...

    async def upload_sarif(
        self, installation_id: int, repo: str, commit_sha: str, sarif: dict
    ) -> None: ...
```

### Webhook Handler: `src/caliper/cloud/webhook.py`

```python
async def handle_webhook(request: Request) -> Response:
    """Process GitHub App webhook — validate, parse, enqueue."""
    # 1. Verify webhook signature (HMAC-SHA256)
    # 2. Parse event type (pull_request.opened, pull_request.synchronize)
    # 3. Extract: repo, PR number, head SHA, installation_id
    # 4. Look up tenant by installation_id
    # 5. Check scan quota
    # 6. Enqueue scan job
    # 7. Return 202 Accepted
```

### Changes to Existing Files

**`src/caliper/agent/main.py`**: The `ForemanAgent` class currently uses raw
`httpx` calls with a `GITHUB_TOKEN`. Replace `_github_headers()`,
`_post_comment()`, and `_set_check_status()` to accept a `GitHubAppAuth`
instance. The agent's `run()` method signature gains an `installation_id`
parameter.

**`src/caliper/agent/config.py`**: `AgentSettings.github_token` becomes optional.
Add `github_app_id`, `github_app_private_key`, and `github_installation_id`
fields with the `FOREMAN_` prefix.

**`.github/workflows/foreman.yml`**: In the cloud model, this workflow is no
longer needed for cloud tenants. It remains available for self-hosted/hybrid
deployments where customers run their own runners.


## 6. Tenant Isolation and Sandboxing

### Threat Model

Caliper scans customer source code. A malicious repository could contain:
- Files designed to exploit scanner binaries (crafted JSON, deep nesting)
- Symlinks escaping the workspace
- `.caliper.yaml` with adversarial plugin config

### Isolation Architecture

**Container-per-scan.** Each scan runs in a fresh container with:
- Read-only filesystem mount for the cloned repository
- No network access during scanning (scanner binaries work offline after DB
  download; Trivy/OSV maintain local vulnerability DBs)
- CPU/memory limits per container (2 vCPU, 4GB RAM)
- 300-second hard timeout (matching `pipeline_timeout`)
- No persistent volumes -- ephemeral storage only

**Repository cloning in a separate step.** The webhook handler triggers a
shallow clone (`git clone --depth 1`) into ephemeral storage. The scan worker
receives a read-only volume mount. The clone step runs with network access; the
scan step runs without it.

```
[Clone Container]  --network=host-->  git clone --depth 1
        |
        v  (read-only volume)
[Scan Container]   --network=none-->  caliper review --repo-path /workspace
```

**OPA policy sandboxing.** OPA evaluates customer-defined policies in a sandboxed
subprocess with `--timeout`. The existing 10-second timeout
(`CaliperSettings.opa_timeout`) prevents denial-of-service via expensive Rego
queries.

**No tenant data cross-contamination.** Each container processes exactly one
tenant's scan. There is no shared filesystem between scans. The database uses
row-level security keyed by `tenant_id`.

### AWS Implementation

| Concern | Service | Configuration |
|---------|---------|--------------|
| Container isolation | ECS Fargate | `readonlyRootFilesystem: true`, `networkMode: none` for scan |
| Repo cloning | Lambda + EFS or S3 | Shallow clone to S3, presigned URL to worker |
| Secrets | AWS Secrets Manager | GitHub App private key, DB credentials |
| Scan timeout | ECS task timeout | `stopTimeout: 300` |
| Resource limits | Fargate task definition | `cpu: 2048, memory: 4096` |

### GCP Implementation

| Concern | Service | Configuration |
|---------|---------|--------------|
| Container isolation | Cloud Run jobs | `--no-cpu-throttling`, `--vpc-egress=none` for scan |
| Repo cloning | Cloud Build or Cloud Function | Clone to GCS, mount via FUSE |
| Secrets | Secret Manager | GitHub App private key, DB credentials |
| Scan timeout | Cloud Run max timeout | `--timeout=300s` |
| Resource limits | Cloud Run resource limits | `--cpu=2 --memory=4Gi` |


## 7. Queue-Based Processing

### Job Queue Schema

```json
{
  "job_id": "uuid",
  "tenant_id": "org-acme",
  "installation_id": 12345678,
  "repo_full_name": "acme/web-app",
  "pr_number": 42,
  "head_sha": "abc123def012",
  "base_sha": "def012abc345",
  "clone_url": "https://github.com/acme/web-app.git",
  "scan_type": "review",
  "plugins": ["all"],
  "enqueued_at": "2026-04-24T15:30:00Z",
  "priority": 0
}
```

### AWS: SQS + ECS Fargate

```
GitHub Webhook --> API Gateway --> Lambda (webhook handler)
                                      |
                                      v
                                  SQS Queue (scan-jobs)
                                      |
                                      v
                                  ECS Fargate Service (scan workers)
                                      |
                                      +---> S3 (evidence)
                                      +---> RDS PostgreSQL (decisions + catalog)
                                      +---> GitHub API (comments + SARIF)
                                      +---> Kinesis (metering events)
```

### GCP: Cloud Tasks + Cloud Run

```
GitHub Webhook --> Cloud Endpoints --> Cloud Function (webhook handler)
                                            |
                                            v
                                        Cloud Tasks Queue
                                            |
                                            v
                                        Cloud Run Job (scan workers)
                                            |
                                            +---> GCS (evidence)
                                            +---> Cloud SQL PostgreSQL (decisions + catalog)
                                            +---> GitHub API (comments + SARIF)
                                            +---> Pub/Sub (metering events)
```

### Dead Letter Queue

Failed scan jobs go to a DLQ after 3 retries. The DLQ consumer logs the failure,
updates the scan event as `failed`, and posts a "scan failed" comment on the PR
via the GitHub App.

### Priority Queue

Enterprise tenants get priority 10; team gets priority 5; free gets priority 0.
Workers pull highest-priority jobs first. Implemented via SQS message attributes
or Cloud Tasks priority.


## 8. Multi-Region

### Evidence Residency

Some customers require evidence artifacts to stay in a specific region (GDPR,
SOC2). Object storage buckets are region-scoped:

```
caliper-evidence-us-east-1    (US tenants)
caliper-evidence-eu-west-1    (EU tenants)
caliper-evidence-ap-southeast-1  (APAC tenants)
```

The `tenants` table stores `evidence_region`. The scan worker uses this to select
the correct bucket.

### Scan Locality

GitHub's webhook delivery is region-agnostic, but scan workers should run close
to the tenant's GitHub Enterprise Server (if applicable) to minimize clone
latency. For github.com customers, US East is optimal (GitHub's primary
datacenter).

### Database

PostgreSQL read replicas in each region for dashboard queries. Write primary in
US East. Cross-region replication lag is acceptable for audit data (eventual
consistency within seconds).

### Latency Implications

| Operation | Latency | Notes |
|-----------|---------|-------|
| Webhook receipt to job enqueue | <100ms | Lambda/Cloud Function in same region as API Gateway |
| Job dequeue to scan start | <5s | Warm container pool |
| Scan execution | 30-300s | Depends on repo size and plugin count |
| Result posting to GitHub | <2s | GitHub API from US East |
| Evidence write to S3/GCS | <1s | Same-region object storage |
| Total webhook-to-PR-comment | 35-310s | Dominated by scan execution time |


## 9. Billing and Metering

### Existing Signals

The pipeline already produces everything needed for usage tracking:

| Signal | Source | Location |
|--------|--------|----------|
| Scan count | Each `ReviewPipeline.evaluate()` call | `pipeline.py:82` |
| Plugin count | `PluginRegistry.run_all()` result length | `core/registry.py` |
| Finding count | `len(decision.findings)` | `core/models.py` |
| Pipeline duration | `decision.pipeline_duration_seconds` | `core/models.py` |
| Scanner names | `scan_results[].tool_name` | `core/models.py` |
| Repo name | `request.repo_name` | `core/models.py` |
| Ecosystem | `request.ecosystem` | `core/models.py` |

### Metering Implementation

Add a metering event emitter to the scan worker:

```python
# src/caliper/cloud/metering.py
@dataclass
class ScanEvent:
    tenant_id: str
    run_id: str
    scan_type: str          # "dependency" | "review"
    plugin_count: int
    finding_count: int
    pipeline_duration_s: float
    repo_name: str
    pr_number: int
    timestamp: datetime

class MeteringEmitter:
    """Emit usage events to a streaming platform."""

    async def emit(self, event: ScanEvent) -> None:
        """Write to Kinesis/Pub/Sub for downstream billing aggregation."""
        ...
```

### Billing Model Options

| Plan | Monthly Quota | Price Signal |
|------|--------------|--------------|
| Free | 100 scans | Scan count only |
| Team | 1,000 scans | Scan count + repo count |
| Enterprise | Unlimited | Scan count + plugin count + repo count |

Quota enforcement happens at the webhook handler level (`check scan quota` before
enqueuing). Over-quota scans return a PR comment explaining the limit.


## 10. API Surface

### REST API for Cloud Caliper

The cloud service needs a REST API for:
1. Dashboard data (scan history, findings, trends)
2. Org settings management (enabled plugins, policy overrides)
3. GitHub App installation flow
4. Webhook receiver

#### Endpoints

```
POST   /webhooks/github                  # GitHub App webhook receiver
GET    /api/v1/scans                     # List scans (paginated, filtered)
GET    /api/v1/scans/{run_id}            # Scan detail (decision, findings, memo)
GET    /api/v1/scans/{run_id}/sarif      # SARIF download
GET    /api/v1/scans/{run_id}/evidence   # Evidence bundle download
GET    /api/v1/packages                  # Package catalog (paginated)
GET    /api/v1/packages/{eco}/{name}/{ver}  # Package detail
GET    /api/v1/packages/{eco}/{name}/{ver}/consumers  # Repos using this package
POST   /api/v1/packages/search           # Semantic search (pgvector)
GET    /api/v1/stats/overview            # Org dashboard: scan count, finding trends
GET    /api/v1/stats/packages            # Most-rejected packages
GET    /api/v1/stats/teams               # Per-team scan activity
GET    /api/v1/settings                  # Org settings
PUT    /api/v1/settings                  # Update org settings
GET    /api/v1/settings/policy           # Current OPA policy
PUT    /api/v1/settings/policy           # Upload custom OPA policy
POST   /api/v1/auth/github/install       # Handle GitHub App installation callback
DELETE /api/v1/auth/github/install       # Handle GitHub App uninstallation
GET    /api/v1/billing/usage             # Current billing period usage
```

#### Implementation

New presentation tier at `src/caliper/api/` using FastAPI:

```
src/caliper/api/
  __init__.py
  app.py           # FastAPI app factory
  routes/
    webhooks.py    # POST /webhooks/github
    scans.py       # /api/v1/scans/*
    packages.py    # /api/v1/packages/*
    stats.py       # /api/v1/stats/*
    settings.py    # /api/v1/settings/*
    auth.py        # /api/v1/auth/*
    billing.py     # /api/v1/billing/*
  middleware/
    tenant.py      # Extract tenant_id from JWT, set on request state
    rate_limit.py  # Per-tenant rate limiting
  deps.py          # Dependency injection (DB pool, object store, etc.)
```

This is a third presentation tier alongside `cli/` and `agent/`, all calling the
same `core/` logic layer. The three-tier architecture holds.


## 11. Dashboard Data

### Already Available (from existing data model)

| Dashboard Widget | Data Source | Query |
|-----------------|-------------|-------|
| Scan history timeline | `review_decisions` | `SELECT * FROM review_decisions WHERE tenant_id = %s ORDER BY created_at DESC` |
| Verdict distribution (pie chart) | `review_decisions.decision` | `GROUP BY decision` |
| Finding severity breakdown | `review_decisions.findings_summary` | JSONB aggregation |
| Top rejected packages | `review_decisions` | `WHERE decision = 'reject' GROUP BY package_name` |
| Scanner health | `scan_results` | `GROUP BY tool_name, status` |
| Pipeline latency (p50/p95) | `review_decisions.pipeline_duration_seconds` | Percentile query |
| Policy rule hit frequency | `policy_evaluations.triggered_rules` | JSONB unnest + GROUP BY |
| Package catalog coverage | `package_catalog` | `COUNT(*) WHERE vuln_scanned_at IS NOT NULL` |
| Repo inventory | `repo_inventory` + `repo_packages` | Package count per repo |
| Semantic package search | `package_catalog.description_embedding` | pgvector cosine similarity |
| Parquet-based analytics | `decisions.parquet` | DuckDB queries via Athena or local DuckDB |

### Missing for Dashboard

| Widget | What's Needed | Where to Add |
|--------|--------------|--------------|
| Scan trend over time | Aggregate scan count by day/week | `scan_events` table (new) |
| Per-team comparison | Team-level aggregation | Already available via `review_requests.team` |
| MTTR (mean time to resolve) | Track when a rejected package is later approved | New `resolution_events` table |
| Policy change audit trail | Track OPA policy modifications | New `policy_versions` table |
| Repo health score | Aggregate severity score per repo | Computed from `review_decisions` per repo |
| Alert configuration | Notify on critical findings | New `alert_rules` + `alert_events` tables |
| Scan comparison (before/after) | Diff two scan runs | Compare `decisions.parquet` rows by run_id |


## 12. Migration Path: Self-Hosted CLI to Cloud SaaS

### Phase 1: Storage Abstraction (2-3 weeks)

**Goal:** Decouple evidence storage from local filesystem without changing any
external behavior. All existing tests continue to pass.

| Change | File | Description |
|--------|------|-------------|
| Add `EvidenceStoreProtocol` | `src/caliper/data/evidence.py` | Protocol with `store()`, `store_file()`, `get_path()`, `list_artifacts()` |
| Create `S3EvidenceStore` | `src/caliper/data/object_store.py` | S3-compatible implementation of `EvidenceStoreProtocol` |
| Add `evidence_backend` config | `src/caliper/core/config.py` | New field: `evidence_backend: str = "local"` with values `local`, `s3` |
| Add `evidence_bucket` config | `src/caliper/core/config.py` | New field: `evidence_bucket: str = ""` |
| Factory for evidence store | `src/caliper/core/pipeline.py` | Construct `EvidenceStore` or `S3EvidenceStore` based on config |
| Rewrite Parquet writer | `src/caliper/data/parquet_writer.py` | Write per-run Parquet files instead of read-modify-write |
| Add seal index table | `migrations/003_cloud.sql` | `seal_index` table for seal chain lookup |
| Update `find_previous_seal_hash` | `src/caliper/core/seal.py` | Accept a `SealIndexProtocol` for DB-backed lookup |

### Phase 2: GitHub App + Webhook Handler (2-3 weeks)

**Goal:** Accept GitHub webhooks and run scans without requiring a self-hosted
runner.

| Change | File | Description |
|--------|------|-------------|
| GitHub App auth module | `src/caliper/cloud/github_app.py` | JWT signing, installation token exchange |
| Webhook handler | `src/caliper/cloud/webhook.py` | Validate, parse, enqueue |
| Queue consumer | `src/caliper/cloud/worker.py` | Dequeue, clone, scan, post results |
| Tenant model | `src/caliper/cloud/tenant.py` | Tenant lookup by installation_id |
| Cloud config | `src/caliper/cloud/config.py` | `CloudSettings` with `CALIPER_CLOUD_` prefix |
| Update agent for App auth | `src/caliper/agent/main.py` | Accept `GitHubAppAuth` instead of raw token |
| Migration 003 | `migrations/003_cloud.sql` | `tenants`, `scan_events`, `seal_index` tables |

### Phase 3: Multi-Tenancy + API (3-4 weeks)

**Goal:** Serve multiple organizations from a single deployment with tenant
isolation and a REST API.

| Change | File | Description |
|--------|------|-------------|
| Add `tenant_id` columns | `migrations/004_multi_tenant.sql` | All existing tables get `tenant_id` |
| Row-level security policies | `migrations/004_multi_tenant.sql` | RLS on all tables |
| Tenant context middleware | `src/caliper/api/middleware/tenant.py` | Extract tenant from JWT, set `app.tenant_id` |
| REST API routes | `src/caliper/api/routes/*.py` | All endpoints from Section 10 |
| FastAPI app factory | `src/caliper/api/app.py` | Wire routes, middleware, deps |
| Rate limiting | `src/caliper/api/middleware/rate_limit.py` | Per-tenant rate limits |
| Update `DecisionRepository` | `src/caliper/data/db.py` | All queries include `tenant_id` filter |
| Update `PackageCatalog` | `src/caliper/data/catalog.py` | All queries include `tenant_id` filter |

### Phase 4: Metering + Billing (2 weeks)

**Goal:** Track usage for billing and enforce scan quotas.

| Change | File | Description |
|--------|------|-------------|
| Metering emitter | `src/caliper/cloud/metering.py` | Emit scan events to Kinesis/Pub/Sub |
| Quota enforcement | `src/caliper/cloud/webhook.py` | Check `scans_used_this_month < scan_quota_monthly` |
| Billing API routes | `src/caliper/api/routes/billing.py` | Usage summary endpoint |
| Billing aggregation Lambda | `infra/lambda/billing_aggregator.py` | Consume metering stream, update tenant counts |

### Phase 5: Dashboard UI (3-4 weeks)

**Goal:** Web dashboard for scan history, findings, and org settings.

This phase is frontend work consuming the API from Phase 3. Technology choice:
Next.js or SvelteKit with server-side rendering, hosted on Cloudflare Pages or
Vercel.

### Phase 6: Multi-Region (2-3 weeks)

**Goal:** Evidence residency compliance and scan locality.

| Change | File | Description |
|--------|------|-------------|
| Region-aware evidence routing | `src/caliper/cloud/worker.py` | Select bucket by tenant's `evidence_region` |
| DB read replicas | Infrastructure | Read replica per region for dashboard queries |
| Regional scan workers | Infrastructure | Cloud Run/ECS in eu-west-1 and ap-southeast-1 |
| Tenant region config | `src/caliper/cloud/tenant.py` | `evidence_region` field on tenant |


## 13. Infrastructure as Code

### AWS (Terraform)

```
infra/
  aws/
    main.tf
    modules/
      api-gateway/        # REST API + webhook endpoint
      ecs-worker/         # Fargate task definition for scan worker
      sqs/                # Scan job queue + DLQ
      rds/                # PostgreSQL with pgvector
      s3-evidence/        # Evidence buckets (per-region)
      kinesis-metering/   # Usage event stream
      lambda-webhook/     # Webhook handler
      lambda-billing/     # Billing aggregator
      secrets-manager/    # GitHub App private key, DB creds
      ecr/                # Container registry (or use GHCR)
      cloudwatch/         # Alarms: queue depth, worker errors, latency
```

### GCP (Terraform)

```
infra/
  gcp/
    main.tf
    modules/
      cloud-run-worker/   # Scan worker service
      cloud-tasks/        # Scan job queue
      cloud-sql/          # PostgreSQL with pgvector
      gcs-evidence/       # Evidence buckets (per-region)
      pubsub-metering/    # Usage event topic
      cloud-function-wh/  # Webhook handler
      secret-manager/     # GitHub App private key, DB creds
      artifact-registry/  # Container registry
      monitoring/         # Alerts: queue depth, worker errors, latency
```


## 14. Specific File Changes Summary

### Files That Change

| File | Change Type | What Changes |
|------|------------|--------------|
| `src/caliper/core/config.py` | Modify | Add `evidence_backend`, `evidence_bucket`, `evidence_region` fields |
| `src/caliper/core/pipeline.py` | Modify | Accept `EvidenceStoreProtocol` via DI instead of constructing `EvidenceStore` directly |
| `src/caliper/core/seal.py` | Modify | Accept `SealIndexProtocol` for DB-backed previous seal lookup |
| `src/caliper/data/evidence.py` | Modify | Extract `EvidenceStoreProtocol`; existing class implements it |
| `src/caliper/data/parquet_writer.py` | Modify | Write per-run files; accept storage backend parameter |
| `src/caliper/data/db.py` | Modify | Add `tenant_id` to all queries; accept tenant context |
| `src/caliper/data/catalog.py` | Modify | Add `tenant_id` to all queries |
| `src/caliper/agent/main.py` | Modify | Support `GitHubAppAuth` alongside raw token |
| `src/caliper/agent/config.py` | Modify | Add GitHub App config fields |
| `.github/workflows/foreman.yml` | Keep | Remains for self-hosted/hybrid deployments |
| `Dockerfile` | Keep | Scan worker image; add `CMD` override for queue consumer mode |

### New Files

| File | Purpose |
|------|---------|
| `src/caliper/cloud/__init__.py` | Cloud module package |
| `src/caliper/cloud/config.py` | `CloudSettings` with `CALIPER_CLOUD_` prefix |
| `src/caliper/cloud/github_app.py` | GitHub App JWT auth + installation tokens |
| `src/caliper/cloud/webhook.py` | Webhook validation, parsing, job enqueue |
| `src/caliper/cloud/worker.py` | Queue consumer, scan orchestration |
| `src/caliper/cloud/tenant.py` | Tenant model, lookup, quota check |
| `src/caliper/cloud/metering.py` | Usage event emission |
| `src/caliper/data/object_store.py` | S3/GCS evidence store implementation |
| `src/caliper/api/__init__.py` | API module package |
| `src/caliper/api/app.py` | FastAPI application factory |
| `src/caliper/api/deps.py` | Dependency injection |
| `src/caliper/api/routes/webhooks.py` | Webhook endpoint |
| `src/caliper/api/routes/scans.py` | Scan history endpoints |
| `src/caliper/api/routes/packages.py` | Package catalog endpoints |
| `src/caliper/api/routes/stats.py` | Dashboard stats endpoints |
| `src/caliper/api/routes/settings.py` | Org settings endpoints |
| `src/caliper/api/routes/auth.py` | GitHub App installation flow |
| `src/caliper/api/routes/billing.py` | Usage and billing endpoints |
| `src/caliper/api/middleware/tenant.py` | Tenant context extraction |
| `src/caliper/api/middleware/rate_limit.py` | Per-tenant rate limiting |
| `migrations/003_cloud.sql` | Cloud tables: tenants, scan_events, seal_index |
| `migrations/004_multi_tenant.sql` | Add tenant_id + RLS to all existing tables |


## 15. What Does NOT Change

The following modules are cloud-ready as-is and require zero modifications:

- `src/caliper/core/models.py` -- all domain models
- `src/caliper/core/orchestrator.py` -- scanner parallelism
- `src/caliper/core/normalizer.py` -- finding dedup
- `src/caliper/core/policy.py` -- OPA evaluation
- `src/caliper/core/decision.py` -- decision assembly
- `src/caliper/core/memo.py` -- memo generation
- `src/caliper/core/diff.py` -- diff parsing
- `src/caliper/core/sbom_diff.py` -- SBOM diffing
- `src/caliper/core/plugin.py` -- plugin ABC
- `src/caliper/core/registry.py` -- plugin registry
- `src/caliper/core/renderer.py` -- comment rendering
- `src/caliper/core/sarif.py` -- SARIF generation
- `src/caliper/core/repo_config.py` -- repo config loading
- `src/caliper/core/taskfit.py` -- LLM advisory
- `src/caliper/plugins/*` -- all 19 plugins
- `src/caliper/data/scanners/*` -- all scanner implementations
- `src/caliper/data/pypi.py` -- PyPI client
- `src/caliper/cli/` -- CLI entry point (self-hosted mode)
- `policies/` -- OPA Rego policies
- `src/caliper/templates/` -- Jinja2 templates

This is 80%+ of the codebase. The core logic, plugins, scanners, policy engine,
and rendering pipeline all work unchanged in the cloud. The migration is
primarily about plumbing: replacing local I/O with cloud I/O and adding
multi-tenant context.
