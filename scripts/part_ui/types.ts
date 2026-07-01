/**
 * TS mirrors of the caliper `part` boundary models.
 *
 * Source of truth is Python: `src/caliper/core/models.py` (CutList, Part,
 * Provenance, CutStats, Ambiguity, ChangeType) and
 * `src/caliper/core/repo_config.py` (OverrideRule). Keep these in sync by
 * hand until a drift test lands (planned: diff `SELECTABLE_BUCKETS` below
 * against `_SELECTABLE_BUCKETS` in `src/caliper/cli/part_serve.py`).
 */

// Every ChangeType value (core/models.py `ChangeType`). Structural facts
// (move/delete/binary) come from git, never from reclassification — they are
// excluded from `SELECTABLE_BUCKETS` below, not from this type.
export type ChangeType =
  | "generated"
  | "move"
  | "delete"
  | "binary"
  | "config"
  | "test"
  | "logic"
  | "documentation"
  | "supply_chain"
  | "ci_cd"
  | "security_policy"
  | "schema_contracts"
  | "frontend"
  | "business"
  | "data"
  | "infra";

export interface Kerf {
  fired_rule: string;
  rationale?: string;
}

export interface Part {
  id: string;
  files: string[];
  bucket: ChangeType;
  size: number;
  opened_by: Kerf;
  oversized: boolean;
}

export interface Ambiguity {
  file: string;
  reason: string;
}

export interface Provenance {
  caliper_version: string;
  base_sha: string;
  head_sha: string;
  rename_threshold: number;
  config_digest: string;
  resolved_revsets?: Record<string, string>;
}

export interface CutStats {
  part_count: number;
  file_count: number;
  size_p50: number;
  size_p90: number;
  move_logic_pure?: boolean;
}

export interface OverrideRule {
  glob: string;
  bucket: ChangeType;
  note?: string;
}

export interface CutList {
  parts: Part[];
  ambiguities: Ambiguity[];
  size_cap: number | null;
  provenance: Provenance;
  stats: CutStats;
  overrides?: OverrideRule[];
  /** Present only right after POST /pr — identifies which PR was resolved. */
  pr?: PrMeta;
}

/** The sidecar reports this shape instead of a `CutList` when no range/PR has
 * been targeted yet (see `PartingSession.targeted` in `part_serve.py`). */
export interface UntargetedCut {
  targeted: false;
}

export function isTargeted(cut: CutList | UntargetedCut): cut is CutList {
  return (cut as UntargetedCut).targeted !== false;
}

/** Attached to a CutList response by POST /pr, identifying which PR was resolved. */
export interface PrMeta {
  slug: string;
  number: number;
}

// Buckets a reviewer may assign from the UI. Mirrors `_SELECTABLE_BUCKETS` in
// src/caliper/cli/part_serve.py — same membership, curated order (tiers ->
// intent -> residual), structural facts excluded.
export const SELECTABLE_BUCKETS: ChangeType[] = [
  "frontend",
  "business",
  "data",
  "infra",
  "documentation",
  "supply_chain",
  "ci_cd",
  "security_policy",
  "config",
  "schema_contracts",
  "test",
  "generated",
  "logic",
];

// The bucket the residual lands in — rendered with a distinct "needs a tier" cue.
export const UNTIERED: ChangeType = "logic";

/** Substrate handoff shape for the restack script — affects only the script,
 * never the cut list (core/models.py `PartTarget`). */
export type PartTarget = "stack" | "series";

/** Response of POST /restack (core/part_pipeline.py `PartRunResult` + the
 * session's freshly minted apply_token). */
export interface PartRunResult {
  cutlist: CutList;
  script_text: string;
  backup_bookmark: string;
  rescue_op_id: string;
  jj_version: string;
  can_reconstruct: boolean;
  subjects: Record<string, string>;
  proposed_overrides: OverrideRule[];
  applied_overrides: OverrideRule[];
  restack_path: string | null;
  cutlist_path: string | null;
  apply_token: string;
}

/** Escape hatch echoed by POST /apply and available any time after a
 * /restack — the rescue op a reviewer runs to undo the surgery. */
export interface RollbackInfo {
  backup_bookmark: string;
  rescue_op_id: string;
}

/** Response of POST /apply (session.apply(), core/tool_runner.py `ToolResult`
 * projected to the fields the reviewer needs). */
export interface ApplyResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  rollback: RollbackInfo;
}

/** Response of POST /rollback. */
export interface RollbackResult {
  ok: boolean;
  stdout: string;
  stderr: string;
}
