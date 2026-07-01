/**
 * Typed fetch client for the `caliper part --serve` sidecar API.
 *
 * # tested-by: scripts/screenshots.ts (browser gate) + tests/unit/test_part_serve.py
 *   (server-side route contracts via `dispatch`)
 *
 * Every method throws `Error(message)` on a non-2xx response, reading the
 * `{"error": "..."}` body the sidecar always sends on a rejected request
 * (mirrors the inline `post()` helper the old server-rendered page used).
 */

import type {
  ApplyResult,
  CutList,
  OverrideRule,
  PartRunResult,
  PartTarget,
  RollbackResult,
  UntargetedCut,
} from "./types.js";

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    let message = "";
    try {
      const body = (await res.json()) as { error?: string };
      message = body?.error ?? "";
    } catch {
      // non-JSON error body — fall through to the generic message below
    }
    throw new Error(message || `HTTP ${res.status}`);
  }
  return (await res.json()) as T;
}

function postJson<T>(url: string, payload: unknown): Promise<T> {
  return request<T>(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function fetchCutlist(): Promise<CutList | UntargetedCut> {
  return request<CutList | UntargetedCut>("/cutlist");
}

/** Write one override (glob -> bucket) and re-part — mirrors the CLI's manual
 * `.caliper.yaml` edit + re-run. */
export function reclassify(glob: string, bucket: string, note = ""): Promise<CutList> {
  return postJson<CutList>("/reclassify", { glob, bucket, note });
}

/** Re-cut with the settings already on the session. */
export function repart(): Promise<CutList> {
  return request<CutList>("/repart", { method: "POST" });
}

/** Live-adjust the size cap and re-cut — `null` clears the cap (1 part/bucket). */
export function setSizeCap(sizeCap: number | null): Promise<CutList> {
  return postJson<CutList>("/repart", { size_cap: sizeCap });
}

export interface SuggestResponse {
  suggestions: OverrideRule[];
  configured: boolean;
}

/** Ask the sidecar's advisory tier suggester for globs on the `logic` residual.
 * Nothing is written — the reviewer accepts via `reclassify` or `suggestApply`. */
export function suggest(): Promise<SuggestResponse> {
  return request<SuggestResponse>("/suggest", { method: "POST" });
}

/** Bulk-accept: write every rule and re-part once (the "accept all" button). */
export function suggestApply(rules: OverrideRule[]): Promise<CutList> {
  return postJson<CutList>("/suggest/apply", { globs: rules });
}

/** Point the session at a new base..head range in the already-configured repo. */
export function setRange(base: string, head: string): Promise<CutList> {
  return postJson<CutList>("/range", { base, head });
}

/** Resolve a PR URL or bare number, clone it, and target its base..head. */
export function setPr(ref: string): Promise<CutList> {
  return postJson<CutList>("/pr", { ref });
}

/** Run the safety gate and render the restack script + rollback header. Mints
 * a fresh `apply_token` each call — the P5 `/apply` credential. */
export function restack(opts: {
  describe?: boolean;
  force?: boolean;
  target?: PartTarget;
}): Promise<PartRunResult> {
  return postJson<PartRunResult>("/restack", opts);
}

/** Fetch the last-generated restack.sh as plain text (for the Blob download). */
export async function fetchRestackScript(): Promise<string> {
  const res = await fetch("/restack.sh");
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  return res.text();
}

/** Execute the last-generated restack.sh (the jj surgery) for real. Requires
 * the one-shot `apply_token` from the most recent `restack()` call. */
export function apply(applyToken: string): Promise<ApplyResult> {
  return postJson<ApplyResult>("/apply", { apply_token: applyToken });
}

/** Undo everything since the gate's rescue op (`jj op restore`) — the escape
 * hatch, available any time after a restack whether or not apply ran. */
export function rollback(): Promise<RollbackResult> {
  return request<RollbackResult>("/rollback", { method: "POST" });
}
