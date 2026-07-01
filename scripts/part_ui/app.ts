/**
 * `caliper part --serve` SPA entry point.
 *
 * P1 slice: interaction parity with the CLI's reclassify / suggest / re-part
 * flow (P0 was read-only render parity). Live targeting, settings, restack
 * and apply/rollback land in later phases.
 */

import {
  apply as applyRestack,
  fetchCutlist,
  reclassify,
  repart,
  restack,
  rollback as rollbackRestack,
  setPr,
  setRange,
  setSizeCap,
  suggest,
  suggestApply,
  type SuggestResponse,
} from "./api.js";
import {
  isTargeted,
  SELECTABLE_BUCKETS,
  UNTIERED,
  type ApplyResult,
  type ChangeType,
  type CutList,
  type OverrideRule,
  type Part,
  type PartRunResult,
  type PartTarget,
  type RollbackResult,
  type UntargetedCut,
} from "./types.js";

let currentCut: CutList | UntargetedCut | null = null;
let suggestState: SuggestResponse | null = null;
let errorMessage: string | null = null;
let busy = false;
let showTargetForm = false;
/** A cutlist.json loaded from disk via the explain viewer — purely client-side,
 * no session involved, read-only. Set aside the live `currentCut` while active. */
let explainCut: CutList | null = null;
/** The last `/restack` response — script text, rollback header, apply_token —
 * shown in the restack panel until the next generate or re-target. */
let lastRun: PartRunResult | null = null;
/** Whether the "apply restack now" confirm overlay is open. */
let showApplyConfirm = false;
/** Result of the last `/apply` call — cleared on the next generate/retarget. */
let applyResult: ApplyResult | null = null;
/** Result of the last `/rollback` call — cleared on the next generate/retarget. */
let rollbackResult: RollbackResult | null = null;

function escapeHtml(value: string): string {
  const div = document.createElement("div");
  div.textContent = value;
  return div.innerHTML;
}

/** `escapeHtml` is safe inside text nodes but not inside a quoted attribute —
 * it leaves `"` untouched. Use this wherever untrusted text lands in an
 * attribute value (file paths and glob/note strings can contain anything). */
function escapeAttr(value: string): string {
  return escapeHtml(value).replace(/"/g, "&quot;");
}

function shortSha(sha: string): string {
  return sha ? sha.slice(0, 9) : "—";
}

function dirnameOf(path: string): string {
  const idx = path.lastIndexOf("/");
  return idx === -1 ? "" : path.slice(0, idx);
}

/** The "⤢ broaden" default: widen an exact file path to its containing
 * directory. A reviewer can still hand-edit the input for anything narrower
 * or wider. */
function broadenedGlob(path: string): string {
  const dir = dirnameOf(path);
  return dir ? `${dir}/**` : "**";
}

function renderHeader(cut: CutList): string {
  const bucketCount = new Set(cut.parts.map((p) => p.bucket)).size;
  const capStr = cut.size_cap == null ? "none (1 part/bucket)" : String(cut.size_cap);
  const base = shortSha(cut.provenance.base_sha);
  const head = shortSha(cut.provenance.head_sha);
  return `
    <header class="cut-header">
      <h1>caliper cut list</h1>
      <p class="sub">${cut.stats.part_count} parts across ${bucketCount} bucket${bucketCount === 1 ? "" : "s"}
        &middot; ${cut.stats.file_count} files &middot; cap ${capStr} &middot; ${base} → ${head}</p>
    </header>`;
}

function renderOverrides(overrides: OverrideRule[]): string {
  if (overrides.length === 0) {
    return `<div class="overrides empty">no overrides yet — reclassify a file below</div>`;
  }
  const badges = overrides
    .map(
      (o) =>
        `<span class="ov"><code>${escapeHtml(o.glob)}</code> → <b>${escapeHtml(o.bucket)}</b></span>`,
    )
    .join("");
  return `<div class="overrides"><h2>active overrides</h2>${badges}</div>`;
}

function renderSuggestPanel(): string {
  if (!suggestState) {
    return `<button type="button" class="btn" data-action="suggest">✨ suggest tiers</button>`;
  }
  if (!suggestState.configured) {
    return `<p class="muted">tier suggester not configured (no local model reachable).</p>`;
  }
  if (suggestState.suggestions.length === 0) {
    return `<p class="muted">no tier suggestions — the residual is empty or the model found nothing.</p>`;
  }
  const chips = suggestState.suggestions
    .map(
      (s) => `
      <li class="chip">
        <code>${escapeHtml(s.glob)}</code> → <b>${escapeHtml(s.bucket)}</b>
        <button type="button" class="btn-sm" data-action="suggest-accept"
          data-glob="${escapeAttr(s.glob)}" data-bucket="${escapeAttr(s.bucket)}"
          data-note="${escapeAttr(s.note ?? "")}">accept</button>
      </li>`,
    )
    .join("");
  return `
    <div class="suggestions">
      <ul class="chips">${chips}</ul>
      <button type="button" class="btn" data-action="suggest-accept-all">
        accept all (${suggestState.suggestions.length})
      </button>
    </div>`;
}

function renderRestackPanel(): string {
  const form = `
    <div class="restack-form">
      <label><input type="checkbox" class="restack-describe" /> describe (local model)</label>
      <label><input type="checkbox" class="restack-force" /> force (skip already-pushed check)</label>
      <select class="field restack-target" aria-label="restack target shape">
        <option value="">target: config default</option>
        <option value="stack">target: stack</option>
        <option value="series">target: series</option>
      </select>
      <button type="button" class="btn" data-action="generate-restack">generate restack script</button>
    </div>`;
  if (!lastRun) {
    return `<div class="restack-panel"><h2>restack</h2>${form}</div>`;
  }
  const rollbackHeader = `
    <pre class="rollback-header">ROLLBACK  jj op restore ${escapeHtml(lastRun.rescue_op_id)}
backup bookmark: ${escapeHtml(lastRun.backup_bookmark)}
${escapeHtml(lastRun.jj_version || "jj version unknown")}${lastRun.can_reconstruct ? "" : "  (manual path restore — jj lacks non-interactive support)"}</pre>`;
  return `
    <div class="restack-panel">
      <h2>restack</h2>
      ${form}
      ${rollbackHeader}
      <div class="restack-downloads">
        <button type="button" class="btn-sm" data-action="download-restack">download restack.sh</button>
        <button type="button" class="btn-sm" data-action="download-cutlist">download cutlist.json</button>
      </div>
      <details class="restack-script-viewer">
        <summary>view restack.sh</summary>
        <pre class="script-text">${escapeHtml(lastRun.script_text)}</pre>
      </details>
      ${renderApplyControls(lastRun)}
    </div>`;
}

function renderResultBlock(label: string, result: { ok: boolean; stdout: string; stderr: string }): string {
  return `
    <div class="apply-result ${result.ok ? "ok" : "fail"}">
      <p>${label} ${result.ok ? "succeeded" : "FAILED"}</p>
      ${result.stdout ? `<pre class="apply-output">${escapeHtml(result.stdout)}</pre>` : ""}
      ${result.stderr ? `<pre class="apply-output apply-stderr">${escapeHtml(result.stderr)}</pre>` : ""}
    </div>`;
}

/** The P5 execute/rollback controls: an "apply restack now" button gated
 * behind a confirm overlay that echoes the backup bookmark (per the plan),
 * plus an always-available rollback button and the results of either. */
function renderApplyControls(run: PartRunResult): string {
  const confirm = showApplyConfirm
    ? `
      <div class="apply-confirm-overlay">
        <div class="apply-confirm">
          <h3>apply restack now?</h3>
          <p>This runs the jj surgery for real. If anything goes wrong:</p>
          <pre class="rollback-header">jj op restore ${escapeHtml(run.rescue_op_id)}
backup bookmark: ${escapeHtml(run.backup_bookmark)}</pre>
          <div class="apply-confirm-actions">
            <button type="button" class="btn" data-action="confirm-apply">yes, apply now</button>
            <button type="button" class="btn-sm" data-action="cancel-apply">cancel</button>
          </div>
        </div>
      </div>`
    : "";
  return `
    <div class="apply-controls">
      <button type="button" class="btn" data-action="open-apply-confirm">APPLY restack now</button>
      <button type="button" class="btn-sm" data-action="rollback">rollback (jj op restore)</button>
      ${applyResult ? renderResultBlock("apply", applyResult) : ""}
      ${rollbackResult ? renderResultBlock("rollback", rollbackResult) : ""}
    </div>
    ${confirm}`;
}

function renderToolbar(cut: CutList): string {
  return `
    <div class="toolbar">
      <button type="button" class="btn" data-action="repart">re-part</button>
      <div class="size-cap-control">
        <input
          type="number"
          min="1"
          class="field size-cap-input"
          placeholder="no cap"
          value="${cut.size_cap ?? ""}"
          aria-label="size cap"
        />
        <button type="button" class="btn-sm" data-action="set-size-cap">apply cap</button>
      </div>
      ${renderSuggestPanel()}
      ${renderExplainTrigger()}
    </div>`;
}

/** A styled label wrapping a hidden file input — clicking it opens the OS file
 * picker with no JS-driven .click() needed; only the resulting `change` event
 * is handled (see the delegated "change" listener in attachHandlers). */
function renderExplainTrigger(): string {
  return `
    <label class="btn-sm file-label">
      view a saved cutlist.json
      <input type="file" class="explain-file-input" accept="application/json" hidden />
    </label>`;
}

function renderReadOnlyFileRow(path: string, bucket: string): string {
  return `
    <li class="file-row-ro">
      <code class="path">${escapeHtml(path)}</code>
      <span class="badge">${escapeHtml(bucket)}</span>
    </li>`;
}

function renderReadOnlyPart(part: Part, index: number): string {
  const untiered = part.bucket === UNTIERED;
  return `
    <article class="cut-card" data-bucket="${escapeHtml(part.bucket)}">
      <h3>
        <span class="idx">${index}</span>
        <span class="badge">${escapeHtml(part.bucket)}</span>
        ${untiered ? `<span class="untiered-tag">needs a tier</span>` : ""}
        <small>${part.files.length} file${part.files.length === 1 ? "" : "s"} &middot; size ${part.size}${part.oversized ? " &middot; oversized" : ""}</small>
      </h3>
      <ul class="files-readonly">
        ${part.files.map((f) => renderReadOnlyFileRow(f, part.bucket)).join("")}
      </ul>
    </article>`;
}

function renderExplainView(cut: CutList): string {
  return [
    `<div class="explain-banner">
       viewing a loaded <code>cutlist.json</code> — read-only
       <button type="button" class="btn-sm" data-action="close-explain">back to live session</button>
     </div>`,
    renderHeader(cut),
    renderOverrides(cut.overrides ?? []),
    `<div class="cut-cards">${cut.parts.map((p, i) => renderReadOnlyPart(p, i + 1)).join("")}</div>`,
  ].join("");
}

/** The range/PR inputs — shown always in the empty state, toggled on demand
 * once a cut is already rendered (retargeting a live session). */
function renderTargetForm(): string {
  return `
    <div class="target-form">
      <div class="target-row">
        <input type="text" class="field target-base" placeholder="base (e.g. main)" aria-label="base revision" />
        <input type="text" class="field target-head" placeholder="head (e.g. HEAD)" aria-label="head revision" />
        <button type="button" class="btn-sm" data-action="set-range">target range</button>
      </div>
      <div class="target-row">
        <input type="text" class="field target-pr" placeholder="PR URL or number" aria-label="pull request" />
        <button type="button" class="btn-sm" data-action="set-pr">target PR</button>
      </div>
    </div>`;
}

function renderTargetPanel(): string {
  return `
    <div class="target-panel">
      <button type="button" class="btn-sm" data-action="toggle-target-form">retarget</button>
      ${showTargetForm ? renderTargetForm() : ""}
    </div>`;
}

function renderBucketOptions(selected: ChangeType): string {
  return SELECTABLE_BUCKETS.map(
    (b) => `<option value="${b}"${b === selected ? " selected" : ""}>${b}</option>`,
  ).join("");
}

function renderFileRow(path: string, bucket: ChangeType): string {
  return `
    <li class="file-row" data-path="${escapeAttr(path)}">
      <code class="path">${escapeHtml(path)}</code>
      <input class="glob" type="text" value="${escapeAttr(path)}" required
        pattern="\\S.*" aria-label="glob for ${escapeAttr(path)}" />
      <button type="button" class="btn-sm" data-action="broaden"
        title="broaden to the containing directory">⤢</button>
      <select class="bucket-select" aria-label="bucket for ${escapeAttr(path)}">${renderBucketOptions(bucket)}</select>
      <button type="button" class="btn-sm" data-action="reclassify">save</button>
    </li>`;
}

function renderPart(part: Part, index: number): string {
  const untiered = part.bucket === UNTIERED;
  const flag = untiered ? `<span class="untiered-tag">needs a tier</span>` : "";
  const rows = part.files.map((f) => renderFileRow(f, part.bucket)).join("");
  return `
    <article class="cut-card" data-bucket="${escapeHtml(part.bucket)}">
      <h3>
        <span class="idx">${index}</span>
        <span class="badge">${escapeHtml(part.bucket)}</span>
        ${flag}
        <small>${part.files.length} file${part.files.length === 1 ? "" : "s"}
          &middot; size ${part.size}${part.oversized ? " &middot; oversized" : ""}</small>
      </h3>
      <ul class="files">${rows}</ul>
    </article>`;
}

function renderCut(cut: CutList): string {
  return [
    renderHeader(cut),
    cut.pr ? `<p class="muted">targeting PR ${escapeHtml(cut.pr.slug)}#${cut.pr.number}</p>` : "",
    renderTargetPanel(),
    renderOverrides(cut.overrides ?? []),
    renderToolbar(cut),
    errorMessage ? `<div class="error-banner">${escapeHtml(errorMessage)}</div>` : "",
    `<div class="cut-cards">${cut.parts.map((p, i) => renderPart(p, i + 1)).join("")}</div>`,
    renderRestackPanel(),
  ].join("");
}

function renderUntargeted(): string {
  return `
    <header class="cut-header"><h1>caliper cut list</h1></header>
    <div class="empty-state">
      <p>no range targeted yet — enter a base/head range or a PR to begin.</p>
      ${renderTargetForm()}
      <p>${renderExplainTrigger()} a saved cutlist.json instead</p>
      ${errorMessage ? `<div class="error-banner">${escapeHtml(errorMessage)}</div>` : ""}
    </div>`;
}

function render(): void {
  const root = document.getElementById("app");
  if (!root) return;
  if (explainCut) {
    root.innerHTML = renderExplainView(explainCut);
    return;
  }
  if (!currentCut) return;
  root.innerHTML = isTargeted(currentCut) ? renderCut(currentCut) : renderUntargeted();
}

/** Runs one mutating call at a time, capturing failures into `errorMessage`
 * instead of throwing past the click handler (a review tool should never go
 * blank on a rejected reclassify). */
async function withBusy<T>(fn: () => Promise<T>): Promise<T | undefined> {
  if (busy) return undefined;
  busy = true;
  errorMessage = null;
  try {
    return await fn();
  } catch (err) {
    errorMessage = (err as Error).message;
    render();
    return undefined;
  } finally {
    busy = false;
  }
}

async function handleAction(action: string, el: HTMLElement): Promise<void> {
  switch (action) {
    case "repart": {
      const cut = await withBusy(() => repart());
      if (cut) {
        currentCut = cut;
        render();
      }
      break;
    }
    case "suggest": {
      const result = await withBusy(() => suggest());
      if (result) {
        suggestState = result;
        render();
      }
      break;
    }
    case "suggest-accept": {
      const glob = el.dataset.glob ?? "";
      const bucket = el.dataset.bucket ?? "";
      const note = el.dataset.note ?? "";
      if (!glob || !bucket) break;
      const cut = await withBusy(() => reclassify(glob, bucket, note));
      if (cut) {
        currentCut = cut;
        if (suggestState) {
          suggestState = {
            ...suggestState,
            suggestions: suggestState.suggestions.filter((s) => s.glob !== glob),
          };
        }
        render();
      }
      break;
    }
    case "suggest-accept-all": {
      if (!suggestState || suggestState.suggestions.length === 0) break;
      const rules = suggestState.suggestions;
      const cut = await withBusy(() => suggestApply(rules));
      if (cut) {
        currentCut = cut;
        suggestState = null;
        render();
      }
      break;
    }
    case "broaden": {
      const row = el.closest<HTMLLIElement>(".file-row");
      const path = row?.dataset.path;
      const input = row?.querySelector<HTMLInputElement>(".glob");
      if (path && input) input.value = broadenedGlob(path);
      break;
    }
    case "reclassify": {
      const row = el.closest<HTMLLIElement>(".file-row");
      const input = row?.querySelector<HTMLInputElement>(".glob");
      const select = row?.querySelector<HTMLSelectElement>(".bucket-select");
      if (!input || !select || !input.value.trim()) break;
      const cut = await withBusy(() => reclassify(input.value.trim(), select.value));
      if (cut) {
        currentCut = cut;
        render();
      }
      break;
    }
    case "toggle-target-form": {
      showTargetForm = !showTargetForm;
      render();
      break;
    }
    case "set-range": {
      const form = el.closest<HTMLElement>(".target-form");
      const base = form?.querySelector<HTMLInputElement>(".target-base")?.value.trim();
      const head = form?.querySelector<HTMLInputElement>(".target-head")?.value.trim();
      if (!base || !head) break;
      const cut = await withBusy(() => setRange(base, head));
      if (cut) {
        currentCut = cut;
        showTargetForm = false;
        suggestState = null;
        lastRun = null;
        applyResult = null;
        rollbackResult = null;
        showApplyConfirm = false;
        render();
      }
      break;
    }
    case "set-pr": {
      const form = el.closest<HTMLElement>(".target-form");
      const ref = form?.querySelector<HTMLInputElement>(".target-pr")?.value.trim();
      if (!ref) break;
      const cut = await withBusy(() => setPr(ref));
      if (cut) {
        currentCut = cut;
        showTargetForm = false;
        suggestState = null;
        lastRun = null;
        applyResult = null;
        rollbackResult = null;
        showApplyConfirm = false;
        render();
      }
      break;
    }
    case "set-size-cap": {
      const toolbar = el.closest<HTMLElement>(".toolbar");
      const raw = toolbar?.querySelector<HTMLInputElement>(".size-cap-input")?.value.trim() ?? "";
      const sizeCap = raw === "" ? null : Number(raw);
      if (sizeCap !== null && (!Number.isInteger(sizeCap) || sizeCap <= 0)) {
        errorMessage = "size cap must be a positive integer";
        render();
        break;
      }
      const cut = await withBusy(() => setSizeCap(sizeCap));
      if (cut) {
        currentCut = cut;
        render();
      }
      break;
    }
    case "close-explain": {
      explainCut = null;
      render();
      break;
    }
    case "generate-restack": {
      const panel = el.closest<HTMLElement>(".restack-panel");
      const describe = panel?.querySelector<HTMLInputElement>(".restack-describe")?.checked ?? false;
      const force = panel?.querySelector<HTMLInputElement>(".restack-force")?.checked ?? false;
      const targetRaw = panel?.querySelector<HTMLSelectElement>(".restack-target")?.value ?? "";
      const target = targetRaw === "" ? undefined : (targetRaw as PartTarget);
      const result = await withBusy(() => restack({ describe, force, target }));
      if (result) {
        lastRun = result;
        applyResult = null;
        rollbackResult = null;
        showApplyConfirm = false;
        render();
      }
      break;
    }
    case "download-restack": {
      if (!lastRun) break;
      downloadBlob("restack.sh", lastRun.script_text, "text/x-shellscript");
      break;
    }
    case "download-cutlist": {
      if (!lastRun) break;
      downloadBlob("cutlist.json", JSON.stringify(lastRun.cutlist, null, 2), "application/json");
      break;
    }
    case "open-apply-confirm": {
      showApplyConfirm = true;
      render();
      break;
    }
    case "cancel-apply": {
      showApplyConfirm = false;
      render();
      break;
    }
    case "confirm-apply": {
      if (!lastRun) break;
      showApplyConfirm = false;
      const result = await withBusy(() => applyRestack(lastRun!.apply_token));
      if (result) {
        applyResult = result;
      }
      render();
      break;
    }
    case "rollback": {
      const result = await withBusy(() => rollbackRestack());
      if (result) {
        rollbackResult = result;
      }
      render();
      break;
    }
    default:
      break;
  }
}

function downloadBlob(filename: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

async function loadExplainFile(file: File): Promise<void> {
  try {
    const parsed = JSON.parse(await file.text());
    if (!parsed || !Array.isArray(parsed.parts)) {
      throw new Error("not a valid cutlist.json (missing 'parts')");
    }
    errorMessage = null;
    explainCut = parsed as CutList;
  } catch (err) {
    errorMessage = `failed to load cutlist.json: ${(err as Error).message}`;
  }
  render();
}

function attachHandlers(root: HTMLElement): void {
  root.addEventListener("click", (event) => {
    const el = (event.target as HTMLElement).closest<HTMLElement>("[data-action]");
    if (!el) return;
    void handleAction(el.dataset.action ?? "", el);
  });
  root.addEventListener("change", (event) => {
    const el = event.target as HTMLElement;
    if (el instanceof HTMLInputElement && el.classList.contains("explain-file-input")) {
      const file = el.files?.[0];
      if (file) void loadExplainFile(file);
    }
  });
}

export async function main(): Promise<void> {
  const root = document.getElementById("app");
  if (!root) return;
  attachHandlers(root);
  root.textContent = "loading…";
  try {
    currentCut = await fetchCutlist();
    render();
  } catch (err) {
    root.textContent = `failed to load cut list: ${(err as Error).message}`;
  }
}

void main();
