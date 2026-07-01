"""``caliper part --serve`` — a localhost reclassify sidecar (the feedback loop).

# tested-by: tests/unit/test_part_serve.py

A second presentation-tier entry point (parallel to ``part_cmd``): it serves a
TypeScript SPA (``scripts/part_ui/`` -> committed bundle under
``part_ui_dist/``) that renders the live cut list and lets a reviewer
reclassify a file from the browser. A reclassification writes a
version-controlled glob→bucket override into ``.caliper.yaml`` and re-parts —
no ML, no verdict. The override table is the one human decision point in the
otherwise deterministic classifier (see ``OverrideRule`` / ``_classify``).

Design:

* ``write_override`` is the only mutation — a deterministic, idempotent write-back
  into ``.caliper.yaml``, validated through ``PartingConfig`` before it touches
  disk so a bad bucket never corrupts the file.
* ``PartingSession`` holds the repo/base/head and owns the re-part (git IO).
* ``dispatch`` is the pure request router (functional core) over a session —
  testable with a fake session and a hand-built ``Assets`` fixture, no git, no
  filesystem, and no socket required.
* ``load_assets`` is the one piece of filesystem IO — reading the committed SPA
  bundle off disk — kept out of ``dispatch`` so the router stays pure.

Transport is **stdlib ``http.server`` only** — no uvicorn/starlette, so the
sidecar works from any install (it does not need the ``caliper[copilot]`` extra).
The ``BaseHTTPRequestHandler`` is the thin imperative shell around ``dispatch``.

Loopback only: the server binds ``127.0.0.1`` so the unauthenticated write
endpoint is never exposed off-host. ``.caliper.yaml`` is a committed file here, so
writing it is intended — not a dirty-tree violation.
"""

from __future__ import annotations

import hmac
import http.server
import os
import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import orjson
import structlog
import yaml

from caliper.core.registries import PARTING
from caliper.core.repo_config import OverrideRule, PartingConfig, load_repo_config

if TYPE_CHECKING:
    from caliper.cli.part_pipeline import PartRunResult
    from caliper.core.models import CutList
    from caliper.core.tier_suggester import TierSuggesterPort
    from caliper.core.tool_runner import ToolRunnerPort

logger = structlog.get_logger()

# Loopback only — the reclassify endpoint writes config without auth, so it must
# never bind a routable interface. In the dev port range (12000–13000); avoids the
# webhook (12800) and postgres (12432).
HOST = "127.0.0.1"
DEFAULT_PORT = 12700
# Fallback search space when the preferred port is busy. Dev ports only
# (CLAUDE.md: 12000–13000, never common ports) so the sidecar always lands in
# the sanctioned range no matter which one it ends up on.
_DEV_PORTS = range(12000, 13000)

_CONFIG_FILENAME = ".caliper.yaml"


# --------------------------------------------------------------------------- #
# write_override — the deterministic .caliper.yaml write-back
# --------------------------------------------------------------------------- #


def write_override(repo_path: Path, *, glob: str, bucket: str, note: str = "") -> None:
    """Add or update a ``parting.overrides`` rule in ``<repo>/.caliper.yaml``.

    First-match-wins is decided at classification time; here the contract is
    idempotency: an existing rule for the same ``glob`` is updated in place (never
    duplicated), so applying the same reclassification twice equals once. The
    merged parting block is validated through ``PartingConfig`` *before* the file
    is written, so a structural/unknown bucket raises and the on-disk file — and
    any pre-existing valid overrides — are left untouched.
    """
    config_path = repo_path / _CONFIG_FILENAME
    data: dict = {}
    if config_path.exists():
        data = yaml.safe_load(config_path.read_text()) or {}

    parting = data.setdefault("parting", {})
    overrides: list[dict] = parting.setdefault("overrides", [])

    for rule in overrides:
        if rule.get("glob") == glob:
            rule["bucket"] = bucket
            if note:
                rule["note"] = note
            break
    else:
        entry: dict = {"glob": glob, "bucket": bucket}
        if note:
            entry["note"] = note
        overrides.append(entry)

    # Validate before writing — raises ValueError/ValidationError on a structural or
    # unknown bucket, or a duplicate glob, so disk is never left in a bad state.
    PartingConfig.model_validate(parting)

    # The store may be a brand-new sidecar dir (the --pr override store), so create
    # its parent before the first write rather than assuming it already exists.
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.safe_dump(data, sort_keys=False))
    logger.info("parting_override_written", glob=glob, bucket=bucket, path=str(config_path))


# --------------------------------------------------------------------------- #
# Session — owns the re-part (git IO)
# --------------------------------------------------------------------------- #


class _SessionLike(Protocol):
    def cut_dict(self) -> dict: ...
    def repart_dict(self) -> dict: ...
    def reclassify(self, *, target: str, bucket: str, note: str = "") -> dict: ...
    def overrides(self) -> list[dict]: ...
    def suggest_dict(self) -> dict: ...
    def suggest_apply(self, rules: list[dict]) -> dict: ...
    def retarget(self, *, base: str, head: str) -> dict: ...
    def set_target_pr(self, ref: str) -> dict: ...
    def set_size_cap(self, size_cap: int | None) -> dict: ...
    def generate(
        self, *, describe: bool = False, force: bool = False, target: str | None = None
    ) -> dict: ...
    def restack_script(self) -> str | None: ...
    def apply(self, token: str) -> dict: ...
    def rollback(self) -> dict: ...


def _apply_size_cap(cfg: PartingConfig, size_cap: int | None) -> PartingConfig:
    """Apply a CLI --size-cap override onto the loaded config (pure). None = leave as-is."""
    if size_cap is None:
        return cfg
    return cfg.model_copy(update={"size_cap": size_cap})


def _merge_overrides(base: list[OverrideRule], extra: list[OverrideRule]) -> list[OverrideRule]:
    """Layer ``extra`` (the reviewer's sidecar store) over ``base`` (the repo's
    committed overrides), keyed by glob — the sidecar wins per glob, base order is
    preserved, and new sidecar rules are appended. Deduping by glob keeps the
    result valid (PartingConfig rejects duplicate globs)."""
    by_glob = {r.glob: r for r in base}
    for r in extra:
        by_glob[r.glob] = r
    ordered: list[OverrideRule] = []
    seen: set[str] = set()
    for r in base:
        ordered.append(by_glob[r.glob])
        seen.add(r.glob)
    for r in extra:
        if r.glob not in seen:
            ordered.append(r)
            seen.add(r.glob)
    return ordered


class PartingSession:
    """Holds the parting target and re-parts on demand, reloading config each time."""

    def __init__(
        self,
        repo_path: Path,
        base: str | None,
        head: str | None,
        *,
        size_cap: int | None = None,
        override_store: Path | None = None,
        suggester: TierSuggesterPort | None = None,
        out_dir: Path | None = None,
        runner: ToolRunnerPort | None = None,
    ) -> None:
        self.repo_path = repo_path
        self.base = base
        self.head = head
        self.size_cap = size_cap  # CLI --size-cap override; None => use the repo config
        # Advisory tier suggester (off the decision path). None disables /suggest; the
        # button then reports "no model configured". Fail-soft end to end.
        self._suggester = suggester
        # Where reviewer reclassifications are persisted. For --pr this is a durable
        # sidecar dir OUTSIDE the throwaway clone, so overrides survive the clone
        # wipe; for a normal repo it is None and writes land in the repo's own config.
        self.override_store = override_store
        # Where /restack writes restack.sh + cutlist.json. For --pr this is the
        # managed per-PR out dir (set on set_target_pr, mirroring override_store);
        # for a normal repo it is None and artifacts land in the repo root, same
        # default as the CLI's `--out`-less run.
        self.out_dir = out_dir
        # Injected for tests; None means apply()/rollback() build a real
        # SubprocessToolRunner lazily, mirroring run_part()'s own default.
        self._runner = runner
        self._cut: CutList | None = None
        self._last_run: PartRunResult | None = None
        self._apply_token: str | None = None
        # ThreadingHTTPServer serves each request on its own thread; the lock keeps
        # two concurrent requests from both running _cut_now (duplicate git IO) or
        # racing on the cached cut. RLock so a locked reclassify can call repart.
        self._lock = threading.RLock()

    @property
    def targeted(self) -> bool:
        """Whether a range or PR has been targeted yet (vs. the empty-start state)."""
        return bool(self.base and self.head)

    @property
    def _write_target(self) -> Path:
        """Directory whose .caliper.yaml receives reviewer overrides."""
        return self.override_store if self.override_store is not None else self.repo_path

    def _effective_cfg(self) -> PartingConfig:
        """The repo's parting config with the durable sidecar overrides layered on
        top and the CLI --size-cap applied — the single source of truth for both the
        cut and the badge panel."""
        cfg = load_repo_config(self.repo_path).parting
        if self.override_store is not None and (self.override_store / _CONFIG_FILENAME).exists():
            extra = load_repo_config(self.override_store).parting.overrides
            if extra:
                merged = _merge_overrides(cfg.overrides, extra)
                cfg = cfg.model_copy(update={"overrides": merged})
        return _apply_size_cap(cfg, self.size_cap)

    def _cut_now(self) -> CutList:
        cfg = self._effective_cfg()
        # Import triggers the parting plugin's @PARTING.register side effect.
        import caliper.plugins._parting  # noqa: F401

        outcome = PARTING.create("parting").cut(self.repo_path, self.base, self.head, cfg)
        cut = outcome.cutlist
        # Surface what cut was actually produced — the effective cap (so a --size-cap
        # that isn't taking effect is visible) and the resulting part/file counts.
        logger.info(
            "part_serve_cut",
            size_cap=cfg.size_cap,
            parts=cut.stats.part_count,
            files=cut.stats.file_count,
            overrides=len(cfg.overrides),
        )
        return cut

    def cut(self) -> CutList:
        with self._lock:
            if self._cut is None:
                self._cut = self._cut_now()
            return self._cut

    def repart(self) -> CutList:
        with self._lock:
            self._cut = self._cut_now()
            return self._cut

    def cut_dict(self) -> dict:
        if not self.targeted:
            return {"targeted": False}
        return self.cut().model_dump(mode="json")

    def repart_dict(self) -> dict:
        if not self.targeted:
            return {"targeted": False}
        return self.repart().model_dump(mode="json")

    def retarget(self, *, base: str, head: str) -> dict:
        """Point the session at a new base..head range in the current repo.

        Used by POST /range for the live-targeting empty-state prompt (P2) —
        distinct from set_target_pr, which also relocates repo_path to a
        throwaway clone.

        A bad revset must not wedge the session: GET /cutlist has no
        try/except around it (it's read-only, expected to always succeed once
        targeted), so a failed cut here that left ``base``/``head`` pointed at
        the bad values would crash every subsequent read until the reviewer
        guessed a valid range. Roll back on failure instead.

        Also invalidates any pending /restack apply token: a restack.sh
        generated for the old range must not be executable via /apply once
        the session points somewhere else (found by adversarial review —
        docs/reviews/adversarial-2026-06-30.md, P02-1).
        """
        with self._lock:
            prev_base, prev_head, prev_cut = self.base, self.head, self._cut
            prev_last_run, prev_apply_token = self._last_run, self._apply_token
            self.base = base
            self.head = head
            self._cut = None
            self._last_run = None
            self._apply_token = None
            try:
                return self.repart_dict()
            except Exception:
                self.base, self.head, self._cut = prev_base, prev_head, prev_cut
                self._last_run, self._apply_token = prev_last_run, prev_apply_token
                raise

    def set_size_cap(self, size_cap: int | None) -> dict:
        """Live-adjust the size cap and re-part — mirrors the CLI's --size-cap
        override (P3). Same rollback-on-failure shape as retarget/set_target_pr.

        Also invalidates any pending /restack apply token — see retarget()."""
        with self._lock:
            prev_size_cap, prev_cut = self.size_cap, self._cut
            prev_last_run, prev_apply_token = self._last_run, self._apply_token
            self.size_cap = size_cap
            self._cut = None
            self._last_run = None
            self._apply_token = None
            try:
                return self.repart_dict()
            except Exception:
                self.size_cap, self._cut = prev_size_cap, prev_cut
                self._last_run, self._apply_token = prev_last_run, prev_apply_token
                raise

    def set_target_pr(self, ref: str) -> dict:
        """Resolve a PR URL/number, clone it into the centralized XDG workdir,
        and point the session at its base..head — mirrors part_cmd.py's --pr
        handling so the web path behaves identically to the CLI."""
        from caliper.cli.part_pr import (
            PrResolveError,
            default_part_workdir,
            detect_origin_slug,
            resolve_pr,
        )
        from caliper.core.pr_ref import parse_pr_ref

        with self._lock:
            pr_ref = parse_pr_ref(ref, default_slug=detect_origin_slug(self.repo_path))
            try:
                resolved = resolve_pr(pr_ref, workdir_root=default_part_workdir())
            except PrResolveError as exc:
                raise ValueError(f"could not resolve PR: {exc}") from exc
            prev = (
                self.repo_path,
                self.base,
                self.head,
                self.override_store,
                self.out_dir,
                self._cut,
            )
            prev_last_run, prev_apply_token = self._last_run, self._apply_token
            self.repo_path = resolved.repo_path
            self.base = resolved.base
            self.head = resolved.head
            self.override_store = resolved.override_store
            self.out_dir = resolved.out_dir
            self._cut = None
            # Invalidate any pending /restack apply token — a script/rescue op
            # minted for the old repo_path must not be executable via /apply
            # once the session points at a different repo. See retarget().
            self._last_run = None
            self._apply_token = None
            try:
                result = self.repart_dict()
            except Exception:
                (
                    self.repo_path,
                    self.base,
                    self.head,
                    self.override_store,
                    self.out_dir,
                    self._cut,
                ) = prev
                self._last_run, self._apply_token = prev_last_run, prev_apply_token
                raise
            result["pr"] = {"slug": resolved.slug, "number": resolved.number}
            return result

    def reclassify(self, *, target: str, bucket: str, note: str = "") -> dict:
        # Write to the durable store (sidecar for --pr, else the repo's own config)
        # so a throwaway PR clone never swallows the reviewer's reclassification.
        # Hold the lock across write+repart so concurrent reclassifies don't
        # interleave the .caliper.yaml write with another request's re-part.
        with self._lock:
            write_override(self._write_target, glob=target, bucket=bucket, note=note)
            return self.repart_dict()

    def suggest_apply(self, rules: list[dict]) -> dict:
        """Bulk-accept: write every rule then re-part once (the "accept all" path).

        Mirrors ``part_cmd.py``'s ``--suggest-apply`` — each rule lands in the
        durable store individually (same idempotent write as a single
        reclassify), then one re-part reflects the whole batch. Held under the
        lock so a concurrent request never observes a partially-applied batch.
        """
        with self._lock:
            for rule in rules:
                write_override(
                    self._write_target,
                    glob=rule["glob"],
                    bucket=rule["bucket"],
                    note=rule.get("note", ""),
                )
            return self.repart_dict()

    def overrides(self) -> list[dict]:
        """The active (merged) override table, for the report's badge panel."""
        return [o.model_dump(mode="json") for o in self._effective_cfg().overrides]

    def suggest_dict(self) -> dict:
        """Advisory glob proposals for the current cut's 'logic' residual.

        Off the decision path: the model only authors globs; the deterministic core
        boundary validates them and a reviewer accepts one by POSTing /reclassify with
        the suggested glob+bucket. Returns ``{"suggestions": []}`` when no model is
        configured or the residual is empty — the cut is never touched here.
        """
        if self._suggester is None or not self.targeted:
            return {"suggestions": [], "configured": self._suggester is not None}
        from caliper.cli.part_suggest import suggest_overrides

        with self._lock:
            cut = self.cut()
            existing = self._effective_cfg().overrides
        rules = suggest_overrides(cut, self._suggester, existing_overrides=existing)
        return {
            "suggestions": [r.model_dump(mode="json") for r in rules],
            "configured": True,
        }

    def generate(
        self, *, describe: bool = False, force: bool = False, target: str | None = None
    ) -> dict:
        """Run the full parting pipeline (gate -> cut -> probe -> describe ->
        script) and cache the result + a fresh apply token — the web analog of
        the CLI's ``part`` (minus ``--suggest-apply``, handled separately via
        POST /suggest/apply). Raises ``ValueError`` on an untargeted session or
        a gate/parting failure; the dispatch layer turns that into a 400.
        """
        if not self.targeted:
            raise ValueError("no base/head targeted yet — POST /range or /pr first")

        from caliper.cli.part_describe import describer_from_env
        from caliper.cli.part_pipeline import run_part
        from caliper.core.models import PartTarget
        from caliper.core.part_gate import PartingGateError
        from caliper.core.parting import PartingError

        describer = describer_from_env(dict(os.environ), force=describe) if describe else None
        with self._lock:
            cfg = self._effective_cfg()
            if target is not None:
                cfg = cfg.model_copy(update={"target": PartTarget(target)})
            timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
            try:
                result = run_part(
                    self.repo_path,
                    self.base,
                    self.head,
                    cfg,
                    timestamp=timestamp,
                    force=force,
                    describer=describer,
                    suggester=self._suggester,
                    override_write_target=self.override_store,
                    out_dir=self.out_dir or self.repo_path,
                )
            except (PartingGateError, PartingError) as exc:
                raise ValueError(str(exc)) from exc
            self._last_run = result
            self._apply_token = secrets.token_urlsafe(16)
            payload = result.model_dump(mode="json")
            payload["apply_token"] = self._apply_token
            return payload

    def restack_script(self) -> str | None:
        """The last generated restack.sh text, or None before the first /restack."""
        return self._last_run.script_text if self._last_run is not None else None

    def apply(self, token: str) -> dict:
        """Execute the last-generated restack.sh (the jj surgery) via
        ToolRunnerPort. Requires the CSRF token minted by the most recent
        generate() call — checked with hmac.compare_digest (timing-safe) and
        consumed on use (success or failure) so it can never be replayed.
        Raises ValueError on a stale/missing token or an ungenerated script;
        the dispatch layer turns that into a 400.
        """
        from caliper.core.subprocess_runner import SubprocessToolRunner
        from caliper.core.tool_runner import ToolInvocation

        with self._lock:
            if self._apply_token is None or not hmac.compare_digest(token, self._apply_token):
                raise ValueError("invalid or expired apply token — POST /restack again")
            last_run = self._last_run
            if last_run is None or last_run.restack_path is None:
                raise ValueError("no restack script to apply — POST /restack first")
            self._apply_token = None
            runner = self._runner or SubprocessToolRunner()
            # restack_path may be relative to the server process's cwd (e.g. a
            # relative --out), not to repo_path — resolve before handing it to
            # a subprocess run with cwd=repo_path, or a relative --out 404s.
            script_path = str(Path(last_run.restack_path).resolve())
            result = runner.run(
                ToolInvocation(
                    cmd=["bash", script_path],
                    cwd=str(self.repo_path),
                    timeout=300,
                )
            )
            return {
                "ok": result.exit_code == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "rollback": {
                    "backup_bookmark": last_run.backup_bookmark,
                    "rescue_op_id": last_run.rescue_op_id,
                },
            }

    def rollback(self) -> dict:
        """Undo everything since the gate's rescue op via `jj op restore
        <rescue_op_id>` — the escape hatch surfaced in the rollback header.
        Available any time after a /restack (not gated on apply having run),
        since the reviewer may have applied by hand outside the browser.
        """
        from caliper.core.subprocess_runner import SubprocessToolRunner
        from caliper.core.tool_runner import ToolInvocation

        with self._lock:
            last_run = self._last_run
            if last_run is None:
                raise ValueError("nothing to roll back — POST /restack first")
            runner = self._runner or SubprocessToolRunner()
            result = runner.run(
                ToolInvocation(
                    cmd=["jj", "op", "restore", last_run.rescue_op_id],
                    cwd=str(self.repo_path),
                    timeout=60,
                )
            )
            return {
                "ok": result.exit_code == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }


# --------------------------------------------------------------------------- #
# HTML — live reclassify report
# --------------------------------------------------------------------------- #

# Buckets a reviewer may assign. Structural facts (move/delete/binary) come from
# git, not reclassification, so they are excluded; the rest of ChangeType is
# offered, ordered tiers → intent → residual for a sensible dropdown. This is the
# human dropdown — a superset of the model's legal output (core SELECTABLE_TIERS:
# same membership minus 'logic', which a human may pick to *un*-tier). The membership
# tie is drift-guarded in tests; the order here is curated for UX, not enum order.
#
# Mirrored in scripts/part_ui/types.ts as SELECTABLE_BUCKETS (same membership
# and order) — the TS SPA renders the reclassify dropdown from that copy, not
# from an endpoint, so the two lists are kept in sync by hand until a drift
# test lands. Per-bucket accent hues live in scripts/part_ui/styles.css
# ([data-bucket] -> --bucket-hue), not here — this module owns the bucket
# *list*, not presentation.
_SELECTABLE_BUCKETS: tuple[str, ...] = (
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
)


# --------------------------------------------------------------------------- #
# Assets — the committed TypeScript SPA bundle (scripts/part_ui -> build.ts)
# --------------------------------------------------------------------------- #

_ASSETS_DIRNAME = "part_ui_dist"


@dataclass(frozen=True)
class Assets:
    """The built SPA bundle: the HTML shell plus its JS/CSS, as raw bytes."""

    index_html: bytes
    js: bytes
    css: bytes


def load_assets(assets_dir: Path | None = None) -> Assets:
    """Read the committed bundle off disk (imperative shell — the only IO here).

    Defaults to ``part_ui_dist/`` next to this module, i.e. the bundle
    ``scripts/part_ui/build.ts`` writes to
    ``src/caliper/cli/part_ui_dist/``. Raises ``FileNotFoundError`` if the
    bundle hasn't been built — callers must fail loudly (see ``dispatch``'s
    500 on a missing ``assets``), never fall back to serving nothing.
    """
    directory = assets_dir if assets_dir is not None else Path(__file__).parent / _ASSETS_DIRNAME
    return Assets(
        index_html=(directory / "index.html").read_bytes(),
        js=(directory / "part_ui.js").read_bytes(),
        css=(directory / "part_ui.css").read_bytes(),
    )


# --------------------------------------------------------------------------- #
# HTTP transport — stdlib only (zero extra deps; works from any install)
# --------------------------------------------------------------------------- #
#
# The sidecar is loopback, single-reviewer, short-lived — it has no business
# pulling in uvicorn/starlette (the caliper[copilot] extra). The whole transport
# is Python's stdlib http.server. Routing is the pure `dispatch()` below
# (functional core) so it is exercised without ever binding a socket; the
# BaseHTTPRequestHandler is the thin imperative shell around it.


@dataclass(frozen=True)
class Response:
    """A rendered HTTP response: status + content type + raw body bytes."""

    status: int
    content_type: str
    body: bytes


def _json(payload: object, status: int = 200) -> Response:
    return Response(status, "application/json", orjson.dumps(payload))


def _with_overrides(session: _SessionLike, cut: dict) -> dict:
    """Merge the session's current override list into a cut payload.

    Every route that returns a cut (not just GET /cutlist) must carry this —
    the SPA's overrides panel re-renders from whatever the *last* response
    said, and a reclassify/repart/suggest-apply response that omitted the key
    made a successful write look like it silently did nothing.

    The untargeted sentinel (``{"targeted": False}``, no range/PR set yet)
    passes through bare — there is no cut to attach overrides to.
    """
    if cut.get("targeted") is False:
        return cut
    return {**cut, "overrides": session.overrides()}


_LOOPBACK_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1"})


def _hostname_of(header_value: str) -> str:
    """Bare hostname from a Host header (``127.0.0.1:12700``) or an Origin
    header (``http://127.0.0.1:12700``) — strips scheme, port, and path."""
    value = header_value.split("://", 1)[-1].split("/", 1)[0]
    if value.startswith("["):  # bracketed IPv6, e.g. "[::1]:12700"
        return value[1 : value.index("]")]
    return value.rsplit(":", 1)[0] if ":" in value else value


def _is_loopback_request(headers: Mapping[str, str] | None) -> bool:
    """Whether a request's Host (and, if present, Origin) both name loopback.

    Defense against a browser tab or DNS-rebinding attack POSTing to this
    loopback-bound sidecar: fails closed (missing/absent headers -> False),
    matching the plan's "reject requests whose Origin/Host is not loopback."
    """
    if headers is None:
        return False
    host = headers.get("host")
    if not host or _hostname_of(host) not in _LOOPBACK_HOSTNAMES:
        return False
    origin = headers.get("origin")
    return origin is None or _hostname_of(origin) in _LOOPBACK_HOSTNAMES


def dispatch(
    session: _SessionLike,
    method: str,
    path: str,
    body: bytes,
    assets: Assets | None = None,
    headers: Mapping[str, str] | None = None,
) -> Response:
    """Route one request against *session*. Pure: no IO, no socket — fully testable.

    *headers* is a plain lowercased-key mapping (``{"host": ..., "origin": ...}``)
    threaded in the same way as *assets* — the handler shell reads the real
    socket headers, dispatch only ever inspects plain data. Only ``/apply``
    consults it (the loopback/CSRF guard); every other route ignores it, so
    existing callers that omit it are unaffected.

    *assets* is the committed SPA bundle (``load_assets()``), threaded in as a
    plain-data argument rather than loaded here — that keeps dispatch itself
    filesystem-free and testable with a hand-built ``Assets`` fixture. ``None``
    means the caller hasn't loaded a bundle (e.g. a misconfigured install); the
    asset routes then fail loudly with 500 rather than serving a blank shell.
    """
    if method == "GET" and path == "/":
        if assets is None:
            return _json({"error": "static assets not loaded"}, 500)
        return Response(200, "text/html; charset=utf-8", assets.index_html)
    if method == "GET" and path == "/assets/part_ui.js":
        if assets is None:
            return _json({"error": "static assets not loaded"}, 500)
        return Response(200, "application/javascript; charset=utf-8", assets.js)
    if method == "GET" and path == "/assets/part_ui.css":
        if assets is None:
            return _json({"error": "static assets not loaded"}, 500)
        return Response(200, "text/css; charset=utf-8", assets.css)
    if method == "GET" and path == "/cutlist":
        return _json(_with_overrides(session, session.cut_dict()))
    if method == "POST" and path == "/reclassify":
        try:
            payload = orjson.loads(body or b"")
        except orjson.JSONDecodeError:
            return _json({"error": "invalid JSON body"}, 400)
        if not isinstance(payload, dict):
            return _json({"error": "invalid JSON body"}, 400)
        target = payload.get("glob") or payload.get("file")
        bucket = payload.get("bucket")
        if not target or not bucket:
            return _json({"error": "both a target (file or glob) and a bucket are required"}, 400)
        try:
            cut = session.reclassify(target=target, bucket=bucket, note=payload.get("note", ""))
        except Exception as exc:  # validation / write errors are reviewer-facing, not 500s
            logger.info("parting_reclassify_rejected", error=str(exc))
            return _json({"error": str(exc)}, 400)
        return _json(_with_overrides(session, cut))
    if method == "POST" and path == "/repart":
        if body:
            try:
                payload = orjson.loads(body)
            except orjson.JSONDecodeError:
                return _json({"error": "invalid JSON body"}, 400)
            if not isinstance(payload, dict):
                return _json({"error": "invalid JSON body"}, 400)
            if "size_cap" in payload:
                size_cap = payload["size_cap"]
                valid = size_cap is None or (
                    isinstance(size_cap, int) and not isinstance(size_cap, bool) and size_cap > 0
                )
                if not valid:
                    return _json({"error": "size_cap must be a positive integer or null"}, 400)
                try:
                    cut = session.set_size_cap(size_cap)
                except Exception as exc:  # live setting rejected -> reviewer-facing 400
                    return _json({"error": str(exc)}, 400)
                return _json(_with_overrides(session, cut))
        return _json(_with_overrides(session, session.repart_dict()))
    if method == "POST" and path == "/range":
        try:
            payload = orjson.loads(body or b"")
        except orjson.JSONDecodeError:
            return _json({"error": "invalid JSON body"}, 400)
        if not isinstance(payload, dict):
            return _json({"error": "invalid JSON body"}, 400)
        base = payload.get("base")
        head = payload.get("head")
        if not base or not head:
            return _json({"error": "both 'base' and 'head' are required"}, 400)
        try:
            cut = session.retarget(base=base, head=head)
        except Exception as exc:  # bad revsets etc. are reviewer-facing, not 500s
            logger.info("parting_retarget_rejected", error=str(exc))
            return _json({"error": str(exc)}, 400)
        return _json(_with_overrides(session, cut))
    if method == "POST" and path == "/pr":
        try:
            payload = orjson.loads(body or b"")
        except orjson.JSONDecodeError:
            return _json({"error": "invalid JSON body"}, 400)
        if not isinstance(payload, dict):
            return _json({"error": "invalid JSON body"}, 400)
        ref = payload.get("ref")
        if not ref:
            return _json({"error": "a 'ref' (PR URL or number) is required"}, 400)
        try:
            cut = session.set_target_pr(ref)
        except Exception as exc:  # unresolvable PR / clone failure -> 400, not 500
            logger.info("parting_pr_target_rejected", error=str(exc))
            return _json({"error": str(exc)}, 400)
        return _json(_with_overrides(session, cut))
    if method == "POST" and path == "/suggest":
        # Advisory: ask the local model for tier globs on the 'logic' residual. The
        # reviewer accepts one by POSTing /reclassify with the suggested glob+bucket;
        # nothing is written here. Fail-soft — the session swallows model errors to [].
        return _json(session.suggest_dict())
    if method == "POST" and path == "/suggest/apply":
        # Bulk-accept: the "accept all" button writes every proposed rule in one
        # request instead of one /reclassify round-trip per suggestion.
        try:
            payload = orjson.loads(body or b"")
        except orjson.JSONDecodeError:
            return _json({"error": "invalid JSON body"}, 400)
        if not isinstance(payload, dict):
            return _json({"error": "invalid JSON body"}, 400)
        rules = payload.get("globs")
        if not isinstance(rules, list) or not rules:
            return _json({"error": "a non-empty 'globs' list is required"}, 400)
        for rule in rules:
            if not isinstance(rule, dict) or not rule.get("glob") or not rule.get("bucket"):
                return _json({"error": "each rule needs a 'glob' and a 'bucket'"}, 400)
        try:
            cut = session.suggest_apply(rules)
        except Exception as exc:  # validation / write errors are reviewer-facing, not 500s
            logger.info("parting_suggest_apply_rejected", error=str(exc))
            return _json({"error": str(exc)}, 400)
        return _json(_with_overrides(session, cut))
    if method == "POST" and path == "/restack":
        payload: dict = {}
        if body:
            try:
                payload = orjson.loads(body)
            except orjson.JSONDecodeError:
                return _json({"error": "invalid JSON body"}, 400)
            if not isinstance(payload, dict):
                return _json({"error": "invalid JSON body"}, 400)
        describe = payload.get("describe", False)
        force = payload.get("force", False)
        target = payload.get("target")
        if not isinstance(describe, bool):
            return _json({"error": "'describe' must be a boolean"}, 400)
        if not isinstance(force, bool):
            return _json({"error": "'force' must be a boolean"}, 400)
        if target is not None and target not in ("stack", "series"):
            return _json({"error": "'target' must be 'stack' or 'series'"}, 400)
        try:
            result = session.generate(describe=describe, force=force, target=target)
        except Exception as exc:  # gate failure / untargeted session -> reviewer-facing 400
            logger.info("parting_restack_rejected", error=str(exc))
            return _json({"error": str(exc)}, 400)
        return _json(result)
    if method == "GET" and path == "/restack.sh":
        script = session.restack_script()
        if script is None:
            return _json({"error": "no restack script generated yet — POST /restack first"}, 404)
        return Response(200, "text/x-shellscript; charset=utf-8", script.encode())
    if method == "POST" and path == "/apply":
        if not _is_loopback_request(headers):
            return _json({"error": "request is not from loopback"}, 403)
        payload = {}
        if body:
            try:
                payload = orjson.loads(body)
            except orjson.JSONDecodeError:
                return _json({"error": "invalid JSON body"}, 400)
            if not isinstance(payload, dict):
                return _json({"error": "invalid JSON body"}, 400)
        token = payload.get("apply_token")
        if not isinstance(token, str) or not token:
            return _json({"error": "'apply_token' is required"}, 400)
        try:
            result = session.apply(token)
        except Exception as exc:  # bad/stale token, ungenerated script -> reviewer-facing 400
            logger.info("parting_apply_rejected", error=str(exc))
            return _json({"error": str(exc)}, 400)
        return _json(result)
    if method == "POST" and path == "/rollback":
        try:
            result = session.rollback()
        except Exception as exc:  # nothing to roll back yet -> reviewer-facing 400
            logger.info("parting_rollback_rejected", error=str(exc))
            return _json({"error": str(exc)}, 400)
        return _json(result)
    return _json({"error": "not found"}, 404)


def _make_handler(
    session: _SessionLike, assets: Assets | None = None
) -> type[http.server.BaseHTTPRequestHandler]:
    """Build a request handler bound to *session* (closure, no mutable class state)."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _serve(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            payload = self.rfile.read(length) if length > 0 else b""
            path = self.path.split("?", 1)[0]  # ignore any query string
            headers = {k.lower(): v for k, v in self.headers.items()}
            resp = dispatch(session, method, path, payload, assets, headers)
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.content_type)
            self.send_header("Content-Length", str(len(resp.body)))
            self.end_headers()
            self.wfile.write(resp.body)

        def do_GET(self) -> None:  # noqa: N802 - stdlib dispatch name
            self._serve("GET")

        def do_POST(self) -> None:  # noqa: N802 - stdlib dispatch name
            self._serve("POST")

        def log_message(self, fmt: str, *args: object) -> None:
            # Route http.server's stderr access log through structlog (debug only).
            logger.debug("part_serve_request", request=fmt % args)

    return _Handler


def _bind_server(
    handler_cls: type[http.server.BaseHTTPRequestHandler], preferred: int
) -> tuple[http.server.ThreadingHTTPServer, int]:
    """Bind on ``preferred``; if it's taken, fall back to the next free dev port.

    The only effect is the successful bind it returns — there is no
    bind-then-rebind race (we keep the first socket that binds). Tries the
    requested port first, then scans the 12000–13000 dev range so a busy 12700
    never kills the sidecar. Raises ``OSError`` only if the whole range is busy.
    """
    last_exc: OSError | None = None
    seen: set[int] = set()
    for port in (preferred, *_DEV_PORTS):
        if port in seen:
            continue
        seen.add(port)
        try:
            return http.server.ThreadingHTTPServer((HOST, port), handler_cls), port
        except OSError as exc:  # EADDRINUSE (and friends) — try the next candidate
            last_exc = exc
    raise OSError(
        f"no free port: {preferred} and the whole {_DEV_PORTS.start}-{_DEV_PORTS.stop - 1} "
        "dev range are all in use"
    ) from last_exc


def serve_part(
    repo_path: Path,
    base: str | None,
    head: str | None,
    *,
    port: int = DEFAULT_PORT,
    size_cap: int | None = None,
    override_store: Path | None = None,
    suggester: TierSuggesterPort | None = None,
    out_dir: Path | None = None,
) -> None:
    """Run the sidecar on loopback. Blocks until interrupted (presentation tier)."""
    session = PartingSession(
        repo_path,
        base,
        head,
        size_cap=size_cap,
        override_store=override_store,
        suggester=suggester,
        out_dir=out_dir,
    )
    # Load once at startup, not per-request — the bundle is immutable for the
    # life of the process; a missing bundle fails fast here rather than on the
    # first browser hit.
    assets = load_assets()
    server, bound = _bind_server(_make_handler(session, assets), port)
    url = f"http://{HOST}:{bound}"
    if bound != port:
        logger.warning("part_serve_port_busy", requested=port, using=bound, url=url)
    logger.info(
        "part_serve_starting",
        host=HOST,
        port=bound,
        base=base,
        head=head,
        size_cap=size_cap,
        override_store=str(override_store) if override_store else None,
        url=url,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # Ctrl-C is the intended way to stop the sidecar
        pass
    finally:
        server.server_close()
        logger.info("part_serve_stopped", url=url)
