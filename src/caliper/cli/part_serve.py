"""``caliper part --serve`` — a localhost reclassify sidecar (the feedback loop).

# tested-by: tests/unit/test_part_serve.py

A second presentation-tier entry point (parallel to ``part_cmd``): it serves the
live cut list as HTML on loopback, and lets a reviewer reclassify a file from the
browser. A reclassification writes a version-controlled glob→bucket override into
``.caliper.yaml`` and re-parts — no ML, no verdict. The override table is the one
human decision point in the otherwise deterministic classifier (see
``OverrideRule`` / ``_classify``).

Design:

* ``write_override`` is the only mutation — a deterministic, idempotent write-back
  into ``.caliper.yaml``, validated through ``PartingConfig`` before it touches
  disk so a bad bucket never corrupts the file.
* ``PartingSession`` holds the repo/base/head and owns the re-part (git IO).
* ``dispatch`` is the pure request router (functional core) over a session —
  testable with a fake session, no git and no socket required.

Transport is **stdlib ``http.server`` only** — no uvicorn/starlette, so the
sidecar works from any install (it does not need the ``caliper[copilot]`` extra).
The ``BaseHTTPRequestHandler`` is the thin imperative shell around ``dispatch``.

Loopback only: the server binds ``127.0.0.1`` so the unauthenticated write
endpoint is never exposed off-host. ``.caliper.yaml`` is a committed file here, so
writing it is intended — not a dirty-tree violation.
"""

# ruff: noqa: E501 — the inline CSS/HTML/JS in render_report is intentionally long
# (mirrors scripts/cutlist_report.py); reflowing template lines hurts readability.

from __future__ import annotations

import html
import http.server
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import orjson
import structlog
import yaml

from caliper.core.registries import PARTING
from caliper.core.repo_config import OverrideRule, PartingConfig, load_repo_config

if TYPE_CHECKING:
    from caliper.core.models import CutList

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
        base: str,
        head: str,
        *,
        size_cap: int | None = None,
        override_store: Path | None = None,
    ) -> None:
        self.repo_path = repo_path
        self.base = base
        self.head = head
        self.size_cap = size_cap  # CLI --size-cap override; None => use the repo config
        # Where reviewer reclassifications are persisted. For --pr this is a durable
        # sidecar dir OUTSIDE the throwaway clone, so overrides survive the clone
        # wipe; for a normal repo it is None and writes land in the repo's own config.
        self.override_store = override_store
        self._cut: CutList | None = None

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
        if self._cut is None:
            self._cut = self._cut_now()
        return self._cut

    def repart(self) -> CutList:
        self._cut = self._cut_now()
        return self._cut

    def cut_dict(self) -> dict:
        return self.cut().model_dump(mode="json")

    def repart_dict(self) -> dict:
        return self.repart().model_dump(mode="json")

    def reclassify(self, *, target: str, bucket: str, note: str = "") -> dict:
        # Write to the durable store (sidecar for --pr, else the repo's own config)
        # so a throwaway PR clone never swallows the reviewer's reclassification.
        write_override(self._write_target, glob=target, bucket=bucket, note=note)
        return self.repart_dict()

    def overrides(self) -> list[dict]:
        """The active (merged) override table, for the report's badge panel."""
        return [o.model_dump(mode="json") for o in self._effective_cfg().overrides]


# --------------------------------------------------------------------------- #
# HTML — live reclassify report
# --------------------------------------------------------------------------- #

# The bucket the residual lands in — rendered with a distinct "needs a tier" cue.
_UNTIERED = "logic"

# Buckets a reviewer may assign. Structural facts (move/delete/binary) come from
# git, not reclassification, so they are excluded; the rest of ChangeType is
# offered, ordered tiers → intent → residual for a sensible dropdown.
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

# Per-bucket accent hue (HSL hue; CSS supplies sat/lum). Unknown → slate fallback.
_BUCKET_HUE: dict[str, int] = {
    "frontend": 280,
    "business": 213,
    "data": 190,
    "infra": 25,
    "documentation": 150,
    "supply_chain": 320,
    "ci_cd": 90,
    "security_policy": 0,
    "config": 198,
    "schema_contracts": 260,
    "test": 152,
    "generated": 38,
    "logic": 45,
    "binary": 220,
    "move": 220,
    "delete": 0,
}


def _suggest_glob(path: str) -> str:
    """Suggest a broadening glob for *path*: ``<dir>/**`` if nested, else the path."""
    if "/" in path:
        return path.rsplit("/", 1)[0] + "/**"
    return path


def _bucket_options(selected: str) -> str:
    """``<option>`` list for the reclassify dropdown, marking *selected*."""
    out = []
    for b in _SELECTABLE_BUCKETS:
        mark = " selected" if b == selected else ""
        out.append(f'<option value="{b}"{mark}>{b}</option>')
    return "".join(out)


def _file_row(path: str, current_bucket: str) -> str:
    """One reclassifiable file: path, a glob input (pre-filled), and a bucket select."""
    esc = html.escape(path)
    suggest = html.escape(_suggest_glob(path))
    return (
        f'<li class="file"><code class="path">{esc}</code>'
        f'<input class="glob" value="{esc}" data-suggest="{suggest}" '
        f'title="glob to write (a file path matches itself); use the ⤢ button to broaden">'
        f'<button class="broaden" type="button" title="broaden to {suggest}">⤢</button>'
        f'<select class="bucket">{_bucket_options(current_bucket)}</select>'
        f'<button class="save" type="button">reclassify</button></li>'
    )


def render_report(cut: dict, overrides: list[dict] | None = None) -> str:
    """Render the live reclassify report as a self-contained HTML page.

    Defensive on shape (every field via ``.get``) so a partial cut still renders.
    The page is dependency-free: inline CSS + vanilla JS that POSTs to
    ``/reclassify`` and ``/repart`` and reloads on success.
    """
    overrides = overrides or []
    prov = cut.get("provenance", {})
    stats = cut.get("stats", {})
    parts = cut.get("parts", [])
    digest = str(prov.get("config_digest", ""))[:12] or "—"
    base = str(prov.get("base_sha", ""))[:9] or "—"
    head = str(prov.get("head_sha", ""))[:9] or "—"

    cards: list[str] = []
    for i, part in enumerate(parts, start=1):
        bucket = str(part.get("bucket", "?"))
        files = part.get("files", [])
        hue = _BUCKET_HUE.get(bucket, 220)
        untiered = bucket == _UNTIERED
        flag = '<span class="untiered-tag">needs a tier</span>' if untiered else ""
        rows = "".join(_file_row(str(f), bucket) for f in files)
        cards.append(
            f'<article class="part{" untiered" if untiered else ""}" style="--hue:{hue}">'
            f'<h3><span class="idx">{i}</span>'
            f'<span class="badge">{html.escape(bucket)}</span>{flag}'
            f'<small>{len(files)} file{"s" if len(files) != 1 else ""} · size {part.get("size", 0)}'
            f'{" · oversized" if part.get("oversized") else ""}</small></h3>'
            f'<ul class="files">{rows}</ul></article>'
        )

    if overrides:
        badges = "".join(
            f'<span class="ov"><code>{html.escape(str(o.get("glob", "")))}</code>'
            f'→ <b>{html.escape(str(o.get("bucket", "")))}</b></span>'
            for o in overrides
        )
        ov_panel = f'<div class="overrides"><h2>active overrides</h2>{badges}</div>'
    else:
        ov_panel = '<div class="overrides empty">no overrides yet — reclassify a file below</div>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>caliper part · {base}→{head}</title>
<style>
:root{{--bg:#0d1117;--surface:#161b22;--surface2:#1c2330;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#2f81f7;--warn:#d29922;}}
*{{box-sizing:border-box;}}
body{{font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  margin:0;background:var(--bg);color:var(--text);padding:24px;max-width:1100px;margin:0 auto;}}
h1{{font-size:20px;margin:0 0 4px;}} h2{{font-size:13px;text-transform:uppercase;
  letter-spacing:.05em;color:var(--muted);margin:0 0 8px;}}
.sub{{color:var(--muted);font-size:13px;}}
.toolbar{{display:flex;gap:10px;align-items:center;margin:16px 0;}}
button.repart{{background:var(--accent);color:#fff;border:0;border-radius:8px;
  padding:9px 16px;font-size:14px;cursor:pointer;}}
.overrides{{background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:12px 14px;margin:12px 0;}}
.overrides.empty{{color:var(--muted);font-size:13px;}}
.ov{{display:inline-flex;gap:4px;align-items:center;background:var(--surface2);
  border:1px solid var(--border);border-radius:999px;padding:3px 10px;margin:3px;font-size:12px;}}
.part{{background:var(--surface);border:1px solid var(--border);
  border-left:4px solid hsl(var(--hue) 70% 55%);border-radius:10px;padding:14px 16px;margin:12px 0;}}
.part.untiered{{border-left-color:var(--warn);background:color-mix(in srgb,var(--warn) 7%,var(--surface));}}
.part h3{{margin:0 0 10px;font-size:15px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}}
.idx{{color:var(--muted);font-variant-numeric:tabular-nums;}}
.badge{{background:hsl(var(--hue) 70% 50%);color:#fff;padding:2px 9px;border-radius:999px;font-size:12px;}}
.untiered-tag{{background:var(--warn);color:#1c1300;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;}}
small{{color:var(--muted);font-weight:400;}}
ul.files{{list-style:none;margin:0;padding:0;}}
li.file{{display:flex;gap:8px;align-items:center;padding:5px 0;border-bottom:1px dashed var(--border);flex-wrap:wrap;}}
li.file:last-child{{border-bottom:0;}}
.path{{flex:1;min-width:200px;font-family:ui-monospace,monospace;font-size:12.5px;word-break:break-all;}}
.glob{{width:240px;background:var(--bg);color:var(--text);border:1px solid var(--border);
  border-radius:6px;padding:5px 8px;font-family:ui-monospace,monospace;font-size:12px;}}
.bucket{{background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:5px 8px;font-size:12.5px;}}
.broaden,.save{{background:var(--surface2);color:var(--text);border:1px solid var(--border);
  border-radius:6px;padding:5px 9px;font-size:12px;cursor:pointer;}}
.save{{background:var(--accent);color:#fff;border-color:transparent;}}
footer{{color:var(--muted);font-size:12px;margin-top:28px;}}
</style></head><body>
<header>
  <h1>caliper cut list</h1>
  <div class="sub">{stats.get("part_count", len(parts))} parts · {stats.get("file_count", "?")} files · {base} → {head}</div>
</header>
<div class="toolbar"><button class="repart" type="button" onclick="repart()">re-part</button>
  <span class="sub">reclassify any file to write a version-controlled override into <code>.caliper.yaml</code></span></div>
{ov_panel}
{"".join(cards)}
<footer>config digest <code>{html.escape(digest)}</code> · loopback sidecar · caliper part --serve</footer>
<script>
async function post(url, body) {{
  const r = await fetch(url, {{method:'POST', headers:{{'Content-Type':'application/json'}},
    body: body ? JSON.stringify(body) : null}});
  if (!r.ok) {{ let m=''; try {{ m=(await r.json()).error || ''; }} catch(e){{}} throw new Error(m || ('HTTP '+r.status)); }}
  return r.json();
}}
function repart() {{ post('/repart').then(()=>location.reload()).catch(e=>alert('re-part failed: '+e.message)); }}
document.querySelectorAll('li.file').forEach(li => {{
  const glob = li.querySelector('.glob');
  li.querySelector('.broaden').addEventListener('click', () => {{ glob.value = glob.dataset.suggest; }});
  li.querySelector('.save').addEventListener('click', () => {{
    const bucket = li.querySelector('.bucket').value;
    post('/reclassify', {{glob: glob.value, bucket}})
      .then(()=>location.reload())
      .catch(e=>alert('reclassify failed: '+e.message));
  }});
}});
</script>
</body></html>"""


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


def dispatch(session: _SessionLike, method: str, path: str, body: bytes) -> Response:
    """Route one request against *session*. Pure: no IO, no socket — fully testable."""
    if method == "GET" and path == "/":
        html_doc = render_report(session.cut_dict(), session.overrides())
        return Response(200, "text/html; charset=utf-8", html_doc.encode("utf-8"))
    if method == "GET" and path == "/cutlist":
        return _json(session.cut_dict())
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
        return _json(cut)
    if method == "POST" and path == "/repart":
        return _json(session.repart_dict())
    return _json({"error": "not found"}, 404)


def _make_handler(session: _SessionLike) -> type[http.server.BaseHTTPRequestHandler]:
    """Build a request handler bound to *session* (closure, no mutable class state)."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _serve(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            payload = self.rfile.read(length) if length > 0 else b""
            path = self.path.split("?", 1)[0]  # ignore any query string
            resp = dispatch(session, method, path, payload)
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
    base: str,
    head: str,
    *,
    port: int = DEFAULT_PORT,
    size_cap: int | None = None,
    override_store: Path | None = None,
) -> None:
    """Run the sidecar on loopback. Blocks until interrupted (presentation tier)."""
    session = PartingSession(
        repo_path, base, head, size_cap=size_cap, override_store=override_store
    )
    server, bound = _bind_server(_make_handler(session), port)
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
