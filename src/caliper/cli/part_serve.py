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
* ``build_part_serve_app`` is a thin Starlette adapter over a session — testable
  with a fake session, no git required.

Loopback only: the server binds ``127.0.0.1`` so the unauthenticated write
endpoint is never exposed off-host. ``.caliper.yaml`` is a committed file here, so
writing it is intended — not a dirty-tree violation.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

import structlog
import yaml

from caliper.core.registries import PARTING
from caliper.core.repo_config import PartingConfig, load_repo_config

if TYPE_CHECKING:
    from starlette.applications import Starlette

    from caliper.core.models import CutList

logger = structlog.get_logger()

# Loopback only — the reclassify endpoint writes config without auth, so it must
# never bind a routable interface. In the dev port range (12000–13000); avoids the
# webhook (12800) and postgres (12432).
HOST = "127.0.0.1"
DEFAULT_PORT = 12700

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

    config_path.write_text(yaml.safe_dump(data, sort_keys=False))
    logger.info("parting_override_written", glob=glob, bucket=bucket, path=str(config_path))


# --------------------------------------------------------------------------- #
# Session — owns the re-part (git IO)
# --------------------------------------------------------------------------- #


class _SessionLike(Protocol):
    def cut_dict(self) -> dict: ...
    def repart_dict(self) -> dict: ...
    def reclassify(self, *, target: str, bucket: str, note: str = "") -> dict: ...


class PartingSession:
    """Holds the parting target and re-parts on demand, reloading config each time."""

    def __init__(self, repo_path: Path, base: str, head: str) -> None:
        self.repo_path = repo_path
        self.base = base
        self.head = head
        self._cut: CutList | None = None

    def _cut_now(self) -> CutList:
        cfg = load_repo_config(self.repo_path).parting
        # Import triggers the parting plugin's @PARTING.register side effect.
        import caliper.plugins._parting  # noqa: F401

        outcome = PARTING.create("parting").cut(self.repo_path, self.base, self.head, cfg)
        return outcome.cutlist

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
        write_override(self.repo_path, glob=target, bucket=bucket, note=note)
        return self.repart_dict()


# --------------------------------------------------------------------------- #
# HTML — minimal live report (Slice 5 enriches this)
# --------------------------------------------------------------------------- #


def render_report(cut: dict) -> str:
    """Render the cut list as a self-contained HTML page. Defensive on shape."""
    prov = cut.get("provenance", {})
    stats = cut.get("stats", {})
    parts = cut.get("parts", [])
    digest = str(prov.get("config_digest", ""))[:12] or "—"
    base = str(prov.get("base_sha", ""))[:9] or "—"
    head = str(prov.get("head_sha", ""))[:9] or "—"

    rows: list[str] = []
    for i, part in enumerate(parts, start=1):
        bucket = html.escape(str(part.get("bucket", "?")))
        files = part.get("files", [])
        file_lines = "".join(f"<li>{html.escape(str(f))}</li>" for f in files)
        rows.append(
            f'<article class="part"><h3>{i}. <span class="badge">{bucket}</span> '
            f'<small>{len(files)} files · size {part.get("size", 0)}</small></h3>'
            f"<ul>{file_lines}</ul></article>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>caliper part · {base}→{head}</title>
<style>
body{{font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  margin:0;background:#0d1117;color:#e6edf3;padding:24px;}}
h1{{font-size:20px;}} .badge{{background:#1f6feb;color:#fff;padding:2px 8px;
  border-radius:999px;font-size:12px;}}
.part{{background:#161b22;border:1px solid #30363d;border-radius:10px;
  padding:14px 16px;margin:12px 0;}}
.part h3{{margin:0 0 8px;font-size:15px;}} ul{{margin:0;padding-left:18px;}}
li{{font-family:ui-monospace,monospace;font-size:12.5px;color:#8b949e;}}
small{{color:#8b949e;font-weight:400;}}
footer{{color:#8b949e;font-size:12px;margin-top:24px;}}
</style></head><body>
<h1>caliper cut list <small>{base} → {head}</small></h1>
<p>{stats.get("part_count", len(parts))} parts · {stats.get("file_count", "?")} files</p>
{"".join(rows)}
<footer>config digest <code>{html.escape(digest)}</code></footer>
</body></html>"""


# --------------------------------------------------------------------------- #
# Starlette app — thin adapter over a session
# --------------------------------------------------------------------------- #


def _require_starlette() -> Any:
    """Import starlette lazily so the pure write-back stays importable without it."""
    try:
        import starlette.applications
        import starlette.requests  # noqa: F401
        import starlette.responses
        import starlette.routing

        return starlette
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "starlette is required for `caliper part --serve`. Install it via caliper[copilot]."
        ) from exc


def build_part_serve_app(session: _SessionLike) -> Starlette:
    """Construct the Starlette app over *session*. No git here — testable directly."""
    starlette = _require_starlette()
    responses = starlette.responses

    async def index(_request: Any) -> Any:
        return responses.HTMLResponse(render_report(session.cut_dict()))

    async def cutlist(_request: Any) -> Any:
        return responses.JSONResponse(session.cut_dict())

    async def reclassify(request: Any) -> Any:
        try:
            body = await request.json()
        except Exception:
            return responses.JSONResponse({"error": "invalid JSON body"}, status_code=400)
        target = body.get("glob") or body.get("file")
        bucket = body.get("bucket")
        if not target or not bucket:
            return responses.JSONResponse(
                {"error": "both a target (file or glob) and a bucket are required"},
                status_code=400,
            )
        try:
            cut = session.reclassify(target=target, bucket=bucket, note=body.get("note", ""))
        except Exception as exc:  # validation / write errors are reviewer-facing, not 500s
            logger.info("parting_reclassify_rejected", error=str(exc))
            return responses.JSONResponse({"error": str(exc)}, status_code=400)
        return responses.JSONResponse(cut)

    async def repart(_request: Any) -> Any:
        return responses.JSONResponse(session.repart_dict())

    route = starlette.routing.Route
    return starlette.applications.Starlette(
        routes=[
            route("/", index, methods=["GET"]),
            route("/cutlist", cutlist, methods=["GET"]),
            route("/reclassify", reclassify, methods=["POST"]),
            route("/repart", repart, methods=["POST"]),
        ]
    )


def serve_part(repo_path: Path, base: str, head: str, *, port: int = DEFAULT_PORT) -> None:
    """Run the sidecar on loopback. Blocks until interrupted (presentation tier)."""
    import uvicorn

    session = PartingSession(repo_path, base, head)
    app = build_part_serve_app(session)
    logger.info("part_serve_starting", host=HOST, port=port, base=base, head=head)
    uvicorn.run(app, host=HOST, port=port, log_level="warning")
