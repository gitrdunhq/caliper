"""``caliper part --serve`` — the localhost reclassify sidecar (the feedback loop).

# tested-by: tests/unit/test_part_serve.py

A second presentation-tier entry point (parallel to ``part_cmd``): serves the
TypeScript SPA (``scripts/part_ui/`` -> committed bundle under
``part_ui_dist/``) that renders the live cut list and lets a reviewer
reclassify a file from the browser. Reclassification writes a
version-controlled glob→bucket override into ``.caliper.yaml`` and re-parts —
no ML, no verdict. The override table is the one human decision point in an
otherwise deterministic classifier (see ``OverrideRule`` / ``_classify``).

The session (``PartingSession``, which owns the re-part/git IO) lives in
``part_session.py`` — split out so neither file grows past the repo's
500-line cap. This module is the HTTP transport only: stdlib
``http.server`` (no uvicorn/starlette, so the sidecar works from any install
without the ``caliper[copilot]`` extra), with routing delegated to the pure
``dispatch()`` in ``part_routes.py`` (functional core) so it is exercised
without ever binding a socket; ``BaseHTTPRequestHandler`` here is the thin
imperative shell around it.

Loopback only by default: the primary server binds ``127.0.0.1`` so the
unauthenticated write endpoints are never exposed off-host. ``.caliper.yaml``
is a committed file, so writing to it here is intended — it's the server's
bind and auth model that keep this safe.

An optional read-only LAN view (``--lan``) binds a **second**, TLS-wrapped
server on a separate port; its handler implements only ``do_GET``, so every
mutating route is structurally unreachable through it. Both servers share one
``PartingSession`` under the session's existing lock.
"""

from __future__ import annotations

import http.server
import ssl
import threading
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from caliper.cli.part_routes import Assets, _SessionLike, dispatch
from caliper.cli.part_session import (  # noqa: F401 — re-exported for existing callers
    PartingSession,
    _apply_size_cap,
    _merge_overrides,
    write_override,
)

if TYPE_CHECKING:
    from caliper.core.tier_suggester import TierSuggesterPort

logger = structlog.get_logger()

# Loopback only — the reclassify endpoint writes config without auth, so this
# must never bind a routable interface. In the dev port range (12000–13000); avoids
# the webhook (12800) and postgres (12432).
HOST = "127.0.0.1"
DEFAULT_PORT = 12700
# The read-only LAN view binds a port other than the primary loopback server (never
# the same port on the same host — 0.0.0.0 and 127.0.0.1 binding the same port race
# or collide on some platforms).
DEFAULT_LAN_PORT = 12701
# Fallback search space when the preferred port is busy. Dev ports only
# (CLAUDE.md: 12000–13000, never common ports) so the sidecar always lands in the
# sanctioned range no matter how many are already up.
_DEV_PORTS = range(12000, 13000)

# The full, curated dropdown of buckets a reviewer can reclassify a file into —
# structural facts (move/delete/binary/generated) are decided by the classifier and
# never offered, ordered tiers → intent → residual as a sensible dropdown. This is a
# human-facing dropdown — a superset of the model's legal output (core
# SELECTABLE_TIERS: same membership minus 'logic', which a human may pick to *un*-tier).
# Membership parity is drift-guarded in tests; the order here is curated for UX, not
# the enum's declaration order.
#
# Mirrored in scripts/part_ui/types.ts SELECTABLE_BUCKETS (same membership and
# order) — the TS SPA renders this reclassify dropdown from its own copy, not this
# endpoint, so the two lists are kept in sync by hand until a drift test lands.
# Per-bucket accent hues live in scripts/part_ui/styles.css ([data-bucket] ->
# --bucket-hue), not here — this module owns the bucket *list*, not presentation.
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
# is Python's stdlib http.server. Routing is the pure `dispatch()` in
# `part_routes.py` (functional core) so it is exercised without ever binding a
# socket; the BaseHTTPRequestHandler here is the thin imperative shell around it.


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


def _make_readonly_handler(
    session: _SessionLike, assets: Assets | None = None
) -> type[http.server.BaseHTTPRequestHandler]:
    """Build a GET-only handler for the optional LAN view server.

    Deliberately implements only ``do_GET`` — ``BaseHTTPRequestHandler`` answers
    any other verb with a bare 501 Unsupported, so every mutating route
    (``/reclassify``, ``/repart``, ``/range``, ``/pr``, ``/suggest/apply``,
    ``/restack``, ``/apply``, ``/rollback`` — all POST-only in ``dispatch``) is
    unreachable through this handler without touching ``dispatch`` itself. The
    handful of GET routes it does reach (``/``, ``/assets/*``, ``/cutlist``,
    ``/restack.sh``) are all read-only.
    """

    class _ReadOnlyHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802 - stdlib dispatch name
            path = self.path.split("?", 1)[0]  # ignore any query string
            headers = {k.lower(): v for k, v in self.headers.items()}
            resp = dispatch(session, "GET", path, b"", assets, headers)
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.content_type)
            self.send_header("Content-Length", str(len(resp.body)))
            self.end_headers()
            self.wfile.write(resp.body)

        def log_message(self, fmt: str, *args: object) -> None:
            logger.debug("part_serve_lan_request", request=fmt % args)

    return _ReadOnlyHandler


def _bind_server(
    handler_cls: type[http.server.BaseHTTPRequestHandler], preferred: int, host: str = HOST
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
            return http.server.ThreadingHTTPServer((host, port), handler_cls), port
        except OSError as exc:  # EADDRINUSE (and friends) — try the next candidate
            last_exc = exc
    raise OSError(
        f"no free port: {preferred} and the whole {_DEV_PORTS.start}-{_DEV_PORTS.stop - 1} "
        "dev range are all in use"
    ) from last_exc


def _tls_context(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    return ctx


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
    lan_host: str | None = None,
    lan_port: int = DEFAULT_LAN_PORT,
    tls_cert: Path | None = None,
    tls_key: Path | None = None,
) -> None:
    """Run the sidecar on loopback. Blocks until interrupted (presentation tier).

    ``lan_host`` optionally starts a **second**, TLS-wrapped, read-only server
    (see ``_make_readonly_handler``) on a LAN-routable host/IP — e.g. for a
    reviewer to browse the cut list from another device via an mkcert-issued
    cert. Requires ``tls_cert``/``tls_key``. The primary loopback server (and
    every mutating endpoint) is unaffected: its bind, auth, and CSRF model stay
    exactly as they are today.
    """
    if lan_host and not (tls_cert and tls_key):
        raise ValueError("lan_host requires both tls_cert and tls_key (mkcert-issued)")
    if not lan_host and (tls_cert or tls_key):
        raise ValueError("tls_cert/tls_key only apply to lan_host — set lan_host too")

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

    lan_server: http.server.ThreadingHTTPServer | None = None
    lan_thread: threading.Thread | None = None
    lan_url: str | None = None
    if lan_host:
        assert tls_cert is not None and tls_key is not None  # validated above
        lan_server, lan_bound = _bind_server(
            _make_readonly_handler(session, assets), lan_port, host=lan_host
        )
        lan_server.socket = _tls_context(tls_cert, tls_key).wrap_socket(
            lan_server.socket, server_side=True
        )
        lan_url = f"https://{lan_host}:{lan_bound}"
        logger.info(
            "part_serve_lan_starting",
            host=lan_host,
            port=lan_bound,
            url=lan_url,
            mode="read-only",
        )
        lan_thread = threading.Thread(target=lan_server.serve_forever, daemon=True)
        lan_thread.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:  # Ctrl-C is the intended way to stop the sidecar
        pass
    finally:
        server.server_close()
        logger.info("part_serve_stopped", url=url)
        if lan_server is not None:
            lan_server.shutdown()
            lan_server.server_close()
            logger.info("part_serve_lan_stopped", url=lan_url)
