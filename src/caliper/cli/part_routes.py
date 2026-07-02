"""Route table for ``caliper part --serve`` (the pure request router).

# tested-by: tests/unit/test_part_serve.py

Split out of ``part_serve.py`` (formerly a single ~190-line ``if (method, path)``
chain in ``dispatch()``, cyclomatic complexity 139) into one small handler per
route plus a ``_ROUTES`` lookup table. ``dispatch`` stays a pure function — no
IO, no socket — fully testable with a fake session and a hand-built ``Assets``
fixture; ``part_serve.py``'s ``BaseHTTPRequestHandler`` is the thin imperative
shell that calls it.

This module deliberately has no import of ``part_serve`` (that would be
circular — ``part_serve.py`` imports ``dispatch``/``Response``/``Assets``/
``_SessionLike`` from here and re-exports them for backward-compatible
``part_serve.Assets`` / ``part_serve.dispatch`` access from tests and callers).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

import orjson
import structlog

logger = structlog.get_logger()


# --------------------------------------------------------------------------- #
# Session — the pure contract dispatch routes against
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


# --------------------------------------------------------------------------- #
# Assets — the committed TypeScript SPA bundle (scripts/part_ui -> build.ts)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Assets:
    """The built SPA bundle: the HTML shell plus its JS/CSS, as raw bytes."""

    index_html: bytes
    js: bytes
    css: bytes


# --------------------------------------------------------------------------- #
# Response — a rendered HTTP response
# --------------------------------------------------------------------------- #


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


# --------------------------------------------------------------------------- #
# Route handlers — one per (method, path), uniform ``_Request -> Response``
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Request:
    """Plain-data bundle threaded into every handler — mirrors dispatch's args."""

    session: _SessionLike
    body: bytes
    assets: Assets | None
    headers: Mapping[str, str] | None


def _h_index(req: _Request) -> Response:
    if req.assets is None:
        return _json({"error": "static assets not loaded"}, 500)
    return Response(200, "text/html; charset=utf-8", req.assets.index_html)


def _h_js(req: _Request) -> Response:
    if req.assets is None:
        return _json({"error": "static assets not loaded"}, 500)
    return Response(200, "application/javascript; charset=utf-8", req.assets.js)


def _h_css(req: _Request) -> Response:
    if req.assets is None:
        return _json({"error": "static assets not loaded"}, 500)
    return Response(200, "text/css; charset=utf-8", req.assets.css)


def _h_cutlist(req: _Request) -> Response:
    return _json(_with_overrides(req.session, req.session.cut_dict()))


def _h_reclassify(req: _Request) -> Response:
    try:
        payload = orjson.loads(req.body or b"")
    except orjson.JSONDecodeError:
        return _json({"error": "invalid JSON body"}, 400)
    if not isinstance(payload, dict):
        return _json({"error": "invalid JSON body"}, 400)
    target = payload.get("glob") or payload.get("file")
    bucket = payload.get("bucket")
    if not target or not bucket:
        return _json({"error": "both a target (file or glob) and a bucket are required"}, 400)
    try:
        cut = req.session.reclassify(target=target, bucket=bucket, note=payload.get("note", ""))
    except Exception as exc:  # validation / write errors are reviewer-facing, not 500s
        logger.info("parting_reclassify_rejected", error=str(exc))
        return _json({"error": str(exc)}, 400)
    return _json(_with_overrides(req.session, cut))


def _h_repart(req: _Request) -> Response:
    if req.body:
        try:
            payload = orjson.loads(req.body)
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
                cut = req.session.set_size_cap(size_cap)
            except Exception as exc:  # live setting rejected -> reviewer-facing 400
                return _json({"error": str(exc)}, 400)
            return _json(_with_overrides(req.session, cut))
    return _json(_with_overrides(req.session, req.session.repart_dict()))


def _h_range(req: _Request) -> Response:
    try:
        payload = orjson.loads(req.body or b"")
    except orjson.JSONDecodeError:
        return _json({"error": "invalid JSON body"}, 400)
    if not isinstance(payload, dict):
        return _json({"error": "invalid JSON body"}, 400)
    base = payload.get("base")
    head = payload.get("head")
    if not base or not head:
        return _json({"error": "both 'base' and 'head' are required"}, 400)
    try:
        cut = req.session.retarget(base=base, head=head)
    except Exception as exc:  # bad revsets etc. are reviewer-facing, not 500s
        logger.info("parting_retarget_rejected", error=str(exc))
        return _json({"error": str(exc)}, 400)
    return _json(_with_overrides(req.session, cut))


def _h_pr(req: _Request) -> Response:
    try:
        payload = orjson.loads(req.body or b"")
    except orjson.JSONDecodeError:
        return _json({"error": "invalid JSON body"}, 400)
    if not isinstance(payload, dict):
        return _json({"error": "invalid JSON body"}, 400)
    ref = payload.get("ref")
    if not ref:
        return _json({"error": "a 'ref' (PR URL or number) is required"}, 400)
    try:
        cut = req.session.set_target_pr(ref)
    except Exception as exc:  # unresolvable PR / clone failure -> 400, not 500
        logger.info("parting_pr_target_rejected", error=str(exc))
        return _json({"error": str(exc)}, 400)
    return _json(_with_overrides(req.session, cut))


def _h_suggest(req: _Request) -> Response:
    # Advisory: ask the local model for tier globs on the 'logic' residual. The
    # reviewer accepts one by POSTing /reclassify with the suggested glob+bucket;
    # nothing is written here. Fail-soft — the session swallows model errors to [].
    return _json(req.session.suggest_dict())


def _h_suggest_apply(req: _Request) -> Response:
    # Bulk-accept: the "accept all" button writes every proposed rule in one
    # request instead of one /reclassify round-trip per suggestion.
    try:
        payload = orjson.loads(req.body or b"")
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
        cut = req.session.suggest_apply(rules)
    except Exception as exc:  # validation / write errors are reviewer-facing, not 500s
        logger.info("parting_suggest_apply_rejected", error=str(exc))
        return _json({"error": str(exc)}, 400)
    return _json(_with_overrides(req.session, cut))


def _h_restack(req: _Request) -> Response:
    payload: dict = {}
    if req.body:
        try:
            payload = orjson.loads(req.body)
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
        result = req.session.generate(describe=describe, force=force, target=target)
    except Exception as exc:  # gate failure / untargeted session -> reviewer-facing 400
        logger.info("parting_restack_rejected", error=str(exc))
        return _json({"error": str(exc)}, 400)
    return _json(result)


def _h_restack_sh(req: _Request) -> Response:
    script = req.session.restack_script()
    if script is None:
        return _json({"error": "no restack script generated yet — POST /restack first"}, 404)
    return Response(200, "text/x-shellscript; charset=utf-8", script.encode())


def _h_apply(req: _Request) -> Response:
    if not _is_loopback_request(req.headers):
        return _json({"error": "request is not from loopback"}, 403)
    payload: dict = {}
    if req.body:
        try:
            payload = orjson.loads(req.body)
        except orjson.JSONDecodeError:
            return _json({"error": "invalid JSON body"}, 400)
        if not isinstance(payload, dict):
            return _json({"error": "invalid JSON body"}, 400)
    token = payload.get("apply_token")
    if not isinstance(token, str) or not token:
        return _json({"error": "'apply_token' is required"}, 400)
    try:
        result = req.session.apply(token)
    except Exception as exc:  # bad/stale token, ungenerated script -> reviewer-facing 400
        logger.info("parting_apply_rejected", error=str(exc))
        return _json({"error": str(exc)}, 400)
    return _json(result)


def _h_rollback(req: _Request) -> Response:
    try:
        result = req.session.rollback()
    except Exception as exc:  # nothing to roll back yet -> reviewer-facing 400
        logger.info("parting_rollback_rejected", error=str(exc))
        return _json({"error": str(exc)}, 400)
    return _json(result)


_ROUTES: dict[tuple[str, str], Callable[[_Request], Response]] = {
    ("GET", "/"): _h_index,
    ("GET", "/assets/part_ui.js"): _h_js,
    ("GET", "/assets/part_ui.css"): _h_css,
    ("GET", "/cutlist"): _h_cutlist,
    ("POST", "/reclassify"): _h_reclassify,
    ("POST", "/repart"): _h_repart,
    ("POST", "/range"): _h_range,
    ("POST", "/pr"): _h_pr,
    ("POST", "/suggest"): _h_suggest,
    ("POST", "/suggest/apply"): _h_suggest_apply,
    ("POST", "/restack"): _h_restack,
    ("GET", "/restack.sh"): _h_restack_sh,
    ("POST", "/apply"): _h_apply,
    ("POST", "/rollback"): _h_rollback,
}


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

    Lookup is a plain dict keyed on ``(method, path)`` — an unknown pair falls
    through to a bare 404, matching the previous if-chain's behavior exactly.
    """
    handler = _ROUTES.get((method, path))
    if handler is None:
        return _json({"error": "not found"}, 404)
    return handler(_Request(session=session, body=body, assets=assets, headers=headers))
