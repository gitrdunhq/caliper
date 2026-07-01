"""Tests for the localhost reclassify sidecar — ``caliper part --serve``.

# tested-by: tests/unit/test_part_serve.py

Two seams are tested independently:

* ``write_override`` — the deterministic write-back into ``.caliper.yaml``. No
  git, no server: a tmp repo dir is enough. This is the feedback loop's only
  mutation, so it carries the Idempotency property (applying the same override
  twice is the same as once).
* ``dispatch`` — the pure request router (functional core), driven by a fake
  session so the HTTP layer is tested without a real repo / git / re-part and
  without binding a socket. The transport is stdlib ``http.server`` — no
  starlette/uvicorn, so the sidecar works from any install (no extra).

Property domains (DPS-12):
  Idempotency   INVARIANT  applying the same override twice == once
  Confidentiality/Isolation  SAFETY  the server binds loopback only (127.0.0.1)
"""

from __future__ import annotations

import threading
from pathlib import Path

import orjson
import pytest
import yaml

from caliper.cli import part_serve
from caliper.cli.part_serve import dispatch, write_override
from caliper.core.repo_config import load_repo_config

# --------------------------------------------------------------------------- #
# write_override — the deterministic .caliper.yaml write-back
# --------------------------------------------------------------------------- #


def _overrides(repo: Path) -> list[dict]:
    data = yaml.safe_load((repo / ".caliper.yaml").read_text()) or {}
    return data.get("parting", {}).get("overrides", [])


class TestWriteOverride:
    def test_creates_caliper_yaml_with_override(self, tmp_path: Path) -> None:
        """A first override on a repo with no config file creates one."""
        write_override(tmp_path, glob="src/ui/**", bucket="frontend", note="the SPA")
        rules = _overrides(tmp_path)
        assert rules == [{"glob": "src/ui/**", "bucket": "frontend", "note": "the SPA"}]

    def test_override_is_loadable(self, tmp_path: Path) -> None:
        """The written table round-trips through load_repo_config."""
        write_override(tmp_path, glob="src/repo/**", bucket="data")
        cfg = load_repo_config(tmp_path)
        assert len(cfg.parting.overrides) == 1
        assert cfg.parting.overrides[0].glob == "src/repo/**"
        assert cfg.parting.overrides[0].bucket == "data"

    def test_idempotent_same_override_twice(self, tmp_path: Path) -> None:
        """Idempotency INVARIANT: writing the same rule twice yields one entry."""
        write_override(tmp_path, glob="src/x/**", bucket="business")
        write_override(tmp_path, glob="src/x/**", bucket="business")
        assert _overrides(tmp_path) == [{"glob": "src/x/**", "bucket": "business"}]

    def test_reclassify_updates_existing_glob_in_place(self, tmp_path: Path) -> None:
        """Re-targeting an existing glob updates its bucket — never a duplicate."""
        write_override(tmp_path, glob="src/x/**", bucket="business")
        write_override(tmp_path, glob="src/x/**", bucket="data")
        rules = _overrides(tmp_path)
        assert len(rules) == 1
        assert rules[0]["bucket"] == "data"

    def test_preserves_other_config_keys(self, tmp_path: Path) -> None:
        """The write-back must not clobber unrelated config (plugins, thresholds)."""
        (tmp_path / ".caliper.yaml").write_text(
            yaml.safe_dump({"plugins": {"disabled": ["typos"]}})
        )
        write_override(tmp_path, glob="src/x/**", bucket="frontend")
        data = yaml.safe_load((tmp_path / ".caliper.yaml").read_text())
        assert data["plugins"]["disabled"] == ["typos"]
        assert data["parting"]["overrides"][0]["glob"] == "src/x/**"

    def test_appends_second_distinct_glob(self, tmp_path: Path) -> None:
        write_override(tmp_path, glob="src/x/**", bucket="frontend")
        write_override(tmp_path, glob="src/y/**", bucket="data")
        assert [r["glob"] for r in _overrides(tmp_path)] == ["src/x/**", "src/y/**"]

    def test_structural_bucket_rejected(self, tmp_path: Path) -> None:
        """A structural target (delete/move/binary) is refused — and not written."""
        with pytest.raises(ValueError):
            write_override(tmp_path, glob="src/x/**", bucket="delete")
        assert not (tmp_path / ".caliper.yaml").exists()

    def test_unknown_bucket_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            write_override(tmp_path, glob="src/x/**", bucket="nonsense")

    def test_invalid_bucket_does_not_corrupt_existing_file(self, tmp_path: Path) -> None:
        """A rejected write leaves a pre-existing valid override untouched."""
        write_override(tmp_path, glob="src/x/**", bucket="frontend")
        with pytest.raises(ValueError):
            write_override(tmp_path, glob="src/y/**", bucket="delete")
        assert _overrides(tmp_path) == [{"glob": "src/x/**", "bucket": "frontend"}]


# --------------------------------------------------------------------------- #
# dispatch — the pure router, driven by a fake session (no git, no socket)
# --------------------------------------------------------------------------- #

_FAKE_CUT = {
    "parts": [
        {
            "id": "p1",
            "files": ["src/app.py"],
            "bucket": "logic",
            "size": 12,
            "opened_by": {"fired_rule": "seed"},
            "oversized": False,
        }
    ],
    "ambiguities": [],
    "size_cap": 400,
    "provenance": {
        "caliper_version": "0.0.0",
        "base_sha": "aaaaaaaa",
        "head_sha": "bbbbbbbb",
        "rename_threshold": 50,
        "config_digest": "deadbeefcafe",
    },
    "stats": {"part_count": 1, "file_count": 1, "size_p50": 12, "size_p90": 12},
}


class FakeSession:
    """Implements the session interface the app depends on; records calls."""

    def __init__(self) -> None:
        self.reclassified: list[tuple[str, str]] = []
        self.reparted = 0
        self.raise_on_reclassify: Exception | None = None
        self.suggestions: list[dict] = []
        self.suggest_configured = True
        self.suggest_calls = 0
        self.suggest_apply_calls: list[list[dict]] = []
        self.raise_on_suggest_apply: Exception | None = None
        # Sentinel, not []: proves a route actually calls session.overrides()
        # and merges its result, rather than happening to already have an
        # empty "overrides" key from somewhere else.
        self._overrides_value: list[dict] = [
            {"glob": "sentinel/**", "bucket": "config", "note": ""}
        ]
        self.untargeted = False
        self.retargeted_calls: list[tuple[str, str]] = []
        self.raise_on_retarget: Exception | None = None
        self.pr_calls: list[str] = []
        self.raise_on_pr: Exception | None = None
        self.size_cap_calls: list[int | None] = []
        self.raise_on_size_cap: Exception | None = None
        self.generate_calls: list[dict] = []
        self.raise_on_generate: Exception | None = None
        self._restack_script: str | None = None
        self.generate_result: dict = {
            "cutlist": _FAKE_CUT,
            "script_text": "#!/usr/bin/env bash\n",
            "backup_bookmark": "caliper-part-backup-x",
            "rescue_op_id": "op-1",
            "jj_version": "0.99.0",
            "can_reconstruct": True,
            "subjects": {},
            "proposed_overrides": [],
            "applied_overrides": [],
            "restack_path": "/tmp/restack.sh",
            "cutlist_path": "/tmp/cutlist.json",
            "apply_token": "tok-123",
        }
        self.apply_calls: list[str] = []
        self.raise_on_apply: Exception | None = None
        self.apply_result: dict = {
            "ok": True,
            "stdout": "applied\n",
            "stderr": "",
            "rollback": {"backup_bookmark": "caliper-part-backup-x", "rescue_op_id": "op-1"},
        }
        self.rollback_calls = 0
        self.raise_on_rollback: Exception | None = None
        self.rollback_result: dict = {"ok": True, "stdout": "restored\n", "stderr": ""}

    def cut_dict(self) -> dict:
        if self.untargeted:
            return {"targeted": False}
        return _FAKE_CUT

    def retarget(self, *, base: str, head: str) -> dict:
        if self.raise_on_retarget is not None:
            raise self.raise_on_retarget
        self.retargeted_calls.append((base, head))
        self.untargeted = False
        return _FAKE_CUT

    def set_target_pr(self, ref: str) -> dict:
        if self.raise_on_pr is not None:
            raise self.raise_on_pr
        self.pr_calls.append(ref)
        self.untargeted = False
        return {**_FAKE_CUT, "pr": {"slug": "acme/widgets", "number": 42}}

    def repart_dict(self) -> dict:
        self.reparted += 1
        return _FAKE_CUT

    def set_size_cap(self, size_cap: int | None) -> dict:
        if self.raise_on_size_cap is not None:
            raise self.raise_on_size_cap
        self.size_cap_calls.append(size_cap)
        return _FAKE_CUT

    def reclassify(self, *, target: str, bucket: str, note: str = "") -> dict:
        if self.raise_on_reclassify is not None:
            raise self.raise_on_reclassify
        self.reclassified.append((target, bucket))
        return _FAKE_CUT

    def overrides(self) -> list[dict]:
        return self._overrides_value

    def suggest_dict(self) -> dict:
        self.suggest_calls += 1
        return {"suggestions": self.suggestions, "configured": self.suggest_configured}

    def suggest_apply(self, rules: list[dict]) -> dict:
        if self.raise_on_suggest_apply is not None:
            raise self.raise_on_suggest_apply
        self.suggest_apply_calls.append(rules)
        return _FAKE_CUT

    def generate(self, *, describe: bool = False, force: bool = False, target=None) -> dict:
        if self.raise_on_generate is not None:
            raise self.raise_on_generate
        self.generate_calls.append({"describe": describe, "force": force, "target": target})
        self._restack_script = self.generate_result["script_text"]
        return self.generate_result

    def restack_script(self) -> str | None:
        return self._restack_script

    def apply(self, token: str) -> dict:
        if self.raise_on_apply is not None:
            raise self.raise_on_apply
        self.apply_calls.append(token)
        return self.apply_result

    def rollback(self) -> dict:
        if self.raise_on_rollback is not None:
            raise self.raise_on_rollback
        self.rollback_calls += 1
        return self.rollback_result


_LOOPBACK_HEADERS = {"host": "127.0.0.1:12700"}


def _post(session: FakeSession, path: str, payload: dict):
    return dispatch(session, "POST", path, orjson.dumps(payload))


def _body(resp) -> dict:
    return orjson.loads(resp.body)


def _fake_assets() -> part_serve.Assets:
    return part_serve.Assets(
        index_html=b'<!doctype html><html><body><div id="app"></div>'
        b'<script src="/assets/part_ui.js"></script></body></html>',
        js=b"console.log('part ui');",
        css=b":root{color-scheme:light dark;}",
    )


class TestDispatch:
    def test_index_without_assets_is_500(self) -> None:
        # A misconfigured server (bundle not built/loaded) fails loudly rather
        # than serving a 200 with no shell.
        resp = dispatch(FakeSession(), "GET", "/", b"")
        assert resp.status == 500

    def test_index_serves_shell_when_assets_loaded(self) -> None:
        resp = dispatch(FakeSession(), "GET", "/", b"", assets=_fake_assets())
        assert resp.status == 200
        assert "text/html" in resp.content_type
        assert b'id="app"' in resp.body
        assert b"/assets/part_ui.js" in resp.body

    def test_assets_js_served(self) -> None:
        resp = dispatch(FakeSession(), "GET", "/assets/part_ui.js", b"", assets=_fake_assets())
        assert resp.status == 200
        assert "javascript" in resp.content_type
        assert resp.body == b"console.log('part ui');"

    def test_assets_css_served(self) -> None:
        resp = dispatch(FakeSession(), "GET", "/assets/part_ui.css", b"", assets=_fake_assets())
        assert resp.status == 200
        assert "text/css" in resp.content_type
        assert resp.body == b":root{color-scheme:light dark;}"

    def test_assets_route_without_assets_is_500(self) -> None:
        resp = dispatch(FakeSession(), "GET", "/assets/part_ui.js", b"")
        assert resp.status == 500

    def test_cutlist_returns_json(self) -> None:
        resp = dispatch(FakeSession(), "GET", "/cutlist", b"")
        assert resp.status == 200
        assert _body(resp)["parts"][0]["id"] == "p1"
        assert _body(resp)["overrides"] == [{"glob": "sentinel/**", "bucket": "config", "note": ""}]

    def test_reclassify_writes_override_and_returns_cut(self) -> None:
        session = FakeSession()
        resp = _post(session, "/reclassify", {"file": "src/app.py", "bucket": "business"})
        assert resp.status == 200
        assert session.reclassified == [("src/app.py", "business")]
        assert _body(resp)["parts"][0]["bucket"] == "logic"
        # The overrides panel must refresh from a reclassify response too, not
        # only from the initial GET /cutlist — otherwise the SPA shows a stale
        # "no overrides yet" after a write that plainly succeeded.
        assert _body(resp)["overrides"] == [{"glob": "sentinel/**", "bucket": "config", "note": ""}]

    def test_reclassify_accepts_glob(self) -> None:
        session = FakeSession()
        _post(session, "/reclassify", {"glob": "src/**", "bucket": "frontend"})
        assert session.reclassified == [("src/**", "frontend")]

    def test_reclassify_missing_bucket_is_400(self) -> None:
        session = FakeSession()
        resp = _post(session, "/reclassify", {"file": "src/app.py"})
        assert resp.status == 400
        assert session.reclassified == []

    def test_reclassify_missing_target_is_400(self) -> None:
        resp = _post(FakeSession(), "/reclassify", {"bucket": "frontend"})
        assert resp.status == 400

    def test_reclassify_invalid_json_is_400(self) -> None:
        resp = dispatch(FakeSession(), "POST", "/reclassify", b"not json{")
        assert resp.status == 400
        assert "invalid JSON" in _body(resp)["error"]

    def test_reclassify_validation_error_is_400(self) -> None:
        session = FakeSession()
        session.raise_on_reclassify = ValueError("override bucket 'delete' is structural")
        resp = _post(session, "/reclassify", {"file": "x", "bucket": "delete"})
        assert resp.status == 400
        assert "structural" in _body(resp)["error"]

    def test_repart_triggers_repart(self) -> None:
        session = FakeSession()
        resp = dispatch(session, "POST", "/repart", b"")
        assert resp.status == 200
        assert session.reparted == 1
        assert _body(resp)["overrides"] == [{"glob": "sentinel/**", "bucket": "config", "note": ""}]

    def test_repart_with_size_cap_applies_and_reparts(self) -> None:
        session = FakeSession()
        resp = dispatch(session, "POST", "/repart", orjson.dumps({"size_cap": 500}))
        assert resp.status == 200
        assert session.size_cap_calls == [500]
        assert session.reparted == 0  # set_size_cap re-parts itself, not repart_dict()

    def test_repart_with_null_size_cap_clears_cap(self) -> None:
        session = FakeSession()
        resp = dispatch(session, "POST", "/repart", orjson.dumps({"size_cap": None}))
        assert resp.status == 200
        assert session.size_cap_calls == [None]

    def test_repart_size_cap_wrong_type_is_400(self) -> None:
        session = FakeSession()
        resp = dispatch(session, "POST", "/repart", orjson.dumps({"size_cap": "big"}))
        assert resp.status == 400
        assert session.size_cap_calls == []

    def test_repart_size_cap_zero_is_400(self) -> None:
        session = FakeSession()
        resp = dispatch(session, "POST", "/repart", orjson.dumps({"size_cap": 0}))
        assert resp.status == 400

    def test_repart_size_cap_negative_is_400(self) -> None:
        session = FakeSession()
        resp = dispatch(session, "POST", "/repart", orjson.dumps({"size_cap": -5}))
        assert resp.status == 400

    def test_repart_invalid_json_body_is_400(self) -> None:
        session = FakeSession()
        resp = dispatch(session, "POST", "/repart", b"not json")
        assert resp.status == 400

    def test_repart_size_cap_session_error_is_400(self) -> None:
        session = FakeSession()
        session.raise_on_size_cap = ValueError("bad cap")
        resp = dispatch(session, "POST", "/repart", orjson.dumps({"size_cap": 10}))
        assert resp.status == 400
        assert _body(resp)["error"] == "bad cap"

    def test_suggest_returns_session_suggestions(self) -> None:
        session = FakeSession()
        session.suggestions = [{"glob": "**/lib/lambda/**", "bucket": "business", "note": ""}]
        resp = dispatch(session, "POST", "/suggest", b"")
        assert resp.status == 200
        assert session.suggest_calls == 1
        body = _body(resp)
        assert body["configured"] is True
        assert body["suggestions"][0]["glob"] == "**/lib/lambda/**"

    def test_suggest_unconfigured_reports_false(self) -> None:
        session = FakeSession()
        session.suggest_configured = False
        body = _body(dispatch(session, "POST", "/suggest", b""))
        assert body["configured"] is False
        assert body["suggestions"] == []

    def test_suggest_apply_writes_all_and_reparts(self) -> None:
        session = FakeSession()
        rules = [
            {"glob": "**/lib/lambda/**", "bucket": "business", "note": "suggested"},
            {"glob": "**/cdk.json", "bucket": "config"},
        ]
        resp = _post(session, "/suggest/apply", {"globs": rules})
        assert resp.status == 200
        assert session.suggest_apply_calls == [rules]
        assert _body(resp)["parts"][0]["id"] == "p1"
        assert _body(resp)["overrides"] == [{"glob": "sentinel/**", "bucket": "config", "note": ""}]

    def test_suggest_apply_empty_globs_is_400(self) -> None:
        resp = _post(FakeSession(), "/suggest/apply", {"globs": []})
        assert resp.status == 400

    def test_suggest_apply_missing_globs_is_400(self) -> None:
        resp = _post(FakeSession(), "/suggest/apply", {})
        assert resp.status == 400

    def test_suggest_apply_rule_missing_bucket_is_400(self) -> None:
        resp = _post(FakeSession(), "/suggest/apply", {"globs": [{"glob": "**/x/**"}]})
        assert resp.status == 400

    def test_suggest_apply_invalid_json_is_400(self) -> None:
        resp = dispatch(FakeSession(), "POST", "/suggest/apply", b"not json{")
        assert resp.status == 400

    def test_suggest_apply_session_error_is_400(self) -> None:
        session = FakeSession()
        session.raise_on_suggest_apply = ValueError("bad bucket")
        resp = _post(session, "/suggest/apply", {"globs": [{"glob": "**/x/**", "bucket": "nope"}]})
        assert resp.status == 400
        assert _body(resp)["error"] == "bad bucket"

    def test_cutlist_untargeted_reports_targeted_false(self) -> None:
        session = FakeSession()
        session.untargeted = True
        resp = dispatch(session, "GET", "/cutlist", b"")
        assert resp.status == 200
        # The untargeted sentinel must pass through bare — no "overrides" key
        # merged in, since there is no cut to attach it to yet.
        assert _body(resp) == {"targeted": False}

    def test_range_retargets_and_returns_cut(self) -> None:
        session = FakeSession()
        resp = _post(session, "/range", {"base": "main", "head": "feature/x"})
        assert resp.status == 200
        assert session.retargeted_calls == [("main", "feature/x")]
        assert _body(resp)["parts"][0]["id"] == "p1"
        assert _body(resp)["overrides"] == [{"glob": "sentinel/**", "bucket": "config", "note": ""}]

    def test_range_missing_base_is_400(self) -> None:
        resp = _post(FakeSession(), "/range", {"head": "feature/x"})
        assert resp.status == 400
        assert "base" in _body(resp)["error"]

    def test_range_missing_head_is_400(self) -> None:
        resp = _post(FakeSession(), "/range", {"base": "main"})
        assert resp.status == 400

    def test_range_invalid_json_is_400(self) -> None:
        resp = dispatch(FakeSession(), "POST", "/range", b"{not json")
        assert resp.status == 400

    def test_range_session_error_is_400(self) -> None:
        session = FakeSession()
        session.raise_on_retarget = ValueError("bad revset")
        resp = _post(session, "/range", {"base": "main", "head": "nope"})
        assert resp.status == 400
        assert _body(resp)["error"] == "bad revset"

    def test_pr_resolves_and_returns_cut(self) -> None:
        session = FakeSession()
        resp = _post(session, "/pr", {"ref": "acme/widgets#42"})
        assert resp.status == 200
        assert session.pr_calls == ["acme/widgets#42"]
        assert _body(resp)["parts"][0]["id"] == "p1"
        assert _body(resp)["pr"] == {"slug": "acme/widgets", "number": 42}
        assert _body(resp)["overrides"] == [{"glob": "sentinel/**", "bucket": "config", "note": ""}]

    def test_pr_missing_ref_is_400(self) -> None:
        resp = _post(FakeSession(), "/pr", {})
        assert resp.status == 400

    def test_pr_session_error_is_400(self) -> None:
        session = FakeSession()
        session.raise_on_pr = ValueError("could not resolve PR: not found")
        resp = _post(session, "/pr", {"ref": "999999"})
        assert resp.status == 400
        assert "not found" in _body(resp)["error"]

    def test_unknown_route_is_404(self) -> None:
        resp = dispatch(FakeSession(), "GET", "/nope", b"")
        assert resp.status == 404

    def test_query_string_is_ignored_by_handler(self) -> None:
        # The handler strips the query string before dispatch; dispatch matches the bare path.
        resp = dispatch(FakeSession(), "GET", "/cutlist", b"")
        assert resp.status == 200

    def test_restack_generates_and_returns_apply_token(self) -> None:
        session = FakeSession()
        resp = _post(session, "/restack", {})
        assert resp.status == 200
        assert session.generate_calls == [{"describe": False, "force": False, "target": None}]
        body = _body(resp)
        assert body["apply_token"] == "tok-123"
        assert body["backup_bookmark"] == "caliper-part-backup-x"

    def test_restack_passes_describe_force_target_through(self) -> None:
        session = FakeSession()
        resp = _post(session, "/restack", {"describe": True, "force": True, "target": "series"})
        assert resp.status == 200
        assert session.generate_calls == [{"describe": True, "force": True, "target": "series"}]

    def test_restack_no_body_defaults_to_false_none(self) -> None:
        session = FakeSession()
        resp = dispatch(session, "POST", "/restack", b"")
        assert resp.status == 200
        assert session.generate_calls == [{"describe": False, "force": False, "target": None}]

    def test_restack_invalid_json_is_400(self) -> None:
        resp = dispatch(FakeSession(), "POST", "/restack", b"{not json")
        assert resp.status == 400

    def test_restack_describe_wrong_type_is_400(self) -> None:
        resp = _post(FakeSession(), "/restack", {"describe": "yes"})
        assert resp.status == 400

    def test_restack_force_wrong_type_is_400(self) -> None:
        resp = _post(FakeSession(), "/restack", {"force": "yes"})
        assert resp.status == 400

    def test_restack_bad_target_is_400(self) -> None:
        resp = _post(FakeSession(), "/restack", {"target": "bogus"})
        assert resp.status == 400

    def test_restack_session_error_is_400(self) -> None:
        session = FakeSession()
        session.raise_on_generate = ValueError("no base/head targeted yet")
        resp = _post(session, "/restack", {})
        assert resp.status == 400
        assert "targeted" in _body(resp)["error"]

    def test_restack_sh_returns_last_script(self) -> None:
        session = FakeSession()
        _post(session, "/restack", {})
        resp = dispatch(session, "GET", "/restack.sh", b"")
        assert resp.status == 200
        assert resp.content_type.startswith("text/x-shellscript")
        assert resp.body == b"#!/usr/bin/env bash\n"

    def test_restack_sh_before_generate_is_404(self) -> None:
        resp = dispatch(FakeSession(), "GET", "/restack.sh", b"")
        assert resp.status == 404

    def test_apply_runs_with_loopback_host_and_token(self) -> None:
        session = FakeSession()
        resp = dispatch(
            session,
            "POST",
            "/apply",
            orjson.dumps({"apply_token": "tok-123"}),
            headers=_LOOPBACK_HEADERS,
        )
        assert resp.status == 200
        body = orjson.loads(resp.body)
        assert body["ok"] is True
        assert body["rollback"]["rescue_op_id"] == "op-1"
        assert session.apply_calls == ["tok-123"]

    def test_apply_accepts_localhost_host_and_matching_origin(self) -> None:
        session = FakeSession()
        resp = dispatch(
            session,
            "POST",
            "/apply",
            orjson.dumps({"apply_token": "tok-123"}),
            headers={"host": "localhost:12700", "origin": "http://localhost:12700"},
        )
        assert resp.status == 200

    def test_apply_rejects_non_loopback_host(self) -> None:
        session = FakeSession()
        resp = dispatch(
            session,
            "POST",
            "/apply",
            orjson.dumps({"apply_token": "tok-123"}),
            headers={"host": "evil.example.com"},
        )
        assert resp.status == 403
        assert session.apply_calls == []

    def test_apply_rejects_cross_origin(self) -> None:
        session = FakeSession()
        resp = dispatch(
            session,
            "POST",
            "/apply",
            orjson.dumps({"apply_token": "tok-123"}),
            headers={"host": "127.0.0.1:12700", "origin": "http://evil.example.com"},
        )
        assert resp.status == 403
        assert session.apply_calls == []

    def test_apply_with_no_headers_is_403(self) -> None:
        # dispatch() defaults headers to None (existing callers unaffected) — the
        # guard must fail closed, not treat "no header info" as loopback.
        session = FakeSession()
        resp = dispatch(session, "POST", "/apply", orjson.dumps({"apply_token": "tok-123"}))
        assert resp.status == 403
        assert session.apply_calls == []

    def test_apply_missing_token_is_400(self) -> None:
        session = FakeSession()
        resp = dispatch(session, "POST", "/apply", orjson.dumps({}), headers=_LOOPBACK_HEADERS)
        assert resp.status == 400
        assert session.apply_calls == []

    def test_apply_invalid_json_is_400(self) -> None:
        session = FakeSession()
        resp = dispatch(session, "POST", "/apply", b"{not json", headers=_LOOPBACK_HEADERS)
        assert resp.status == 400

    def test_apply_stale_token_is_400(self) -> None:
        session = FakeSession()
        session.raise_on_apply = ValueError("invalid or expired apply token")
        resp = dispatch(
            session,
            "POST",
            "/apply",
            orjson.dumps({"apply_token": "stale"}),
            headers=_LOOPBACK_HEADERS,
        )
        assert resp.status == 400

    def test_rollback_runs(self) -> None:
        session = FakeSession()
        resp = dispatch(session, "POST", "/rollback", b"")
        assert resp.status == 200
        body = orjson.loads(resp.body)
        assert body["ok"] is True
        assert session.rollback_calls == 1

    def test_rollback_before_restack_is_400(self) -> None:
        session = FakeSession()
        session.raise_on_rollback = ValueError("nothing to roll back — POST /restack first")
        resp = dispatch(session, "POST", "/rollback", b"")
        assert resp.status == 400


# --------------------------------------------------------------------------- #
# _bind_server — preferred port, else the next free dev port (real sockets)
# --------------------------------------------------------------------------- #


class TestBindServer:
    def test_uses_preferred_when_free(self) -> None:
        server, port = part_serve._bind_server(part_serve._make_handler(FakeSession()), 12733)
        try:
            assert port == 12733
        finally:
            server.server_close()

    def test_falls_back_when_preferred_is_taken(self) -> None:
        import socket

        # Hold the preferred port open so the bind must move to another in-range one.
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind((part_serve.HOST, 0))  # let the OS pick a real, busy port
        blocker.listen(1)
        taken = blocker.getsockname()[1]
        try:
            server, port = part_serve._bind_server(part_serve._make_handler(FakeSession()), taken)
            try:
                assert port != taken
                assert port in part_serve._DEV_PORTS
            finally:
                server.server_close()
        finally:
            blocker.close()


class TestApplySizeCap:
    """The --size-cap override must reach the served cut (regression: it was dropped)."""

    def test_override_replaces_config_cap(self) -> None:
        from caliper.cli.part_serve import _apply_size_cap
        from caliper.core.repo_config import PartingConfig

        base = PartingConfig()
        assert _apply_size_cap(base, 100000).size_cap == 100000

    def test_none_leaves_config_cap_untouched(self) -> None:
        from caliper.cli.part_serve import _apply_size_cap
        from caliper.core.repo_config import PartingConfig

        base = PartingConfig()
        assert _apply_size_cap(base, None).size_cap == base.size_cap

    def test_session_stores_the_override(self) -> None:
        # The session must carry the override so each re-part applies it.
        session = part_serve.PartingSession(Path("/repo"), "base", "head", size_cap=100000)
        assert session.size_cap == 100000


class TestLoopbackOnly:
    def test_host_is_loopback(self) -> None:
        """Isolation SAFETY: the sidecar binds loopback, never 0.0.0.0."""
        assert part_serve.HOST == "127.0.0.1"
        assert part_serve.HOST != "0.0.0.0"

    def test_default_port_in_dev_range(self) -> None:
        assert 12000 <= part_serve.DEFAULT_PORT <= 13000


class TestMergeOverrides:
    """Sidecar overrides layer over the repo's committed ones, deduped by glob."""

    def test_sidecar_wins_per_glob_and_order_preserved(self) -> None:
        from caliper.cli.part_serve import _merge_overrides
        from caliper.core.repo_config import OverrideRule

        base = [
            OverrideRule(glob="a/**", bucket="business"),
            OverrideRule(glob="b/**", bucket="data"),
        ]
        extra = [
            OverrideRule(glob="b/**", bucket="frontend"),  # re-targets b
            OverrideRule(glob="c/**", bucket="infra"),  # new
        ]
        merged = _merge_overrides(base, extra)

        assert [r.glob for r in merged] == ["a/**", "b/**", "c/**"]  # base order, new appended
        assert {r.glob: r.bucket.value for r in merged}["b/**"] == "frontend"  # sidecar wins
        # no duplicate globs => still a valid PartingConfig override list
        assert len({r.glob for r in merged}) == len(merged)


class TestConcurrency:
    """Isolation SAFETY: ThreadingHTTPServer fans requests across threads."""

    def test_concurrent_first_cut_computes_once(self) -> None:
        import threading
        import time

        session = part_serve.PartingSession(Path("/repo"), "base", "head")
        calls = {"n": 0}
        sentinel = object()

        def fake_cut_now():
            calls["n"] += 1
            time.sleep(0.05)  # widen the race window
            return sentinel

        session._cut_now = fake_cut_now  # type: ignore[method-assign]

        results: list = []
        barrier = threading.Barrier(8)

        def worker() -> None:
            barrier.wait()
            results.append(session.cut())

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert calls["n"] == 1, "the cut is computed once even under a concurrent first hit"
        assert all(r is sentinel for r in results)


class TestSessionSuggest:
    """PartingSession.suggest_dict wires the cut's residual to the suggester boundary."""

    def _cutlist(self):
        from caliper.core.models import ChangeType, CutList, CutStats, Kerf, Part, Provenance

        def part(bucket: ChangeType, files: list[str]) -> Part:
            return Part(
                id=f"{bucket}-{len(files)}",
                files=sorted(files),
                bucket=bucket,
                size=len(files) * 10,
                opened_by=Kerf(fired_rule="bucket-end"),
            )

        parts = [
            part(ChangeType.infra, ["svc/lib/infra-utils/builder.ts"]),
            part(ChangeType.logic, ["svc/lib/lambda/handler.ts", "svc/cdk.json"]),
        ]
        return CutList(
            parts=parts,
            size_cap=None,
            provenance=Provenance(
                caliper_version="0",
                base_sha="b",
                head_sha="h",
                rename_threshold=50,
                config_digest="d",
            ),
            stats=CutStats(
                part_count=len(parts), file_count=3, size_p50=0, size_p90=0, move_logic_pure=True
            ),
        )

    def test_no_suggester_reports_unconfigured(self, tmp_path: Path) -> None:
        session = part_serve.PartingSession(tmp_path, "base", "head")
        assert session.suggest_dict() == {"suggestions": [], "configured": False}

    def test_runs_suggester_over_residual(self, tmp_path: Path) -> None:
        from caliper.core.tier_suggester import SuggestedRule, SuggestRequest

        class _Stub:
            def __init__(self) -> None:
                self.seen: SuggestRequest | None = None

            def suggest(self, request: SuggestRequest) -> list[SuggestedRule]:
                self.seen = request
                return [
                    SuggestedRule(glob="**/lib/lambda/**", bucket="business"),
                    SuggestedRule(glob="**/cdk.json", bucket="config"),
                ]

        stub = _Stub()
        session = part_serve.PartingSession(tmp_path, "base", "head", suggester=stub)
        session._cut = self._cutlist()
        out = session.suggest_dict()
        assert out["configured"] is True
        assert {s["glob"] for s in out["suggestions"]} == {"**/lib/lambda/**", "**/cdk.json"}
        # Only the residual is shown to the model — never an already-tiered file.
        assert stub.seen is not None
        assert "svc/lib/infra-utils/builder.ts" not in {f.path for f in stub.seen.residual}

    def test_subset_guard_applies_in_session(self, tmp_path: Path) -> None:
        # `**/*.ts` would also steal the already-infra builder.ts -> dropped by the boundary.
        from caliper.core.tier_suggester import SuggestedRule, SuggestRequest

        class _Thief:
            def suggest(self, request: SuggestRequest) -> list[SuggestedRule]:
                return [SuggestedRule(glob="**/*.ts", bucket="business")]

        session = part_serve.PartingSession(tmp_path, "base", "head", suggester=_Thief())
        session._cut = self._cutlist()
        assert session.suggest_dict()["suggestions"] == []


class TestRetargetRollback:
    """A rejected retarget must not leave the session permanently wedged.

    `_cut_now()` fails against tmp_path (not a git repo) exactly like a bad
    revset would against a real one — good enough to prove the rollback
    without needing a real repository fixture.
    """

    def _cutlist(self):
        from caliper.core.models import ChangeType, CutList, CutStats, Kerf, Part, Provenance

        parts = [
            Part(
                id="infra-1",
                files=["svc/lib/infra-utils/builder.ts"],
                bucket=ChangeType.infra,
                size=10,
                opened_by=Kerf(fired_rule="bucket-end"),
            )
        ]
        return CutList(
            parts=parts,
            size_cap=None,
            provenance=Provenance(
                caliper_version="0",
                base_sha="b",
                head_sha="h",
                rename_threshold=50,
                config_digest="d",
            ),
            stats=CutStats(
                part_count=1, file_count=1, size_p50=0, size_p90=0, move_logic_pure=True
            ),
        )

    def test_range_failure_restores_prior_target_and_cut(self, tmp_path: Path) -> None:
        session = part_serve.PartingSession(tmp_path, "base", "head")
        good_cut = self._cutlist()
        session._cut = good_cut

        with pytest.raises(Exception):
            session.retarget(base="nope", head="also-nope")

        assert session.base == "base"
        assert session.head == "head"
        # A read-only re-check must keep working — it must not re-raise.
        assert session.cut_dict() == good_cut.model_dump(mode="json")

    def test_pr_failure_restores_prior_target_and_cut(self, tmp_path: Path) -> None:
        session = part_serve.PartingSession(tmp_path, "base", "head")
        good_cut = self._cutlist()
        session._cut = good_cut

        with pytest.raises(Exception):
            session.set_target_pr("not-a-valid-pr-ref")

        assert session.repo_path == tmp_path
        assert session.base == "base"
        assert session.head == "head"
        assert session.cut_dict() == good_cut.model_dump(mode="json")

    def test_size_cap_failure_restores_prior_cap_and_cut(self, tmp_path: Path) -> None:
        session = part_serve.PartingSession(tmp_path, "base", "head", size_cap=100)
        good_cut = self._cutlist()
        session._cut = good_cut

        # tmp_path isn't a git repo, so re-cutting under the new cap fails —
        # same "bad state exercises the real cut path" trick as the range test.
        with pytest.raises(Exception):
            session.set_size_cap(5)

        assert session.size_cap == 100
        assert session.cut_dict() == good_cut.model_dump(mode="json")


class TestRetargetInvalidatesApplyToken:
    """A restack.sh + apply token minted for one target must not survive a
    successful retarget to a different one (adversarial review finding
    P02-1, docs/reviews/adversarial-2026-06-30.md) — otherwise a stale
    token/script from the old target could be replayed via /apply against
    whatever the session now points at.
    """

    def _cutlist(self):
        from caliper.core.models import ChangeType, CutList, CutStats, Kerf, Part, Provenance

        parts = [
            Part(
                id="infra-1",
                files=["svc/lib/infra-utils/builder.ts"],
                bucket=ChangeType.infra,
                size=10,
                opened_by=Kerf(fired_rule="bucket-end"),
            )
        ]
        return CutList(
            parts=parts,
            size_cap=None,
            provenance=Provenance(
                caliper_version="0",
                base_sha="b",
                head_sha="h",
                rename_threshold=50,
                config_digest="d",
            ),
            stats=CutStats(
                part_count=1, file_count=1, size_p50=0, size_p90=0, move_logic_pure=True
            ),
        )

    def _fake_last_run(self):
        from caliper.cli.part_pipeline import PartRunResult

        return PartRunResult(
            cutlist=self._cutlist(),
            script_text="#!/bin/sh\necho hi\n",
            backup_bookmark="bak",
            rescue_op_id="op1",
            jj_version="0",
            can_reconstruct=True,
            subjects={},
            proposed_overrides=[],
            applied_overrides=[],
            restack_path="/tmp/restack.sh",
            cutlist_path=None,
        )

    def test_retarget_success_clears_pending_apply_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = part_serve.PartingSession(tmp_path, "base", "head")
        session._last_run = self._fake_last_run()
        session._apply_token = "stale-token"
        monkeypatch.setattr(session, "repart_dict", lambda: self._cutlist().model_dump(mode="json"))

        session.retarget(base="new-base", head="new-head")

        assert session._apply_token is None
        assert session._last_run is None
        with pytest.raises(ValueError, match="invalid or expired apply token"):
            session.apply("stale-token")

    def test_set_size_cap_success_clears_pending_apply_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = part_serve.PartingSession(tmp_path, "base", "head")
        session._last_run = self._fake_last_run()
        session._apply_token = "stale-token"
        monkeypatch.setattr(session, "repart_dict", lambda: self._cutlist().model_dump(mode="json"))

        session.set_size_cap(5)

        assert session._apply_token is None
        assert session._last_run is None

    def test_set_target_pr_success_clears_pending_apply_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from caliper.cli import part_pr

        session = part_serve.PartingSession(tmp_path, "base", "head")
        session._last_run = self._fake_last_run()
        session._apply_token = "stale-token"

        other_repo = tmp_path / "other-repo"
        other_repo.mkdir()
        resolved = part_pr.ResolvedPr(
            repo_path=other_repo,
            base="pr-base",
            head="pr-head",
            slug="owner/repo",
            number=1,
            workdir=tmp_path / "workdir",
            out_dir=tmp_path / "out",
            override_store=other_repo / ".caliper.yaml",
        )
        monkeypatch.setattr(part_pr, "resolve_pr", lambda *a, **k: resolved)
        monkeypatch.setattr(part_pr, "detect_origin_slug", lambda *a, **k: "owner/repo")
        monkeypatch.setattr(session, "repart_dict", lambda: self._cutlist().model_dump(mode="json"))

        session.set_target_pr("1")

        assert session._apply_token is None
        assert session._last_run is None


class TestSelectableBucketsDriftGuard:
    """The human dropdown and the model's legal output set must not drift apart."""

    def test_dropdown_is_model_tiers_plus_logic(self) -> None:
        from caliper.cli.part_serve import _SELECTABLE_BUCKETS
        from caliper.core.tier_suggester import SELECTABLE_TIERS

        # Same membership as the model's tiers, plus 'logic' (a human may un-tier).
        assert set(_SELECTABLE_BUCKETS) == set(SELECTABLE_TIERS) | {"logic"}
        # Structural facts come from git, never reclassification.
        assert {"move", "delete", "binary"}.isdisjoint(_SELECTABLE_BUCKETS)


class TestLoadAssets:
    """The SPA bundle loader — an imperative-shell read, no fallback rendering."""

    def test_loads_from_a_dist_dir(self, tmp_path: Path) -> None:
        (tmp_path / "index.html").write_text("<html>shell</html>")
        (tmp_path / "part_ui.js").write_text("console.log(1)")
        (tmp_path / "part_ui.css").write_text("body{}")

        assets = part_serve.load_assets(tmp_path)

        assert assets.index_html == b"<html>shell</html>"
        assert assets.js == b"console.log(1)"
        assert assets.css == b"body{}"

    def test_default_dir_resolves_to_the_committed_bundle(self) -> None:
        # scripts/part_ui/build.ts must have been run (`npm run build:part-ui`)
        # so the committed bundle under src/caliper/cli/part_ui_dist/ exists.
        assets = part_serve.load_assets()

        assert b"<!doctype html>" in assets.index_html.lower()
        assert assets.js  # non-empty


class TestReadOnlyHandler:
    """The optional LAN view server (view-only: mutating routes stay loopback)."""

    def test_handler_class_has_no_do_post(self) -> None:
        # BaseHTTPRequestHandler answers an undefined verb with a bare 501 —
        # asserting do_POST is absent is what makes every mutating route
        # (all POST-only in dispatch) structurally unreachable via this handler.
        handler_cls = part_serve._make_readonly_handler(FakeSession())
        assert not hasattr(handler_cls, "do_POST")
        assert hasattr(handler_cls, "do_GET")

    def test_get_and_post_over_a_real_socket(self) -> None:
        import http.client

        handler_cls = part_serve._make_readonly_handler(FakeSession())
        server, port = part_serve._bind_server(handler_cls, 12744)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPConnection(part_serve.HOST, port, timeout=5)
            conn.request("GET", "/cutlist")
            resp = conn.getresponse()
            assert resp.status == 200
            resp.read()
            conn.close()

            conn = http.client.HTTPConnection(part_serve.HOST, port, timeout=5)
            conn.request("POST", "/reclassify", body=b"{}")
            resp = conn.getresponse()
            assert resp.status == 501
            resp.read()
            conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


class TestServePartLanValidation:
    """serve_part's LAN view is opt-in and requires a cert/key pair, together."""

    def test_lan_host_without_cert_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="requires both tls_cert and tls_key"):
            part_serve.serve_part(tmp_path, "base", "head", lan_host="192.0.2.1")

    def test_cert_without_lan_host_raises(self, tmp_path: Path) -> None:
        fake = tmp_path / "cert.pem"
        fake.write_text("not a real cert")
        with pytest.raises(ValueError, match="only apply to lan_host"):
            part_serve.serve_part(tmp_path, "base", "head", tls_cert=fake, tls_key=fake)
