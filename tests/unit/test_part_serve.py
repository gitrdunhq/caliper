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

    def cut_dict(self) -> dict:
        return _FAKE_CUT

    def repart_dict(self) -> dict:
        self.reparted += 1
        return _FAKE_CUT

    def reclassify(self, *, target: str, bucket: str, note: str = "") -> dict:
        if self.raise_on_reclassify is not None:
            raise self.raise_on_reclassify
        self.reclassified.append((target, bucket))
        return _FAKE_CUT

    def overrides(self) -> list[dict]:
        return []

    def suggest_dict(self) -> dict:
        self.suggest_calls += 1
        return {"suggestions": self.suggestions, "configured": self.suggest_configured}


def _post(session: FakeSession, path: str, payload: dict):
    return dispatch(session, "POST", path, orjson.dumps(payload))


def _body(resp) -> dict:
    return orjson.loads(resp.body)


class TestDispatch:
    def test_index_renders_html(self) -> None:
        resp = dispatch(FakeSession(), "GET", "/", b"")
        assert resp.status == 200
        assert "text/html" in resp.content_type
        assert b"logic" in resp.body  # the part bucket is rendered

    def test_cutlist_returns_json(self) -> None:
        resp = dispatch(FakeSession(), "GET", "/cutlist", b"")
        assert resp.status == 200
        assert _body(resp)["parts"][0]["id"] == "p1"

    def test_reclassify_writes_override_and_returns_cut(self) -> None:
        session = FakeSession()
        resp = _post(session, "/reclassify", {"file": "src/app.py", "bucket": "business"})
        assert resp.status == 200
        assert session.reclassified == [("src/app.py", "business")]
        assert _body(resp)["parts"][0]["bucket"] == "logic"

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

    def test_index_renders_suggest_button(self) -> None:
        # The toolbar offers the advisory pass and a target for its chips.
        resp = dispatch(FakeSession(), "GET", "/", b"")
        assert b"suggest tiers" in resp.body
        assert b'id="suggestions"' in resp.body

    def test_unknown_route_is_404(self) -> None:
        resp = dispatch(FakeSession(), "GET", "/nope", b"")
        assert resp.status == 404

    def test_query_string_is_ignored_by_handler(self) -> None:
        # The handler strips the query string before dispatch; dispatch matches the bare path.
        resp = dispatch(FakeSession(), "GET", "/cutlist", b"")
        assert resp.status == 200


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


class TestRenderReport:
    """The report renderer is a pure function — no starlette, runs everywhere."""

    def test_renders_part_buckets_and_files(self) -> None:
        from caliper.cli.part_serve import render_report

        out = render_report(_FAKE_CUT)
        assert "<!doctype html>" in out.lower()
        assert "src/app.py" in out
        assert "deadbeefcafe" in out  # config digest stamped

    def test_header_summarizes_buckets_and_cap(self) -> None:
        # A no-cap cut must read as intentional ("1 part/bucket"), not broken.
        from caliper.cli.part_serve import render_report

        uncapped = {**_FAKE_CUT, "size_cap": None}
        out = render_report(uncapped)
        assert "1 bucket" in out  # one labelled bucket of concern
        assert "cap none (1 part/bucket)" in out

    def test_header_shows_numeric_cap_when_set(self) -> None:
        from caliper.cli.part_serve import render_report

        out = render_report(_FAKE_CUT)  # size_cap=400
        assert "cap 400" in out
        assert "1 part/bucket" not in out

    def test_offers_every_selectable_bucket(self) -> None:
        from caliper.cli.part_serve import _SELECTABLE_BUCKETS, render_report

        out = render_report(_FAKE_CUT)
        for bucket in _SELECTABLE_BUCKETS:
            assert f'<option value="{bucket}"' in out
        # Structural buckets are decided by git — never offered for reclassification.
        for structural in ("delete", "move", "binary"):
            assert f'<option value="{structural}"' not in out

    def test_untiered_part_is_flagged(self) -> None:
        from caliper.cli.part_serve import render_report

        out = render_report(_FAKE_CUT)  # the only part is bucket "logic"
        assert "needs a tier" in out
        assert "untiered" in out

    def test_per_file_reclassify_controls_present(self) -> None:
        from caliper.cli.part_serve import render_report

        out = render_report(_FAKE_CUT)
        assert '<select class="bucket">' in out
        assert "/reclassify" in out  # the JS posts to it
        assert "/repart" in out

    def test_glob_suggestion_broadens_nested_path(self) -> None:
        from caliper.cli.part_serve import _suggest_glob

        assert _suggest_glob("src/ui/app.py") == "src/ui/**"
        assert _suggest_glob("README.md") == "README.md"  # top-level: itself

    def test_override_badges_rendered(self) -> None:
        from caliper.cli.part_serve import render_report

        out = render_report(_FAKE_CUT, overrides=[{"glob": "src/ui/**", "bucket": "frontend"}])
        assert "active overrides" in out
        assert "src/ui/**" in out

    def test_no_overrides_shows_empty_hint(self) -> None:
        from caliper.cli.part_serve import render_report

        out = render_report(_FAKE_CUT, overrides=[])
        assert "no overrides yet" in out

    def test_defensive_on_empty_cut(self) -> None:
        """A partial/empty cut still renders without raising."""
        from caliper.cli.part_serve import render_report

        out = render_report({})
        assert "<!doctype html>" in out.lower()


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


class TestSelectableBucketsDriftGuard:
    """The human dropdown and the model's legal output set must not drift apart."""

    def test_dropdown_is_model_tiers_plus_logic(self) -> None:
        from caliper.cli.part_serve import _SELECTABLE_BUCKETS
        from caliper.core.tier_suggester import SELECTABLE_TIERS

        # Same membership as the model's tiers, plus 'logic' (a human may un-tier).
        assert set(_SELECTABLE_BUCKETS) == set(SELECTABLE_TIERS) | {"logic"}
        # Structural facts come from git, never reclassification.
        assert {"move", "delete", "binary"}.isdisjoint(_SELECTABLE_BUCKETS)
