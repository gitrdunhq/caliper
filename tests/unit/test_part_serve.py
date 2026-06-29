"""Tests for the localhost reclassify sidecar — ``caliper part --serve``.

# tested-by: tests/unit/test_part_serve.py

Two seams are tested independently:

* ``write_override`` — the deterministic write-back into ``.caliper.yaml``. No
  git, no server: a tmp repo dir is enough. This is the feedback loop's only
  mutation, so it carries the Idempotency property (applying the same override
  twice is the same as once).
* ``build_part_serve_app`` — the Starlette routes, driven by a fake session so
  the HTTP layer is tested without a real repo / git / re-part.

Property domains (DPS-12):
  Idempotency   INVARIANT  applying the same override twice == once
  Confidentiality/Isolation  SAFETY  the server binds loopback only (127.0.0.1)
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from caliper.cli import part_serve
from caliper.cli.part_serve import build_part_serve_app, write_override
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
# Starlette routes — driven by a fake session (no git, no real re-part)
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


@pytest.fixture
def client_and_session():
    # starlette ships only with caliper[copilot]; the app tests skip without it,
    # while the write_override + loopback tests run regardless (no starlette needed).
    testclient = pytest.importorskip(
        "starlette.testclient", reason="starlette not installed (caliper[copilot])"
    )
    session = FakeSession()
    app = build_part_serve_app(session)
    return testclient.TestClient(app), session


class TestPartServeApp:
    def test_index_renders_html(self, client_and_session) -> None:
        client, _ = client_and_session
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "logic" in resp.text  # the part bucket is rendered

    def test_cutlist_returns_json(self, client_and_session) -> None:
        client, _ = client_and_session
        resp = client.get("/cutlist")
        assert resp.status_code == 200
        assert resp.json()["parts"][0]["id"] == "p1"

    def test_reclassify_writes_override_and_returns_cut(self, client_and_session) -> None:
        client, session = client_and_session
        resp = client.post("/reclassify", json={"file": "src/app.py", "bucket": "business"})
        assert resp.status_code == 200
        assert session.reclassified == [("src/app.py", "business")]
        assert resp.json()["parts"][0]["bucket"] == "logic"

    def test_reclassify_accepts_glob(self, client_and_session) -> None:
        client, session = client_and_session
        client.post("/reclassify", json={"glob": "src/**", "bucket": "frontend"})
        assert session.reclassified == [("src/**", "frontend")]

    def test_reclassify_missing_bucket_is_400(self, client_and_session) -> None:
        client, session = client_and_session
        resp = client.post("/reclassify", json={"file": "src/app.py"})
        assert resp.status_code == 400
        assert session.reclassified == []

    def test_reclassify_missing_target_is_400(self, client_and_session) -> None:
        client, _ = client_and_session
        resp = client.post("/reclassify", json={"bucket": "frontend"})
        assert resp.status_code == 400

    def test_reclassify_validation_error_is_400(self, client_and_session) -> None:
        client, session = client_and_session
        session.raise_on_reclassify = ValueError("override bucket 'delete' is structural")
        resp = client.post("/reclassify", json={"file": "x", "bucket": "delete"})
        assert resp.status_code == 400
        assert "structural" in resp.json()["error"]

    def test_repart_triggers_repart(self, client_and_session) -> None:
        client, session = client_and_session
        resp = client.post("/repart")
        assert resp.status_code == 200
        assert session.reparted == 1


class TestLoopbackOnly:
    def test_host_is_loopback(self) -> None:
        """Isolation SAFETY: the sidecar binds loopback, never 0.0.0.0."""
        assert part_serve.HOST == "127.0.0.1"
        assert part_serve.HOST != "0.0.0.0"

    def test_default_port_in_dev_range(self) -> None:
        assert 12000 <= part_serve.DEFAULT_PORT <= 13000
