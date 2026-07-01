"""End-to-end parting test against a REAL jj (skips when jj is absent).

# tested-by: tests/integration/test_part_e2e.py

Builds a colocated jj+git repo with a known ``base..head`` and drives the actual
``caliper part`` CLI. Verifies the cut list, the restack.sh (parses as shell and,
when executed against real jj, reconstructs head exactly), that the cut list is
identical under ``--target stack`` and ``--target series``, and that the run is
fully reversible via ``jj op restore``.

This covers acceptance tests 14/16/17 against a live substrate. The fake-runner
unit tests (test_part_gate, test_part_script, test_part_stock) remain the
container-runnable coverage; this one runs wherever jj is installed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from caliper.cli.part_cmd import part

pytestmark = pytest.mark.skipif(
    not (shutil.which("jj") and shutil.which("git") and shutil.which("bash")),
    reason="real-jj end-to-end test requires jj, git and bash on PATH",
)


def _run(cmd: list[str], cwd: Path, env: dict) -> str:
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    assert proc.returncode == 0, f"{' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}"
    return proc.stdout


@pytest.fixture()
def colocated_repo(tmp_path: Path):
    w = tmp_path / "repo"
    w.mkdir()
    cfg = tmp_path / "jjconfig.toml"
    cfg.write_text('[user]\nname = "t"\nemail = "t@t"\n')
    env = {
        **os.environ,
        "JJ_CONFIG": str(cfg),
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    _run(["git", "init", "-q", "."], w, env)
    _run(["git", "config", "user.email", "t@t"], w, env)
    _run(["git", "config", "user.name", "t"], w, env)

    # base commit
    (w / "a.py").write_text("base\n")
    (w / "keep.py").write_text("keep\n")
    (w / "old.py").write_text("old\n")
    _run(["git", "add", "-A"], w, env)
    _run(["git", "commit", "-qm", "base"], w, env)
    base = _run(["git", "rev-parse", "HEAD"], w, env).strip()

    # head commit: modify a.py, add lock + b.py + config, delete keep.py, rename old->new
    (w / "a.py").write_text("base\nmore\n")
    (w / "poetry.lock").write_text("lock\n")
    (w / "b.py").write_text("b\n")
    (w / "settings.yaml").write_text("k: v\n")
    _run(["git", "rm", "-q", "keep.py"], w, env)
    _run(["git", "mv", "old.py", "new.py"], w, env)
    _run(["git", "add", "-A"], w, env)
    _run(["git", "commit", "-qm", "head"], w, env)
    head = _run(["git", "rev-parse", "HEAD"], w, env).strip()

    # colocate jj (creates an empty clean working-copy commit on top of head)
    _run(["jj", "git", "init", "--colocate", "."], w, env)
    return w, base, head, env


def _invoke(repo: Path, base: str, head: str, out: Path, target: str = "stack"):
    runner = CliRunner()
    return runner.invoke(
        part,
        [
            "--base",
            base,
            "--head",
            head,
            "--repo",
            str(repo),
            "--out",
            str(out),
            "--target",
            target,
        ],
        catch_exceptions=False,
    )


def test_caliper_part_produces_cutlist_and_valid_script(colocated_repo, tmp_path) -> None:
    repo, base, head, env = colocated_repo
    out = tmp_path / "stack"
    result = _invoke(repo, base, head, out, "stack")
    assert result.exit_code == 0, result.output

    cut = json.loads((out / "cutlist.json").read_text())
    by_bucket = {tuple(p["files"][0:1] or [""])[0]: p["bucket"] for p in cut["parts"]}
    # classification of the known diff
    assert by_bucket["poetry.lock"] == "generated"
    assert by_bucket["new.py"] == "move"
    assert by_bucket["settings.yaml"] == "config"
    assert by_bucket["gone.py" if False else "keep.py"] == "delete"
    # provenance stamped + revsets pinned to commit ids
    assert cut["provenance"]["base_sha"] == base
    assert cut["provenance"]["head_sha"] == head
    assert cut["provenance"]["resolved_revsets"]["head"] == head

    script = (out / "restack.sh").read_text()
    assert script.splitlines()[0] == "#!/usr/bin/env bash"
    assert "jj op restore" in script  # rollback header present
    proc = subprocess.run(["bash", "-n", str(out / "restack.sh")], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_cut_list_identical_across_targets(colocated_repo, tmp_path) -> None:
    repo, base, head, env = colocated_repo
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    assert _invoke(repo, base, head, out_a, "stack").exit_code == 0
    assert _invoke(repo, base, head, out_b, "series").exit_code == 0

    cut_a = json.loads((out_a / "cutlist.json").read_text())
    cut_b = json.loads((out_b / "cutlist.json").read_text())
    assert cut_a["parts"] == cut_b["parts"]  # identical cut list...
    # ...but the scripts differ (bookmark strategy)
    assert (out_a / "restack.sh").read_text() != (out_b / "restack.sh").read_text()


def test_backup_bookmark_created_by_gate_before_script(colocated_repo, tmp_path) -> None:
    """Gate success => the backup bookmark exists immediately after `caliper part`
    (before any restack execution), and the emitted script does NOT create it —
    proving it was the gate, created before script emission."""
    repo, base, head, env = colocated_repo
    out = tmp_path / "o"
    assert _invoke(repo, base, head, out, "stack").exit_code == 0
    # backup exists right after the CLI returns, with no restack executed yet,
    # and it anchors the base (not the tip).
    backup = _backup_bookmark(repo, env)
    backup_commit = _run(
        ["jj", "log", "-r", backup, "--no-graph", "-T", "commit_id"], repo, env
    ).strip()
    assert backup_commit == base
    # the script never creates/moves the backup (only references it in a comment)
    for line in (out / "restack.sh").read_text().splitlines():
        if not line.lstrip().startswith("#"):
            assert "caliper-part-backup-" not in line


def test_restack_reconstructs_head_then_rolls_back(colocated_repo, tmp_path) -> None:
    repo, base, head, env = colocated_repo
    out = tmp_path / "o"
    assert _invoke(repo, base, head, out, "stack").exit_code == 0

    pre_op = _run(["jj", "op", "log", "--no-graph", "--limit", "1", "-T", "id"], repo, env).strip()

    # Execute the generated restack script against real jj.
    proc = subprocess.run(
        ["bash", str(out / "restack.sh")], cwd=repo, env=env, capture_output=True, text=True
    )
    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"

    # The top of the reconstructed stack reproduces head exactly (empty diff).
    new_top = _run(["jj", "log", "-r", "@", "--no-graph", "-T", "commit_id"], repo, env).strip()
    diff = _run(["git", "diff", "--stat", head, new_top], repo, env).strip()
    assert diff == "", f"reconstructed stack differs from head:\n{diff}"
    # the stack was built (per-part bookmarks exist)
    assert "caliper-part-1" in _run(["jj", "bookmark", "list"], repo, env)

    # Fully reversible: restore to the pre-execution operation.
    _run(["jj", "op", "restore", pre_op], repo, env)
    assert "caliper-part-1" not in _run(["jj", "bookmark", "list"], repo, env)


# ---------------------------------------------------------------------------
# Rename round-trip hardening — path-granular restore is most fragile for
# renames (restore old+new path, delete old). Assert the rebuilt top equals
# head BYTE-FOR-BYTE, not merely that the file set matches.
# ---------------------------------------------------------------------------


def _env(tmp_path: Path, name: str) -> dict:
    cfg = tmp_path / f"{name}-jjconfig.toml"
    cfg.write_text('[user]\nname = "t"\nemail = "t@t"\n')
    return {
        **os.environ,
        "JJ_CONFIG": str(cfg),
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def _build_colocated(
    tmp_path: Path,
    name: str,
    base_files: dict[str, str],
    *,
    renames: list[tuple[str, str]] = (),
    head_writes: dict[str, str] | None = None,
    deletes: list[str] = (),
):
    """Build a colocated jj+git repo with a base commit and a head commit."""
    w = tmp_path / name
    w.mkdir()
    env = _env(tmp_path, name)
    _run(["git", "init", "-q", "."], w, env)
    _run(["git", "config", "user.email", "t@t"], w, env)
    _run(["git", "config", "user.name", "t"], w, env)
    for rel, content in base_files.items():
        _write(w, rel, content)
    _run(["git", "add", "-A"], w, env)
    _run(["git", "commit", "-qm", "base"], w, env)
    base = _run(["git", "rev-parse", "HEAD"], w, env).strip()

    for old, new in renames:
        (w / new).parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "mv", old, new], w, env)
    for rel, content in (head_writes or {}).items():
        _write(w, rel, content)
    for d in deletes:
        _run(["git", "rm", "-q", d], w, env)
    _run(["git", "add", "-A"], w, env)
    _run(["git", "commit", "-qm", "head"], w, env)
    head = _run(["git", "rev-parse", "HEAD"], w, env).strip()

    _run(["jj", "git", "init", "--colocate", "."], w, env)
    return w, base, head, env


def _exec_restack(repo: Path, out: Path, env: dict) -> str:
    """Run the emitted restack.sh and return the commit id of the rebuilt top (@)."""
    proc = subprocess.run(
        ["bash", str(out / "restack.sh")], cwd=repo, env=env, capture_output=True, text=True
    )
    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
    return _run(["jj", "log", "-r", "@", "--no-graph", "-T", "commit_id"], repo, env).strip()


def _trees_identical(repo: Path, env: dict, a: str, b: str) -> bool:
    """True when commits *a* and *b* have byte-identical trees (`git diff --quiet`)."""
    return subprocess.run(["git", "diff", "--quiet", a, b], cwd=repo, env=env).returncode == 0


def _files_in(cut: dict, bucket: str | None = None) -> list[str]:
    return [f for p in cut["parts"] if bucket is None or p["bucket"] == bucket for f in p["files"]]


def test_pure_rename_with_referencing_edit_rebuilds_byte_for_byte(tmp_path) -> None:
    """Fixture A: pure rename in one part, a logic edit referencing it in another."""
    repo, base, head, env = _build_colocated(
        tmp_path,
        "renameA",
        base_files={
            "core/module.py": "def greet():\n    return 'hi'\n",
            "main.py": "from core.module import greet\n\nprint(greet())\n",
        },
        renames=[("core/module.py", "core/renamed.py")],  # pure rename (content identical)
        head_writes={"main.py": "from core.renamed import greet\n\nprint(greet())\n"},  # logic edit
    )
    out = tmp_path / "o"
    assert _invoke(repo, base, head, out, "stack").exit_code == 0
    cut = json.loads((out / "cutlist.json").read_text())

    # rename counted once under the new path; old path absent everywhere
    assert "core/renamed.py" in _files_in(cut)
    assert "core/module.py" not in _files_in(cut)
    # new path in a MOVE part; the referencing edit in a LOGIC part
    assert "core/renamed.py" in _files_in(cut, "move")
    assert "main.py" in _files_in(cut, "logic")

    new_top = _exec_restack(repo, out, env)
    assert _trees_identical(repo, env, head, new_top), "rebuilt top diverges from head"


def test_rename_with_subthreshold_delta_rebuilds_byte_for_byte(tmp_path) -> None:
    """Fixture B: rename WITH a content delta below the move-ambiguity threshold."""
    repo, base, head, env = _build_colocated(
        tmp_path,
        "renameB",
        base_files={"lib/old.py": "a\nb\nc\nd\ne\nf\ng\nh\n", "x.py": "x\n"},
        renames=[("lib/old.py", "lib/new.py")],
        head_writes={
            "lib/new.py": "a\nb\nc\nd\ne\nf\ng\nh\ni\n"
        },  # +1 line: small delta, stays move
    )
    out = tmp_path / "o"
    assert _invoke(repo, base, head, out, "stack").exit_code == 0
    cut = json.loads((out / "cutlist.json").read_text())

    assert "lib/new.py" in _files_in(cut)
    assert "lib/old.py" not in _files_in(cut)
    # still classified as a move (delta below move_ambiguity_size, default 50)
    assert "lib/new.py" in _files_in(cut, "move")

    new_top = _exec_restack(repo, out, env)
    assert _trees_identical(repo, env, head, new_top), "rebuilt top diverges from head"


def _backup_bookmark(repo: Path, env: dict) -> str:
    """Return the caliper-part-backup-* bookmark name from `jj bookmark list`."""
    out = _run(["jj", "bookmark", "list"], repo, env)
    for line in out.splitlines():
        name = line.split(":", 1)[0].strip()
        if name.startswith("caliper-part-backup-"):
            return name
    raise AssertionError(f"no backup bookmark found in:\n{out}")


def test_parts_form_linear_chain_backup_plus_to_at(colocated_repo, tmp_path) -> None:
    """Acceptance test 17 (literal ``backup+::@``): after parting, the parts are
    exactly the linear chain ``backup+::@`` with no fork, no empty commit, no
    conflicted commit, and the gate-resolved revset ids appear in provenance.

    The backup bookmark is anchored on ``base``, so its children up to ``@`` are
    precisely the rebuilt parts.
    """
    repo, base, head, env = colocated_repo
    out = tmp_path / "o"
    assert _invoke(repo, base, head, out, "stack").exit_code == 0
    cut = json.loads((out / "cutlist.json").read_text())
    nparts = len(cut["parts"])

    # Gate-resolved revset commit ids are pinned into provenance.
    rr = cut["provenance"]["resolved_revsets"]
    assert rr["base"] == base and rr["head"] == head
    assert all(rr[k] for k in ("base", "head", "@", "trunk"))

    # The backup bookmark anchors the base (so backup+::@ == the parts).
    backup = _backup_bookmark(repo, env)
    backup_commit = _run(
        ["jj", "log", "-r", backup, "--no-graph", "-T", "commit_id"], repo, env
    ).strip()
    assert backup_commit == base

    _exec_restack(repo, out, env)

    rng = f"{backup}+::@"  # the spec's literal linear-chain revset

    def _count(revset: str) -> int:
        out_s = _run(
            ["jj", "log", "-r", revset, "--no-graph", "-T", 'commit_id ++ "\n"'], repo, env
        )
        return len([ln for ln in out_s.splitlines() if ln.strip()])

    assert _count(rng) == nparts  # the parts ARE backup+::@
    assert _count(f"heads({rng})") == 1  # single head: no fork
    assert _count(f"roots({rng})") == 1  # single root: linear chain
    assert _count(f"({rng}) & empty()") == 0  # no empty commit
    assert _count(f"({rng}) & conflicts()") == 0  # no conflicted commit


def test_gate_aborts_on_stray_working_copy_file(colocated_repo, tmp_path) -> None:
    repo, base, head, env = colocated_repo
    (repo / "stray.txt").write_text("oops\n")  # untracked, non-ignored
    result = CliRunner().invoke(
        part, ["--base", base, "--head", head, "--repo", str(repo), "--out", str(tmp_path / "o")]
    )
    assert result.exit_code != 0
    # jj auto-snapshots the stray file into @, so the jj-native dirty check fires
    # first; either way it is a precondition abort with no state change.
    out = result.output.lower()
    assert "precondition failed" in out and ("dirty-tree" in out or "untracked" in out)
    assert "caliper-part-backup-" not in _run(["jj", "bookmark", "list"], repo, env)


# ---------------------------------------------------------------------------
# --serve session (PartingSession) — size cap and the durable override store.
# These drive the REAL session against a real diff (the unit tests use a fake
# session), so a silently-dropped cap or a misrouted override write is caught.
# ---------------------------------------------------------------------------


def _serve_repo(tmp_path: Path, name: str):
    """A repo whose head diff has two big untiered (.py) files plus one doc."""
    return _build_colocated(
        tmp_path,
        name,
        base_files={"svc/a.py": "x\n", "svc/b.py": "x\n", "README.md": "doc\n"},
        head_writes={
            "svc/a.py": "x\n" + "y\n" * 500,
            "svc/b.py": "x\n" + "z\n" * 500,
            "README.md": "doc\n" + "more\n" * 500,
        },
    )


def _bucket_counts(cut) -> dict[str, int]:
    counts: dict[str, int] = {}
    for p in cut.parts:
        counts[p.bucket.value] = counts.get(p.bucket.value, 0) + 1
    return counts


def test_serve_session_uncapped_is_one_part_per_bucket(tmp_path) -> None:
    """The real session with no cap cuts one part per labelled bucket — the big
    .py files do NOT split even though each is ~500 lines."""
    from caliper.cli.part_serve import PartingSession

    repo, base, head, _ = _serve_repo(tmp_path, "serve-uncapped")
    cut = PartingSession(repo, base, head).cut()  # no size_cap => uncapped

    counts = _bucket_counts(cut)
    assert all(c == 1 for c in counts.values()), counts
    assert cut.stats.part_count == len(counts)
    assert cut.size_cap is None


def test_serve_session_size_cap_splits_within_bucket(tmp_path) -> None:
    """Opting into a small cap restores within-bucket splitting in the session."""
    from caliper.cli.part_serve import PartingSession

    repo, base, head, _ = _serve_repo(tmp_path, "serve-capped")
    cut = PartingSession(repo, base, head, size_cap=100).cut()

    logic_parts = [p for p in cut.parts if p.bucket.value == "logic"]
    assert len(logic_parts) > 1, "a small cap splits the untiered .py bucket"


def test_serve_reclassify_persists_to_override_store_not_clone(tmp_path) -> None:
    """sev-5 fix: under --pr the override is written to the durable sidecar store,
    NOT the throwaway clone's .caliper.yaml, and it moves the file's bucket."""
    from caliper.cli.part_serve import PartingSession

    repo, base, head, _ = _serve_repo(tmp_path, "serve-store")
    store = tmp_path / "pr42-overrides"  # sibling of the clone, survives the wipe
    session = PartingSession(repo, base, head, override_store=store)

    cut = session.reclassify(target="svc/*.py", bucket="business")

    biz = [p for p in cut["parts"] if p["bucket"] == "business"]
    assert biz, "the reclassified files land in the business bucket"
    assert any(f.startswith("svc/") for f in biz[0]["files"])
    # written to the sidecar store, clone's config left untouched
    assert (store / ".caliper.yaml").exists()
    assert not (repo / ".caliper.yaml").exists()


def test_serve_override_store_survives_and_relayers(tmp_path) -> None:
    """A new session pointed at an existing store re-applies the override (the
    durable loop): the file stays in its reassigned bucket across runs."""
    from caliper.cli.part_serve import PartingSession

    repo, base, head, _ = _serve_repo(tmp_path, "serve-relayer")
    store = tmp_path / "pr42-overrides"
    PartingSession(repo, base, head, override_store=store).reclassify(
        target="svc/*.py", bucket="data"
    )

    # fresh session (simulates the next `part --pr --serve` run) reads the store
    cut = PartingSession(repo, base, head, override_store=store).cut()
    data_files = [f for p in cut.parts if p.bucket.value == "data" for f in p.files]
    assert "svc/a.py" in data_files and "svc/b.py" in data_files


def test_serve_session_generate_writes_restack_and_apply_token(tmp_path) -> None:
    """The web sidecar's generate() runs the real gate + pipeline (P4 parity with
    the CLI): restack.sh + cutlist.json land in out_dir with a rollback header,
    and each call mints a fresh apply_token."""
    from caliper.cli.part_serve import PartingSession

    repo, base, head, _ = _serve_repo(tmp_path, "serve-generate")
    out_dir = tmp_path / "out"
    session = PartingSession(repo, base, head, out_dir=out_dir)

    result = session.generate()

    assert result["backup_bookmark"].startswith("caliper-part-backup-")
    assert result["rescue_op_id"]
    script = (out_dir / "restack.sh").read_text()
    assert script == result["script_text"]
    assert "jj op restore" in script
    assert (out_dir / "cutlist.json").exists()
    assert result["apply_token"]
    assert session.restack_script() == script

    second = session.generate()
    assert second["apply_token"] != result["apply_token"]


def test_serve_session_apply_runs_restack_then_rollback_restores(tmp_path, monkeypatch) -> None:
    """P5: /apply executes the generated restack.sh for real (bash + jj), then
    /rollback undoes it via `jj op restore <rescue_op_id>` — the full escape
    hatch the rollback header promises. The apply token is single-use.

    Uses a *relative* out_dir with the process cwd deliberately different from
    repo_path (as a relative `--out` would be relative to the invocation
    directory, not the repo) — regression coverage for apply() resolving
    restack_path against the wrong root before running `bash <path>`.
    """
    from caliper.cli.part_serve import PartingSession

    repo, base, head, env = _serve_repo(tmp_path, "serve-apply")
    monkeypatch.chdir(tmp_path)
    out_dir = Path("out")
    session = PartingSession(repo, base, head, out_dir=out_dir)

    result = session.generate()
    token = result["apply_token"]

    applied = session.apply(token)

    assert applied["ok"] is True, applied["stderr"]
    assert applied["rollback"]["rescue_op_id"] == result["rescue_op_id"]
    # per-part bookmarks exist -> the restack script really ran against jj
    assert "caliper-part-1" in _run(["jj", "bookmark", "list"], repo, env)

    # single-use: replaying the same token is rejected, never re-applied
    with pytest.raises(ValueError):
        session.apply(token)

    rolled_back = session.rollback()

    assert rolled_back["ok"] is True, rolled_back["stderr"]
    assert "caliper-part-1" not in _run(["jj", "bookmark", "list"], repo, env)
