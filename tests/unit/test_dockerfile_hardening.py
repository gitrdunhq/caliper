"""Runtime image hardening (hexops Dockerfile best practices).
# tested-by: tests/unit/test_dockerfile_hardening.py

Non-root with a static UID/GID >= 10000 (host-side `chown 10000:10001` always
works and never collides with a privileged host user), tini as PID 1 so the
scanners' child processes (java, node, opengrep) can never leave zombies, and
CMD carrying only arguments so `podman run caliper --help` just works.
"""

from __future__ import annotations

import re
from pathlib import Path

_DOCKERFILE = Path(__file__).resolve().parents[2] / "Dockerfile"


def _runtime_stage() -> str:
    text = _DOCKERFILE.read_text(encoding="utf-8")
    start = text.index("AS runtime\n")
    end = text.index("FROM runtime AS e2e-test")
    return text[start:end]


def test_runtime_user_is_static_uid_10000_gid_10001() -> None:
    stage = _runtime_stage()
    assert re.search(r"groupadd\s+(?:-r\s+)?-g\s+10001\s+caliper", stage)
    assert re.search(r"useradd\s+.*-u\s+10000\s+.*caliper", stage)
    assert "USER caliper" in stage or "USER 10000" in stage


def test_user_switch_happens_before_entrypoint() -> None:
    stage = _runtime_stage()
    assert stage.index("USER caliper") < stage.index("ENTRYPOINT")


def test_tini_is_pid_1_and_cmd_holds_only_arguments() -> None:
    stage = _runtime_stage()
    assert "tini" in stage.split("apt-get install")[1].split("\n\n")[0]
    m = re.search(r"^ENTRYPOINT \[(.*)\]$", stage, re.M)
    assert m and m.group(1).startswith('"/usr/bin/tini", "--", '), m.group(0) if m else None
    c = re.search(r"^CMD \[(.*)\]$", stage, re.M)
    assert c and not any(
        tok.strip('" ').startswith("/") for tok in c.group(1).split(",")
    ), "CMD must carry arguments only, never the binary"
