"""Regression guard for #203: make test bind mount hiding container-built uv environment.

Bug (FIXED): Dockerfile.test built the uv venv under /workspace, but make test
bind-mounted the host checkout over /workspace:ro, hiding the container-built
environment. Tests ran against host-visible state rather than the image-built
venv, breaking the deterministic container-only test standard.

Fix: UV_PROJECT_ENVIRONMENT=/opt/test-venv anchors the venv outside /workspace.
The make test target invokes /opt/test-venv/bin/python directly without a bind mount.

These are regression guards — they PASS while the fix is in place and FAIL if
someone reverts the Dockerfile or Makefile back to the broken pattern.
See issues #203 and #237.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def _read(relative_path: str) -> str:
    return (_REPO / relative_path).read_text(encoding="utf-8")


def _extract_makefile_target(content: str, target: str) -> str:
    """Return the recipe lines for a specific Makefile target."""
    lines = content.splitlines()
    in_target = False
    recipe: list[str] = []
    for line in lines:
        if re.match(rf"^{re.escape(target)}[\s:]", line):
            in_target = True
            continue
        if in_target:
            if line and not line[0].isspace():
                break
            recipe.append(line)
    return "\n".join(recipe)


class TestDockerfileTestVenvAnchor:
    """Dockerfile.test must anchor the uv venv outside /workspace."""

    def test_uv_project_environment_is_set(self) -> None:
        """Dockerfile.test must declare UV_PROJECT_ENVIRONMENT.

        Without it, uv defaults to placing the venv under /workspace. When
        make test bind-mounts the host checkout over /workspace:ro the
        container-built venv is invisible and tests run against whatever
        host-side state is present.
        """
        content = _read("Dockerfile.test")
        assert "UV_PROJECT_ENVIRONMENT=" in content, (
            "Dockerfile.test is missing UV_PROJECT_ENVIRONMENT. "
            "Add: ENV UV_PROJECT_ENVIRONMENT=/opt/test-venv "
            "so the venv lives outside the bind-mount path. See issue #203."
        )

    def test_uv_project_environment_not_under_workspace(self) -> None:
        """UV_PROJECT_ENVIRONMENT must point outside /workspace."""
        content = _read("Dockerfile.test")
        match = re.search(r"UV_PROJECT_ENVIRONMENT=([^\s\\]+)", content)
        assert match is not None, "UV_PROJECT_ENVIRONMENT not found (see previous test)"
        venv_path = match.group(1)
        assert not venv_path.startswith("/workspace"), (
            f"UV_PROJECT_ENVIRONMENT={venv_path!r} is under /workspace. "
            "A read-only bind mount will shadow this path, hiding the "
            "container-built venv. Use a path outside /workspace (e.g. /opt/test-venv). "
            "See issue #203."
        )

    def test_virtual_env_not_under_workspace(self) -> None:
        """VIRTUAL_ENV must also be set outside /workspace to match UV_PROJECT_ENVIRONMENT."""
        content = _read("Dockerfile.test")
        match = re.search(r"VIRTUAL_ENV=([^\s\\]+)", content)
        assert match is not None, (
            "Dockerfile.test is missing VIRTUAL_ENV. "
            "Set it to match UV_PROJECT_ENVIRONMENT so uv and the entrypoint "
            "agree on the venv path. See issue #203."
        )
        venv_path = match.group(1)
        assert not venv_path.startswith("/workspace"), (
            f"VIRTUAL_ENV={venv_path!r} is under /workspace. "
            "Fix: set VIRTUAL_ENV to match UV_PROJECT_ENVIRONMENT outside /workspace."
        )


class TestMakefileTestTarget:
    """make test must invoke the image-built venv directly, without a workspace bind mount."""

    def test_make_test_references_opt_test_venv(self) -> None:
        """The make test recipe must invoke /opt/test-venv/bin/python.

        The fix for #203 removed the -v bind mount from make test and changed the
        entrypoint to call /opt/test-venv/bin/python directly. If this reverts to
        bare 'python' or 'uv run' without anchoring the venv, the host environment
        can leak in. See issue #203.
        """
        content = _read("Makefile")
        recipe = _extract_makefile_target(content, "test")
        # The recipe may delegate to the warm-runner script; the anchor must then
        # live on that script's container run line instead.
        anchored_in = recipe
        if "scripts/test-run.sh" in recipe:
            anchored_in = _read("scripts/test-run.sh")
        assert "/opt/test-venv/bin/python" in anchored_in, (
            "Neither the make test recipe nor scripts/test-run.sh references "
            "/opt/test-venv/bin/python. The test path must invoke the container-built "
            "venv directly. Regression of #203: host state can shadow the container "
            "environment. Fix: use /opt/test-venv/bin/python -m pytest in the recipe "
            "or in scripts/test-run.sh."
        )

    def test_make_test_does_not_bind_mount_workspace_without_venv_guard(self) -> None:
        """make test must not bind-mount /workspace unless the venv is anchored outside it.

        The root cause of #203 was: -v "$(CURDIR):/workspace:ro" shadowed the
        container-built uv environment. If a bind mount is reintroduced, the venv
        must be guaranteed to live outside /workspace via UV_PROJECT_ENVIRONMENT.
        """
        content = _read("Makefile")
        recipe = _extract_makefile_target(content, "test")
        has_workspace_mount = bool(re.search(r"-v\s+[\"']?[^\"'\s]*:/workspace", recipe))
        if has_workspace_mount:
            # Bind mount is present — only acceptable if the venv is explicitly outside it
            assert "/opt/test-venv" in recipe or "UV_PROJECT_ENVIRONMENT" in recipe, (
                "make test bind-mounts /workspace but does not anchor the venv "
                "outside it via /opt/test-venv or UV_PROJECT_ENVIRONMENT. "
                "This reproduces issue #203: the host mount shadows the "
                "container-built venv. Remove the bind mount or set "
                "UV_PROJECT_ENVIRONMENT to a path outside /workspace."
            )
