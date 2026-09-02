"""release-please workflow and docs rename guard (task-014).
# tested-by: tests/test_release-please.py

Caliper's PyPI *distribution* name is being renamed to ``caliper-review``
(task-013 renamed ``pyproject.toml``). This module checks that the release
workflow's publish job and the human-facing docs (README, CAPABILITIES) are
updated to match — otherwise the release environment URL and install
instructions keep pointing at the old, no-longer-published ``caliper``
distribution.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[1]


def _read(rel_path: str) -> str:
    return (_REPO / rel_path).read_text()


class TestTask014ReleasePleaseRename:
    def test_ac1_release_please_yml_publish_job_environment_url_references_caliper_review(
        self,
    ):
        """AC1: release-please.yml's publish job environment.url references
        'caliper-review' instead of 'caliper'."""
        workflow = yaml.safe_load(_read(".github/workflows/release-please.yml"))
        publish_job = workflow["jobs"]["publish"]
        environment_url = publish_job["environment"]["url"]
        assert "caliper-review" in environment_url, (
            f"expected publish job environment.url to reference the "
            f"'caliper-review' distribution, got {environment_url!r}"
        )
        assert environment_url != "https://pypi.org/project/caliper/", (
            "expected publish job environment.url to no longer reference "
            "the old 'caliper' distribution"
        )

    def test_ac2_readme_install_instructions_reference_caliper_review(self):
        """AC2: README.md install instructions (pip install ...) reference
        'caliper-review'."""
        readme = _read("README.md")
        assert "pip install caliper-review" in readme, (
            "expected README.md to document `pip install caliper-review` "
            "as the install instruction"
        )

    def test_ac3_capabilities_md_install_instructions_reference_caliper_review(self):
        """AC3: docs/CAPABILITIES.md install instructions reference
        'caliper-review'."""
        capabilities = _read("docs/CAPABILITIES.md")
        assert "pip install caliper-review" in capabilities, (
            "expected docs/CAPABILITIES.md to document "
            "`pip install caliper-review` as the install instruction"
        )

    def test_ac4_readme_documents_trusted_publisher_registration(self):
        """AC4: README documents that the PyPI trusted publisher must be
        registered by the owner for repo gitrdunhq/caliper, workflow
        release-please.yml, environment pypi."""
        readme = _read("README.md")
        assert "gitrdunhq/caliper" in readme, (
            "expected README.md to name the repo (gitrdunhq/caliper) that "
            "must register the PyPI trusted publisher"
        )
        assert "release-please.yml" in readme, (
            "expected README.md to name the workflow (release-please.yml) "
            "for the PyPI trusted publisher registration"
        )
        assert (
            "trusted publisher" in readme.lower()
        ), "expected README.md to document the PyPI trusted publisher registration requirement"
        trusted_publisher_idx = readme.lower().index("trusted publisher")
        nearby = readme[max(0, trusted_publisher_idx - 500) : trusted_publisher_idx + 500]
        assert (
            "environment: pypi" in nearby.lower()
            or "environment `pypi`" in nearby.lower()
            or ("environment" in nearby.lower() and "pypi" in nearby.lower())
        ), (
            "expected README.md to name the 'pypi' environment near the "
            "trusted publisher registration instructions"
        )
