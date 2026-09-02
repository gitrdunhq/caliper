"""dogfood.yml/dogfood.sh fail the job on blocked/incomplete verdict (task-025).
# tested-by: tests/test_dogfood.py

Today ``.github/workflows/dogfood.yml`` runs ``caliper review`` in a single step
with no follow-on check of the resulting verdict, and ``scripts/dogfood.sh``
swallows the underlying review invocation's exit code with ``|| true`` before
independently recomputing a pass/fail signal from SARIF error-level counts
alone. Neither path actually fails the job when ``caliper review``'s own verdict
is ``blocked`` or ``incomplete`` (e.g. a verdict driven by something other than
a SARIF error-level finding, such as a scanner failure). This module proves that
gap and will start passing once the workflow/script propagate and check the
verdict explicitly.
"""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[1]
_WORKFLOW_PATH = _REPO / ".github" / "workflows" / "dogfood.yml"
_SCRIPT_PATH = _REPO / "scripts" / "dogfood.sh"


def _read(rel_path: str) -> str:
    return (_REPO / rel_path).read_text()


class TestTask025AC1WorkflowChecksReviewVerdict:
    """AC1: dogfood.yml's review step has its exit code checked; the job fails
    (non-zero) when caliper review's verdict is 'blocked' or 'incomplete'."""

    def test_ac1_github_workflows_dogfood_yml_s_review_step_has_its_exit_code(self):
        assert _WORKFLOW_PATH.exists(), f"workflow not found at {_WORKFLOW_PATH}"
        workflow = yaml.safe_load(_read(".github/workflows/dogfood.yml"))
        steps = workflow["jobs"]["dogfood"]["steps"]

        review_step = next((s for s in steps if "review" in s.get("name", "").lower()), None)
        assert review_step is not None, "expected a review step in the dogfood job"
        assert review_step.get("continue-on-error") is not True, (
            "the review step must not swallow a failing exit code via " "continue-on-error"
        )

        run_steps_text = "\n".join(step.get("run", "") for step in steps if "run" in step).lower()
        # Either acceptable shape counts: the workflow checks the verdict
        # inline (references both 'blocked' and 'incomplete'), or it delegates
        # the review invocation to scripts/dogfood.sh, which is expected to
        # propagate a non-zero exit for those verdicts (AC2).
        delegates_to_script = "dogfood.sh" in run_steps_text
        checks_verdict_inline = "blocked" in run_steps_text and "incomplete" in run_steps_text
        assert delegates_to_script or checks_verdict_inline, (
            "dogfood.yml must fail the job on a blocked/incomplete caliper "
            "review verdict -- either by checking the verdict inline "
            "(referencing 'blocked' and 'incomplete') or by delegating the "
            "review invocation to scripts/dogfood.sh, which propagates the "
            f"exit code. Neither was found in the job's run steps:\n{run_steps_text}"
        )


class TestTask025AC2ScriptPropagatesReviewExitCode:
    """AC2: scripts/dogfood.sh (if it wraps the review invocation) propagates a
    non-zero exit code for blocked/incomplete verdicts instead of always
    exiting 0."""

    # SARIF payload with zero error-level findings, so a fixed script cannot
    # derive a failure purely by recounting "error" level entries in the SARIF
    # file the way it does today -- it must also honor the underlying review
    # command's own exit code.
    _SARIF_NO_ERROR_LEVEL_FINDINGS = json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "caliper", "rules": []}},
                    "results": [
                        {
                            "ruleId": "DEP001",
                            "level": "warning",
                            "message": {"text": "medium finding"},
                        },
                    ],
                }
            ],
        }
    )

    def _mock_uv_nonzero_exit(self, tmp_path: Path, sarif_content: str, exit_code: int) -> Path:
        """Mock `uv` binary that writes sarif_content but exits non-zero,
        simulating `caliper review` reporting a blocked/incomplete verdict via
        its process exit code even though the SARIF payload it wrote carries no
        error-level findings on its own."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        mock = bin_dir / "uv"
        mock.write_text(textwrap.dedent(f"""\
                #!/usr/bin/env python3
                import sys
                args = sys.argv[1:]
                output_path = None
                for i, a in enumerate(args):
                    if a == '--output' and i + 1 < len(args):
                        output_path = args[i + 1]
                is_sarif = '--format' in args and args[args.index('--format') + 1] == 'sarif'
                if output_path:
                    with open(output_path, 'w') as fh:
                        if is_sarif:
                            fh.write({sarif_content!r})
                        else:
                            fh.write('## Caliper Review\\n\\nBlocked.\\n')
                sys.exit({exit_code})
                """))
        mock.chmod(0o755)
        return bin_dir

    def test_ac2_scripts_dogfood_sh_if_it_wraps_the_review_invocation_propaga(self, tmp_path):
        assert _SCRIPT_PATH.exists(), f"dogfood.sh not found at {_SCRIPT_PATH}"

        bin_dir = self._mock_uv_nonzero_exit(
            tmp_path, self._SARIF_NO_ERROR_LEVEL_FINDINGS, exit_code=1
        )
        report_dir = tmp_path / "dogfood"
        report_dir.mkdir()
        env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
            "REPORT_DIR": str(report_dir),
            "REPO_ROOT": str(tmp_path),
        }
        result = subprocess.run(
            ["bash", str(_SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env,
        )

        assert result.returncode != 0, (
            "dogfood.sh must propagate a non-zero exit code from the underlying "
            "caliper review invocation (a blocked/incomplete verdict) instead "
            "of always exiting 0, even when the SARIF payload it wrote has no "
            f"error-level findings\nstdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
