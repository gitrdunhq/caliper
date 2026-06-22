"""Task-fit LLM advisory -- optional proportionality check.
# tested-by: tests/unit/test_taskfit.py

Asks an LLM whether a package is proportionate for its stated use case.
Entirely optional: when disabled or on any failure, returns an empty
string. Never raises, never blocks the pipeline.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

import structlog

from caliper.core.llm_client import LlmClient

if TYPE_CHECKING:
    from caliper.core.config import CaliperSettings

logger = structlog.get_logger(__name__)

_MAX_ADVISORY_LENGTH = 500
# Valid PyPI package names: letters, digits, hyphens, dots, underscores (PEP 508).
_VALID_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_SUMMARY_MAX_LEN = 200

_SYSTEM_PROMPT = """\
You are a dependency review analyst for a software engineering organization.

Your job is to evaluate whether a requested third-party package is appropriate, \
proportionate, and safe for its stated use case. You are the last line of reasoning \
before a deterministic policy engine makes the final allow/deny decision. Your output \
is advisory — it informs human reviewers and scribees the decision memo. It does not \
independently block or approve anything.

Evaluate the package against these 8 dimensions. Score each PASS, CONCERN, or FAIL. \
Then give your overall recommendation.

1. NECESSITY — Is a third-party dependency required at all? Could the stated use case \
be satisfied by the language's standard library, an existing approved internal package, \
or fewer than 50 lines of purpose-built code? If yes, the dependency is unnecessary \
regardless of quality.

2. MINIMALITY — Is this the narrowest reasonable dependency for the task? A package \
that provides 200 features when the team needs 1 is an overpowered choice. A full web \
framework for a single HTTP endpoint. An ORM for one SELECT query. Flag disproportionate \
scope.

3. MAINTAINABILITY — Is the project actively maintained? Check: when was the last \
release? Is the repo archived or deprecated? How many maintainers? A single-maintainer \
package with no release in 2 years is a future supply chain risk regardless of current \
quality.

4. SECURITY POSTURE — Does the package show healthy supply-chain signals? Look for: \
signed releases, provenance attestation, security policy (SECURITY.md), responsible \
disclosure process, history of timely CVE response. Absence of these is a yellow flag, \
not a red flag — but multiple absences compound.

5. RUNTIME EXPOSURE — Will this package process untrusted input, handle secrets, \
manage authentication tokens, parse serialized data from external sources, or run in \
an internet-facing service? Higher exposure demands higher scrutiny. A dev-only test \
utility has different risk than a runtime request parser.

6. OPERATIONAL BLAST RADIUS — How much transitive complexity does this package add? \
Check the transitive dependency count. A package that pulls in 300 transitive deps \
for a logging utility is a blast radius problem. Native extensions, compiled code, \
and platform-specific binaries increase operational risk.

7. ALTERNATIVE AVAILABILITY — Are there safer, already-approved alternatives that \
serve the same purpose? If the organization has already approved package X for this \
category of work, recommending package Y requires justification for why X is insufficient. \
Always surface approved alternatives when they exist.

8. BEHAVIORAL CONCERNS — Does the package execute code at install time (setup.py with \
subprocess calls, post-install scripts)? Does it make network requests during import? \
Does it spawn child processes, access the filesystem outside its scope, or use native \
extensions that bypass Python's safety model? Any of these is a flag.

OUTPUT FORMAT (strict — do not deviate):

```
NECESSITY:    [PASS|CONCERN|FAIL] — [one sentence]
MINIMALITY:   [PASS|CONCERN|FAIL] — [one sentence]
MAINTENANCE:  [PASS|CONCERN|FAIL] — [one sentence]
SECURITY:     [PASS|CONCERN|FAIL] — [one sentence]
EXPOSURE:     [PASS|CONCERN|FAIL] — [one sentence]
BLAST_RADIUS: [PASS|CONCERN|FAIL] — [one sentence]
ALTERNATIVES: [PASS|CONCERN|FAIL] — [one sentence, name specific alternatives if any]
BEHAVIORAL:   [PASS|CONCERN|FAIL] — [one sentence]

RECOMMENDATION: [APPROVE|REVIEW|REJECT] — [one sentence summary]
```

Rules:
- If you lack information for a dimension, score it CONCERN with "insufficient data."
- Never score PASS on trust alone — "it's popular" is not evidence of safety.
- If approved alternatives exist in the provided list, ALTERNATIVES must be CONCERN or FAIL.
- FAIL on any dimension does not mean the package should be rejected — that's the policy \
engine's job. You flag; OPA decides.
- Do not hallucinate package metadata. Work only with what is provided in the user message. \
If the summary is empty or uninformative, say so explicitly.
- Keep each line under 100 characters. Total output under 500 characters.\
"""


def _sanitize_summary(text: str) -> str:
    """Strip HTML tags and common markdown formatting from a PyPI summary.

    Prevents prompt injection via crafted package metadata.
    Returns the sanitised text truncated to _SUMMARY_MAX_LEN characters.
    """
    # Remove HTML tags
    text = re.sub(r"<[^>]+>", "", text)
    # Collapse markdown links [label](url) -> label
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    # Remove markdown formatting characters (* _ ` # ~)
    text = re.sub(r"[*_`#~]", "", text)
    return text.strip()[:_SUMMARY_MAX_LEN]


class TaskFitAdvisor:
    """Queries an OpenAI-compatible LLM for package proportionality advice.

    All failures are absorbed -- this class never raises and never blocks
    the review pipeline.
    """

    def __init__(self, config: CaliperSettings) -> None:
        self._enabled = config.llm_enabled
        self._endpoint = config.llm_endpoint
        self._model = config.llm_model
        # Transport is shared with the other LLM features via LlmClient (SoT).
        self._llm = LlmClient(config)

    def assess(
        self,
        package_name: str,
        version: str,
        use_case: str | None,
        metadata: dict,
        alternatives: list[str],
    ) -> str:
        """Produce a brief advisory on whether a package is appropriate.

        Args:
            package_name: The package being evaluated.
            version: The target version.
            use_case: Free-text description of what the package is for.
            metadata: PyPI metadata dict (expects a ``summary`` key).
            alternatives: List of approved alternative package names.

        Returns:
            Advisory text (max 500 chars) or empty string if disabled/failed.
        """
        if not self._enabled:
            return ""

        if not package_name.strip() or not _VALID_PACKAGE_NAME_RE.match(package_name):
            logger.warning("taskfit.invalid_package_name", package=repr(package_name))
            return ""

        if not self._endpoint or not self._model:
            logger.warning("taskfit.missing_config", endpoint=self._endpoint, model=self._model)
            return ""

        use_case_text = use_case or "unspecified"
        # Sanitise and truncate the PyPI summary to prevent prompt injection (F-013).
        summary = _sanitize_summary(str(metadata.get("summary", "unknown")))

        # Structured system/user message format keeps instructions separate from
        # untrusted data, preventing prompt injection via package metadata.
        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "package": f"{package_name}@{version}",
                        "use_case": use_case_text,
                        "summary": summary,
                        "approved_alternatives": alternatives,
                    }
                ),
            },
        ]

        try:
            return self._call_and_validate(messages)
        except Exception as exc:
            logger.warning("taskfit.assessment_failed", error=str(exc))
            return ""

    def _call_and_validate(self, messages: list[dict], max_retries: int = 2) -> str:
        """Call LLM and validate response against the 8-dimension gate.

        Retries up to max_retries times if the response fails validation,
        appending rejection guidance to help the LLM self-correct.
        Returns validated text or empty string if all retries exhausted.
        """
        from caliper.core.taskfit_validator import validate_taskfit_response

        attempt_messages = list(messages)

        for attempt in range(max_retries):
            raw = self._call_llm(attempt_messages)
            if not raw:
                return ""

            result = validate_taskfit_response(raw)
            if result.valid:
                logger.info(
                    "taskfit.validated",
                    attempt=attempt + 1,
                    pass_count=result.assessment.pass_count,
                    concern_count=result.assessment.concern_count,
                    fail_count=result.assessment.fail_count,
                    recommendation=result.assessment.recommendation.value,
                )
                return raw

            logger.warning(
                "taskfit.validation_failed",
                attempt=attempt + 1,
                errors=[e.message for e in result.errors],
            )

            attempt_messages = list(messages) + [
                {"role": "assistant", "content": raw},
                {
                    "role": "user",
                    "content": (
                        "Your response did not pass validation. "
                        "Fix the following errors and respond again "
                        "using the exact format specified.\n\n" + result.rejection_guidance()
                    ),
                },
            ]

        logger.warning("taskfit.validation_exhausted", max_retries=max_retries)
        return ""

    def _call_llm(self, messages: list[dict]) -> str:
        """Make a single chat-completions call and cap the advisory length."""
        text = self._llm.complete(messages, max_tokens=200)
        if len(text) > _MAX_ADVISORY_LENGTH:
            text = text[:_MAX_ADVISORY_LENGTH]
        return text
