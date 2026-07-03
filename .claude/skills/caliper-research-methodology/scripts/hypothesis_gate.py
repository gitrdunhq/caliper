#!/usr/bin/env python3
"""hypothesis_gate.py — enforce the caliper research-methodology evidence bar
on a single hypothesis record before it's allowed to move to the next stage
of the idea lifecycle (experiment -> flag -> adopted change / retirement).

Stdlib only. No repo dependency (works outside a venv, works for agents that
haven't run `uv sync`). Two subcommands, run in order:

  preregister-check   Run BEFORE the experiment. Fails unless the hypothesis
                       file states a mechanism, at least one predicted number,
                       and at least one observation the mechanism must explain
                       that is explicitly marked negative (a "this should NOT
                       happen if the mechanism is right" case). This is the
                       predict-numbers-before-running gate — it exists so a
                       prediction can't be written after the fact.

  accept-check         Run AFTER the experiment + assigned adversarial
                       refutation pass. Fails unless actual_numbers were
                       recorded, a refutation_owner other than the author
                       attempted to kill the claim, the refutation verdict is
                       present, and the mechanism has an explanation entry for
                       EVERY observation listed in preregistration (positive
                       AND negative) -- a mechanism that only explains the
                       hits is not accepted here.

Exit code 0 = gate passes. Exit code 1 = gate fails (reasons printed).

See .claude/skills/caliper-research-methodology/SKILL.md for the full
discipline this operationalizes, and templates/hypothesis.json for the
schema this validates.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text())


def preregister_check(record: dict) -> list[str]:
    errors = []

    if not record.get("claim", "").strip():
        errors.append("claim: empty. One sentence: what do you believe is true?")

    if not record.get("mechanism", "").strip():
        errors.append("mechanism: empty. State the CAUSAL reason, not just a correlation.")

    predicted = record.get("predicted_numbers", {})
    if not predicted:
        errors.append(
            "predicted_numbers: empty. Write down the number(s) you expect "
            "BEFORE running the experiment -- this is the whole point of "
            "the gate."
        )
    else:
        for k, v in predicted.items():
            if (
                v is None
                or str(v).strip() in ("", "TBD", "?")
                or str(v).strip().upper().startswith("TBD")
            ):
                errors.append(f"predicted_numbers['{k}']: placeholder, not a real prediction.")

    observations = record.get("observations_explained", [])
    if not observations:
        errors.append(
            "observations_explained: empty. List every observation (existing "
            "or expected) the mechanism must account for."
        )
    else:
        for i, obs in enumerate(observations):
            if "polarity" not in obs or obs["polarity"] not in ("positive", "negative"):
                errors.append(
                    f"observations_explained[{i}]: 'polarity' must be " "'positive' or 'negative'."
                )
        if not any(o.get("polarity") == "negative" for o in observations):
            errors.append(
                "observations_explained: no 'negative' entry. The evidence "
                "bar requires the mechanism to explain a case where the "
                "effect should NOT appear, not just the cases where it does."
            )

    if not record.get("refutation_owner", "").strip():
        errors.append(
            "refutation_owner: empty. Name the person/agent assigned to try "
            "to kill this hypothesis (must not be the author -- see "
            "adversarial-review skill's challenger-model role for the "
            "orchestration mechanics)."
        )

    return errors


def accept_check(record: dict) -> list[str]:
    errors = preregister_check(record)

    actual = record.get("actual_numbers", {})
    if not actual:
        errors.append("actual_numbers: empty. Record what actually happened.")

    predicted = record.get("predicted_numbers", {})
    missing = sorted(set(predicted) - set(actual))
    if missing:
        errors.append(
            f"actual_numbers: missing entries for predicted metric(s) {missing}. "
            "Every predicted metric needs a recorded actual value, even if it "
            "refutes the hypothesis."
        )

    owner = record.get("refutation_owner", "").strip()
    author = record.get("author", "").strip()
    if owner and author and owner == author:
        errors.append(
            "refutation_owner == author: self-refutation doesn't count. "
            "Assign a different reviewer/challenger."
        )

    verdict = record.get("refutation_verdict", "")
    if verdict not in ("CONFIRMED", "REFUTED", "UNCERTAIN"):
        errors.append(
            "refutation_verdict: must be one of CONFIRMED / REFUTED / "
            f"UNCERTAIN once the adversarial pass has run (got {verdict!r})."
        )

    observations = record.get("observations_explained", [])
    for i, obs in enumerate(observations):
        if not obs.get("explanation", "").strip():
            errors.append(
                f"observations_explained[{i}] (polarity={obs.get('polarity')}): "
                "no 'explanation' tying it back to the mechanism. A mechanism "
                "that is silent on one observation does not clear the bar."
            )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "stage", choices=["preregister-check", "accept-check"], help="Which gate to run."
    )
    parser.add_argument("hypothesis_file", help="Path to a hypothesis JSON record.")
    args = parser.parse_args()

    try:
        record = _load(args.hypothesis_file)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: could not read/parse {args.hypothesis_file}: {exc}")
        return 1

    checker = preregister_check if args.stage == "preregister-check" else accept_check
    errors = checker(record)

    if errors:
        print(f"FAIL ({args.stage}): {len(errors)} issue(s)")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(f"PASS ({args.stage}): {args.hypothesis_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
