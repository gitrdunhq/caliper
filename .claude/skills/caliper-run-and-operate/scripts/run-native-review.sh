#!/usr/bin/env bash
# Run `caliper review` natively (no container) against the current repo and
# land the artifact under .caliper/reports/ with a RUN_ID, mirroring the
# timestamped-artifact convention scripts/dogfood.sh already uses in this repo.
#
# This is the "I just want to run a review and see the output" entry point for
# local dev. For container-based scans (parity with CI) use scripts/scan.sh
# instead — see this skill's "Container reviews" section for why the two exist.
#
# Usage:
#   bash .claude/skills/caliper-run-and-operate/scripts/run-native-review.sh [format] [scope-args...]
#
# Examples:
#   bash .claude/skills/caliper-run-and-operate/scripts/run-native-review.sh
#   bash .claude/skills/caliper-run-and-operate/scripts/run-native-review.sh sarif
#   bash .claude/skills/caliper-run-and-operate/scripts/run-native-review.sh json --category quality
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
FORMAT="${1:-markdown}"
shift || true
EXTRA_ARGS=("$@")

RUN_ID="$(date +%Y%m%d-%H%M%S)"
REPORT_DIR="${REPO_ROOT}/.caliper/reports"
mkdir -p "${REPORT_DIR}"

case "${FORMAT}" in
  markdown) EXT="md" ;;
  sarif) EXT="sarif" ;;
  json) EXT="json" ;;
  vex) EXT="vex.json" ;;
  *)
    echo "Usage: run-native-review.sh [markdown|sarif|json|vex] [extra caliper review args...]" >&2
    exit 1
    ;;
esac

OUT="${REPORT_DIR}/review-${RUN_ID}.${EXT}"

echo "=== caliper review (native), format=${FORMAT} ==="
(
  cd "${REPO_ROOT}"
  uv run caliper review --repo-path . --all --format "${FORMAT}" --output "${OUT}" "${EXTRA_ARGS[@]}"
)

echo "Written: ${OUT}"
