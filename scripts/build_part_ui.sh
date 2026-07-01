#!/usr/bin/env bash
# Rebuild the caliper part --serve SPA bundle (scripts/part_ui -> src/caliper/cli/part_ui_dist).
# The committed bundle is package data — no Node needed at runtime, only to rebuild it.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -d node_modules ]; then
  npm install
fi

npx tsc --noEmit -p tsconfig.json
npm run build:part-ui
