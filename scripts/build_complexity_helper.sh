#!/usr/bin/env bash
# Rebuild the JS/TS maintainability helper bundle (#441)
# (scripts/complexity_helper -> src/caliper/plugins/_runners/complexity_helper_dist).
# The committed bundle is package data — no Node modules needed at runtime,
# only the system `node` to execute it.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -d node_modules ]; then
  npm install
fi

npx tsc --noEmit -p tsconfig.json
npm run build:complexity-helper
