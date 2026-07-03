#!/usr/bin/env bash
# Validate a port against caliper's dev-port convention (CLAUDE.md § "Dev Ports")
# before wiring up a new local server (webhook, part --serve, a new sidecar, etc).
#
# Usage:
#   bash .claude/skills/caliper-run-and-operate/scripts/check-dev-port.sh <port>
#
# Exits 1 if the port is outside 12000-13000, or is already claimed by an
# existing caliper service. Exits 0 (with a warning) if the port is free but
# currently bound by something else on this machine. Never mutates anything.
set -euo pipefail

PORT="${1:-}"

if [ -z "${PORT}" ]; then
  echo "Usage: bash check-dev-port.sh <port>" >&2
  exit 1
fi

if ! [[ "${PORT}" =~ ^[0-9]+$ ]]; then
  echo "FAIL: '${PORT}' is not a number." >&2
  exit 1
fi

if [ "${PORT}" -lt 12000 ] || [ "${PORT}" -ge 13000 ]; then
  echo "FAIL: port ${PORT} is outside caliper's dev range 12000-13000 (CLAUDE.md § Dev Ports)." >&2
  exit 1
fi

# Ports already claimed by an existing caliper service (CLAUDE.md § Dev Ports,
# verified against source 2026-07-02 — see this skill's Provenance section for
# the grep that re-derives this table).
declare -A CLAIMED=(
  [12432]="PostgreSQL"
  [12700]="caliper part --serve (loopback sidecar)"
  [12701]="caliper part --serve --lan (read-only TLS LAN view)"
  [12800]="webhook server (caliper.webhook.server)"
)

if [ -n "${CLAIMED[${PORT}]:-}" ]; then
  echo "FAIL: port ${PORT} is already claimed by: ${CLAIMED[${PORT}]}" >&2
  exit 1
fi

echo "OK: port ${PORT} is in range and not claimed by an existing caliper service."

# Best-effort liveness check — never fails the script, just informs.
if command -v lsof >/dev/null 2>&1; then
  if lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "WARN: something is currently listening on ${PORT} on this machine (lsof)."
  else
    echo "INFO: nothing currently listening on ${PORT} on this machine."
  fi
else
  echo "INFO: lsof not available — skipped local liveness check."
fi
