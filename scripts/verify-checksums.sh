#!/bin/sh
# Verifies the shipped scanner binaries against the checksums recorded at
# build time. Reports on stderr so `caliper review --format json` on stdout
# stays machine-parseable; a mismatch still exits non-zero.
set -e
CHECKSUMS="/opt/caliper/scripts/checksums.txt"
if [ ! -f "$CHECKSUMS" ]; then
  echo "FAIL: checksums.txt not found at $CHECKSUMS" >&2
  exit 1
fi
sha256sum -c "$CHECKSUMS" >&2
echo "All binary checksums verified." >&2
