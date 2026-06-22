#!/bin/sh
set -e
CHECKSUMS="/opt/caliper/scripts/checksums.txt"
if [ ! -f "$CHECKSUMS" ]; then
  echo "FAIL: checksums.txt not found at $CHECKSUMS"
  exit 1
fi
sha256sum -c "$CHECKSUMS"
echo "All binary checksums verified."
