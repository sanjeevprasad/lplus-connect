#!/bin/sh
# Wait until a regex appears in the live logcat capture (taplog file).
# Usage: waitlex.sh <ERE> [timeout_s]   exits 0 on match, 1 on timeout.
pat="$1"
t="${2:-15}"
[ -n "$pat" ] || { echo "usage: $0 ERE [timeout]" >&2; exit 2; }
timeout "$t" tail -n0 -F "${TAPLOG:-$(dirname "$0")/../capture/tap-logcat.txt}" 2>/dev/null \
  | grep -m1 -E --line-buffered "$pat"
rc=$?
[ $rc -eq 0 ] && exit 0
echo "TIMEOUT waiting for: $pat" >&2
exit 1
