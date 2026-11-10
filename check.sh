#!/bin/sh
# check.sh — repo gate: gitleaks on commit history, staged index, and
# unstaged worktree changes (.gitleaks.toml rules), plus cargo deny.
# Usage: ./check.sh   (any failing check sets exit 1)
set -eu

cd "$(dirname "$0")"

rc=0

check() {
    label="$1"
    shift
    printf '\n=== %s ===\n' "$label"
    if ! "$@"; then
        printf 'FAILED: %s\n' "$label" >&2
        rc=1
    fi
}

check "gitleaks history" gitleaks detect --redact --no-banner
check "gitleaks staged" gitleaks protect --staged --redact --no-banner
check "gitleaks unstaged" gitleaks protect --redact --no-banner
check "cargo deny" cargo deny check

if [ "$rc" -ne 0 ]; then
    echo "checks FAILED" >&2
    exit 1
fi
echo "checks: gitleaks (history, staged, unstaged) + cargo deny all clean"
