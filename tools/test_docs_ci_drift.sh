#!/usr/bin/env bash
#
# Regression test for audit sha e289021 F7: README/SECURITY/CONTRIBUTING
# drifted materially from the live CI workflows (stale badge count, dead
# AGENTS.md link, a workflow present in .github/workflows/ but undocumented,
# a false -Werror claim). The full fix was a one-time manual re-sync;
# nothing then stopped it drifting again on the next workflow add/rename.
#
# This does NOT try to keep exact TAP subtest counts in sync (that's
# exactly the kind of brittle exact-count claim the F7 fix already
# recommended dropping) -- it checks structural facts that are cheap to
# keep true and expensive to silently get wrong:
#   - every workflow file under .github/workflows/ is referenced somewhere
#     in README.md (by filename), so a new/renamed workflow can't go
#     undocumented
#   - every workflow referenced in README.md's badges/table actually exists
#     under .github/workflows/, so a removed/renamed workflow can't leave a
#     dead link/badge behind
#   - SECURITY.md does not link the removed AGENTS.md
#   - CONTRIBUTING.md does not claim the fuzz harness builds with -Werror
#     unless fuzz/build.sh (or equivalent) actually passes it
#
# Usage: tools/test_docs_ci_drift.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(dirname "$SCRIPT_DIR")"
cd "$MODULE_DIR" || exit 1

fail=0

# --- every real workflow file is mentioned in README.md ---
for wf in .github/workflows/*.yml; do
    name="$(basename "$wf")"
    if ! grep -q "$name" README.md; then
        echo "FAIL: .github/workflows/$name exists but is not referenced in README.md (undocumented workflow)"
        fail=1
    fi
done

# --- every workflow filename README.md references actually exists ---
while IFS= read -r name; do
    [ -f ".github/workflows/$name" ] || {
        echo "FAIL: README.md references .github/workflows/$name, which does not exist (stale/dead link or badge)"
        fail=1
    }
done < <(grep -oE 'workflows/[A-Za-z0-9_-]+\.yml' README.md | sed 's#workflows/##' | sort -u)

# --- SECURITY.md must not link the removed AGENTS.md ---
if [ -f SECURITY.md ] && grep -q 'AGENTS\.md' SECURITY.md; then
    echo "FAIL: SECURITY.md still links AGENTS.md, which was removed (PR #79)"
    fail=1
fi

# --- CONTRIBUTING.md's -Werror claim about the fuzz harness must match
# reality: only assert this if a fuzz build step actually exists and does
# NOT pass -Werror, since a future CI change legitimately flipping this on
# would make the check obsolete rather than wrong. ---
if [ -f CONTRIBUTING.md ] && grep -qi 'fuzz.*-Werror\|-Werror.*fuzz' CONTRIBUTING.md; then
    if ! grep -rq -- '-Werror' fuzz/ 2>/dev/null && ! grep -rlq -- '-Werror' .github/workflows/*.yml 2>/dev/null; then
        echo "FAIL: CONTRIBUTING.md claims the fuzz harness builds with -Werror, but no fuzz build step passes it"
        fail=1
    fi
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL: docs/CI drift detected (audit sha e289021 F7 regression)"
    exit 1
fi
echo "✓ README/SECURITY/CONTRIBUTING workflow references match .github/workflows/ contents"
