#!/usr/bin/env bash
#
# Check nginx.org/angie.software for newer releases than what's pinned in
# ci-deep.yml's build-flavors matrix, and rewrite those pins in place. Called
# by .github/workflows/bump.yml on a schedule; also runnable locally to
# preview a bump before it lands.
#
#   tools/bump-versions.sh [--dry-run]
#
# What gets bumped, and why nginx MAINLINE is deliberately NOT one of them:
#   - nginx mainline is resolved at CI run time (NGINX_VERSION: "" in
#     build-test.yml / ci-deep.yml's env: block, filled by each workflow's own
#     curl-nginx.org scrape — see build-test.yml's `resolve` job and
#     ci-deep.yml's per-job "Resolve latest mainline nginx" steps). There is
#     no static mainline pin in this repo to bump.
#   - nginx STABLE pin  -- ci-deep.yml's build-flavors matrix (label: stable)
#   - angie pin         -- ci-deep.yml's build-flavors matrix (label: angie)
#   - ANGIE_SHA256       -- tools/ci-build.sh (nginx tarballs are PGP-verified
#                            at build time instead, so no nginx sha256 table
#                            exists to bump)
#
# A version bump with a stale sha256 pin is worse than no pin (ci-build.sh
# treats a missing pin as "print a warning", but a WRONG pin is a hard FATAL
# for angie) -- so every angie version edit here is paired with a digest
# computed from the exact tarball that version resolves to, never carried
# over from a previous entry.

set -euo pipefail

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

cd "$(dirname "$0")/.."

# --- discover latest versions -------------------------------------------

# nginx.org/en/download.html lists Mainline then Stable then Legacy, each as
# its own section header followed by a table whose first tarball link is that
# section's current release -- no JSON feed exists, so parse the one page
# nginx itself treats as authoritative.
latest_nginx_stable() {
    local page
    page="$(curl -fsSL https://nginx.org/en/download.html)"
    echo "${page#*"Stable version"}" \
        | grep -oE 'nginx-[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz' | head -1 \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'
}

latest_angie() {
    local json
    json="$(curl -fsSL https://api.github.com/repos/webserver-llc/angie/releases/latest)"
    echo "$json" | grep -m1 '"tag_name"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'
}

NEW_STABLE="$(latest_nginx_stable)"
NEW_ANGIE="$(latest_angie)"

for v in NEW_STABLE NEW_ANGIE; do
    if [ -z "${!v}" ]; then
        echo "FATAL: could not determine $v -- refusing to bump with a blank version" >&2
        exit 1
    fi
done

echo "latest: nginx stable=$NEW_STABLE angie=$NEW_ANGIE"

# Each matrix entry is "version:" immediately followed by "label:" (see
# ci-deep.yml's build-flavors job) -- pair them up rather than assuming
# ordering, so a future reordering of the matrix can't silently swap pins.
matrix_version_for_label() {
    awk -v want="$1" '
        /version:/ { match($0, /"[0-9.]+"/); v = substr($0, RSTART+1, RLENGTH-2); next }
        /label:/   { split($0, a, ":"); l = a[2]; gsub(/[ \t]/, "", l); if (l == want) { print v; exit } }
    ' .github/workflows/ci-deep.yml
}

CUR_STABLE="$(matrix_version_for_label stable)"
CUR_ANGIE="$(matrix_version_for_label angie)"

echo "pinned: nginx stable=$CUR_STABLE angie=$CUR_ANGIE"

CHANGED=0

# --- sha256 helper (angie only -- nginx is PGP-verified at build time) ---
sha256_for_angie() {
    local version="$1" url tmp digest
    url="https://download.angie.software/files/angie-${version}.tar.gz"
    tmp="$(mktemp)"
    curl -fsSL "$url" -o "$tmp"
    digest="$(sha256sum "$tmp" | awk '{print $1}')"
    rm -f "$tmp"
    echo "$digest"
}

# --- bump a version in ci-deep.yml's build-flavors matrix ----------------
bump_matrix_pin() {
    local label="$1" old="$2" new="$3"
    [ "$old" = "$new" ] && return 0
    python3 - "$label" "$old" "$new" <<'PYEOF'
import re, sys
label, old, new = sys.argv[1:4]
path = ".github/workflows/ci-deep.yml"
text = open(path).read()
pattern = re.compile(
    r'(version:\s*"' + re.escape(old) + r'"\n\s*label:\s*' + re.escape(label) + r')'
)
replaced = pattern.sub(lambda m: m.group(1).replace(old, new), text)
if replaced == text:
    print(f"WARNING: no matrix entry matched for label={label} old={old}", file=sys.stderr)
open(path, "w").write(replaced)
PYEOF
    CHANGED=1
}

bump_angie_sha256_pin() {
    local old="$1" new="$2" digest="$3"
    grep -q "\[\"${new}\"\]" tools/ci-build.sh && return 0  # already pinned
    # Insert the new pin right after the table's opening line; leave old
    # entries in place (ci-build.sh keys by version, older callers still work).
    sed -i "/declare -A ANGIE_SHA256=(/a\\    [\"${new}\"]=\"${digest}\"" tools/ci-build.sh
    CHANGED=1
}

if [ "$NEW_STABLE" != "$CUR_STABLE" ]; then
    echo "bump nginx stable: $CUR_STABLE -> $NEW_STABLE"
    if [ "$DRY_RUN" = 0 ]; then
        bump_matrix_pin stable "$CUR_STABLE" "$NEW_STABLE"
    else
        CHANGED=1
    fi
fi

if [ "$NEW_ANGIE" != "$CUR_ANGIE" ]; then
    echo "bump angie: $CUR_ANGIE -> $NEW_ANGIE"
    if [ "$DRY_RUN" = 0 ]; then
        DIGEST="$(sha256_for_angie "$NEW_ANGIE")"
        echo "  sha256 $DIGEST"
        bump_matrix_pin angie "$CUR_ANGIE" "$NEW_ANGIE"
        bump_angie_sha256_pin "$CUR_ANGIE" "$NEW_ANGIE" "$DIGEST"
    else
        CHANGED=1
    fi
fi

if [ "$CHANGED" = 0 ]; then
    echo "everything up to date, nothing to bump"
fi

echo "CHANGED=$CHANGED"
