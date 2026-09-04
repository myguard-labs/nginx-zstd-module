#!/usr/bin/env bash
#
# The newest nginx stable and mainline releases, from the GitHub releases
# feed -- the one place this repo answers "which nginx is current":
#
#   ci/tools/nginx-releases.sh stable      -> 1.30.4
#   ci/tools/nginx-releases.sh mainline    -> 1.31.5
#   ci/tools/nginx-releases.sh both        -> 1.30.4 1.31.5
#
# The CI workflows resolve the mainline they build with it (a hardcoded
# version 404s once nginx.org drops the tarball), ci-build.sh does the same
# for a versionless nginx build, and ci/tools/bump-versions.sh sources this
# file for the functions below (gh_api_json serves its other feeds too).
# A line the feed does not show is a refusal, never a guess.
#
# GH_TOKEN, when set, authenticates the API calls: the shared runner egress
# IP routinely exhausts the unauthenticated allowance. In a workflow, pass
# `GH_TOKEN: ${{ github.token }}` on the step. Needs curl and python3.

# GET an api.github.com path. The runners share an egress IP, so the
# unauthenticated API allowance (60/hr) is routinely exhausted and the call
# 403s; GH_TOKEN, when present, buys the far larger authenticated quota. The
# header goes in through stdin so the token never appears in curl's process
# arguments on a shared runner.
gh_api_json() { # path
    local json
    if [ -n "${GH_TOKEN:-}" ]; then
        json="$(printf 'header = "Authorization: Bearer %s"\n' "$GH_TOKEN" \
            | curl --config - -fsSL "https://api.github.com/$1")" || json=""
    else
        json="$(curl -fsSL "https://api.github.com/$1")" || json=""
    fi
    if [ -z "$json" ]; then
        echo "error: could not query https://api.github.com/$1 (rate limit? set GH_TOKEN)" >&2
        return 1
    fi
    printf '%s\n' "$json"
}

# nginx publishes every release on GitHub as a Release (not just a tag):
# `release-X.Y.Z`, non-draft, carrying the same signed tarball nginx.org
# serves (byte-identical, same .asc, verified by ci/tools/keys). That is a
# structured feed; nginx.org/en/download.html is HTML whose section
# headings a parser has to know by name, and a renamed heading is a
# refusal at best. The stable and mainline lines follow nginx's own
# versioning rule -- even minor is stable, odd minor is mainline -- so
# each line's newest release is the newest of its parity. Tarballs and
# signatures still come from nginx.org (the pinned URLs do not change);
# only "what is newest" moves here.
#
# The feed is paged and ordered by creation time, not by version: a
# security release of an older line (1.28.x) can be created months after
# the current stable's last release, so the first even-minor entry seen
# is not necessarily the newest stable, and a long run of mainline and
# legacy releases can push the real one to a later page. Every page is
# read until a short page ends the list, and the newest of each line is
# the highest version across all of them. The cap bounds a broken feed,
# not a real one (the feed holds every release since nginx moved to
# GitHub, 29 as of 2026-09 at roughly fifteen a year, so five pages of
# thirty is about a decade away); reaching it with a full page is a
# refusal, never a pick from what was read.
NGINX_FEED_PAGE=30
NGINX_FEED_PAGES=5

NGINX_LINE_PY=$(cat <<'PYEOF'
import json, re, sys
# argv: current best even, current best odd ("-" when none yet).
# stdout: "<best even> <best odd> <entries on this page>", "-" when none.
best = {"even": sys.argv[1], "odd": sys.argv[2]}
try:
    releases = json.load(sys.stdin)
except ValueError:
    sys.exit("FATAL: the nginx release feed is not JSON -- refusing to guess")
if not isinstance(releases, list):
    sys.exit("FATAL: the nginx release feed is not a release list -- refusing to guess")
def parse(v):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", v)
    return tuple(int(x) for x in m.groups()) if m else None
for r in releases:
    if (not isinstance(r, dict) or r.get("draft") is not False
            or r.get("prerelease") is not False):
        continue
    m = re.fullmatch(r"release-(\d+\.\d+\.\d+)", str(r.get("tag_name", "")))
    if not m:
        continue
    v = parse(m.group(1))
    line = "even" if v[1] % 2 == 0 else "odd"
    cur = parse(best[line]) if best[line] != "-" else None
    if cur is None or v > cur:
        best[line] = "%d.%d.%d" % v
print(best["even"], best["odd"], len(releases))
PYEOF
)

# Prints "<stable> <mainline>" with "-" for a line the feed did not show,
# which the blank-version check below reports by name.
nginx_lines() {
    local page even="-" odd="-" json count
    for ((page = 1; page <= NGINX_FEED_PAGES; page++)); do
        json="$(gh_api_json "repos/nginx/nginx/releases?per_page=${NGINX_FEED_PAGE}&page=${page}")"
        read -r even odd count < <(printf '%s' "$json" | python3 -c "$NGINX_LINE_PY" "$even" "$odd")
        if [ "$count" -lt "$NGINX_FEED_PAGE" ]; then
            break   # a short page is the end of the list
        fi
    done
    # The cap is not an end-of-list marker: a full last page means pages
    # beyond it were never read and may hold a newer release of either
    # line, so the answer is unknown, not "the best so far".
    if [ "$count" -ge "$NGINX_FEED_PAGE" ]; then
        echo "FATAL: the nginx release feed did not end within ${NGINX_FEED_PAGES} pages" \
            "of ${NGINX_FEED_PAGE} -- refusing to pick from an incomplete read" >&2
        return 1
    fi
    printf '%s %s\n' "$even" "$odd"
}

# nginx_release stable|mainline|both -- prints the version(s); a line the
# feed did not show is fatal by name.
nginx_release() {
    local stable mainline
    # The selector is checked before the feed is asked, so a bad name is
    # usage (status 2) whether or not the API is reachable.
    case "$1" in
        stable|mainline|both) ;;
        *)
            echo "usage: nginx-releases.sh stable|mainline|both" >&2
            return 2
            ;;
    esac
    read -r stable mainline < <(nginx_lines) || return 1
    if [ "$1" != mainline ] && [ "$stable" = "-" ]; then
        echo "FATAL: the nginx release feed shows no stable (even-minor) release" >&2
        return 1
    fi
    if [ "$1" != stable ] && [ "$mainline" = "-" ]; then
        echo "FATAL: the nginx release feed shows no mainline (odd-minor) release" >&2
        return 1
    fi
    case "$1" in
        stable) echo "$stable" ;;
        mainline) echo "$mainline" ;;
        both) echo "$stable $mainline" ;;
    esac
}

# Executed rather than sourced: resolve and print.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -euo pipefail
    shopt -s inherit_errexit
    nginx_release "${1:-mainline}"
fi
