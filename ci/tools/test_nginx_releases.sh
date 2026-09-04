#!/usr/bin/env bash
#
# Hermetic controls for ci/tools/nginx-releases.sh, the one reader of the
# nginx GitHub releases feed that the CI workflows, ci-build.sh and
# bump-versions.sh share. The feed's parsing rules (parity, decoys, paging,
# the cap) are covered case by case in test_bump_versions.sh through the
# same functions; this file pins the command-line contract every workflow
# step relies on: what is printed, what is fatal, and that an authenticated
# call keeps the token out of curl's argv.
#
# Usage: ci/tools/test_nginx_releases.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESOLVER="$SCRIPT_DIR/nginx-releases.sh"

fail=0
say() { printf '%s\n' "$*"; }
ok() { printf 'OK: %s\n' "$*"; }
bad() {
    printf 'FAIL: %s\n' "$*"
    fail=1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/http-zstd-resolver-test.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/bin"

# curl stub: answers the releases endpoint from NGINX_FEED, logs argv and any
# stdin config so the token path can be checked.
cat >"$work/bin/curl" <<'EOF'
#!/bin/bash
[ -z "${CURL_ARGV_LOG:-}" ] || printf '%s\n' "$@" >>"$CURL_ARGV_LOG"
url=""
prev=""
for a in "$@"; do
    case "$a" in http*) url="$a" ;; esac
    [ "$prev" = "--config" ] && [ "$a" = "-" ] && cat >>"${CURL_HEADER_LOG:-/dev/null}"
    prev="$a"
done
case "$url" in
    *api.github.com/repos/nginx/nginx/releases?per_page=30\&page=*)
        case "${NGINX_FEED:-json}" in
            no-even)
                echo '[{"tag_name": "release-1.31.5", "draft": false, "prerelease": false}]' ;;
            dead)
                echo "curl: (22) stub: feed unreachable" >&2
                exit 22 ;;
            endless)
                echo "["
                for i in $(seq 1 30); do
                    echo " {\"tag_name\": \"release-1.29.$i\", \"draft\": false, \"prerelease\": false}$([ "$i" -lt 30 ] && echo ,)"
                done
                echo "]" ;;
            *)
                echo '[{"tag_name": "release-1.28.0", "draft": false, "prerelease": false},'
                echo ' {"tag_name": "release-1.33.0", "draft": true, "prerelease": false},'
                echo ' {"tag_name": "release-1.30.4", "draft": false, "prerelease": false},'
                echo ' {"tag_name": "release-1.31.5", "draft": false, "prerelease": false}]' ;;
        esac
        exit 0 ;;
esac
echo "stub: unexpected url $url" >&2
exit 22
EOF
chmod +x "$work/bin/curl"
export PATH="$work/bin:$PATH"

run() { # NGINX_FEED-mode args... -> stdout in $out, stderr in $err, status in $rc
    local mode="$1"
    shift
    rc=0
    out="$(NGINX_FEED="$mode" bash "$RESOLVER" "$@" 2>"$work/err")" || rc=$?
    err="$(cat "$work/err")"
}

say "== mainline / stable / both print the newest release of each parity =="
run json mainline
[ "$rc" -eq 0 ] && [ "$out" = "1.31.5" ] && ok "mainline -> 1.31.5" || bad "mainline: rc=$rc out='$out' $err"
run json stable
[ "$rc" -eq 0 ] && [ "$out" = "1.30.4" ] && ok "stable -> 1.30.4 (the legacy 1.28.0 and the draft 1.33.0 ignored)" || bad "stable: rc=$rc out='$out' $err"
run json both
[ "$rc" -eq 0 ] && [ "$out" = "1.30.4 1.31.5" ] && ok "both -> '1.30.4 1.31.5'" || bad "both: rc=$rc out='$out' $err"
run json
[ "$rc" -eq 0 ] && [ "$out" = "1.31.5" ] && ok "no argument defaults to mainline" || bad "default: rc=$rc out='$out' $err"

say "== a line the feed does not show is fatal by name, and prints nothing =="
run no-even stable
[ "$rc" -ne 0 ] && [ -z "$out" ] && grep -q 'shows no stable' <<<"$err" && ok "stable absent: fatal, nothing printed" || bad "stable absent: rc=$rc out='$out' $err"
run no-even mainline
[ "$rc" -eq 0 ] && [ "$out" = "1.31.5" ] && ok "mainline still resolves when only the stable line is absent" || bad "mainline with no stable: rc=$rc out='$out' $err"
run no-even both
[ "$rc" -ne 0 ] && [ -z "$out" ] && ok "both with a line absent: fatal, nothing printed" || bad "both with no stable: rc=$rc out='$out' $err"

say "== the page cap is a refusal =="
run endless mainline
[ "$rc" -ne 0 ] && [ -z "$out" ] && grep -q 'did not end within' <<<"$err" && ok "endless feed: refused at the cap, nothing printed" || bad "endless: rc=$rc out='$out' $err"

say "== bad argument, and an unreachable feed =="
run json weekly
[ "$rc" -eq 2 ] && grep -q '^usage:' <<<"$err" && ok "unknown line name: usage, status 2" || bad "usage: rc=$rc $err"
run dead weekly
[ "$rc" -eq 2 ] && grep -q '^usage:' <<<"$err" && ok "unknown line name is usage (2) even when the feed is unreachable: the selector is checked first" || bad "usage-dead: rc=$rc $err"
run dead mainline
[ "$rc" -eq 1 ] && [ -z "$out" ] && grep -q 'could not query' <<<"$err" && ok "unreachable feed: status 1, named, nothing printed" || bad "dead: rc=$rc out='$out' $err"

say "== GH_TOKEN goes through curl's stdin, never its argv =="
argv_log="$work/argv"
header_log="$work/header"
token='resolver-test-token-not-for-output'
rc=0
out="$(GH_TOKEN="$token" CURL_ARGV_LOG="$argv_log" CURL_HEADER_LOG="$header_log" bash "$RESOLVER" mainline 2>"$work/err")" || rc=$?
if [ "$rc" -ne 0 ] || [ "$out" != "1.31.5" ]; then
    bad "token: rc=$rc out='$out' $(cat "$work/err")"
elif grep -Fq "$token" "$argv_log"; then
    bad "token: the token appeared in curl's arguments"
elif ! grep -Fq "Authorization: Bearer $token" "$header_log"; then
    bad "token: the Authorization header never reached curl's stdin"
else
    ok "token: sent through stdin, absent from argv"
fi

if [ "$fail" -eq 0 ]; then
    say "all nginx-releases.sh cases pass"
else
    say "one or more nginx-releases.sh cases FAILED"
fi
exit "$fail"
