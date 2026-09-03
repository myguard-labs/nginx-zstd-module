#!/usr/bin/env bash
#
# Hermetic regression test for ci/tools/bump-versions.sh.
#
# Audit A30-F4 first: the script used stale pre-move paths (tools/keys/,
# tools/ci-build.sh) that do not exist after the tools/ -> ci/tools/ move,
# so a real bump could not import the PGP keyring, and a matrix/pin
# replacement that matched nothing failed silently, leaving a partial edit.
#
# Then the pins the weekly bump did not know about: the harness jobs'
# static mainline pin (HARNESS_NGINX_VERSION, in two workflows) and the
# Windows build's sources (ci/tools/windows-pins.sh) were bumped by hand or
# not at all. The cases below cover every pin the script rewrites, the
# forward-only rule for release-API feeds, the fail-loud / no-partial-edit
# rule for every mutator, the resolve/apply split (every digest fetched
# before any file is touched, so a dead mirror part-way edits nothing), and
# the staged apply (mutators edit copies, installed together, so a mutator
# failing on the second file leaves every tracked file unchanged).
#
# This test builds a scratch copy of the repo layout the script actually
# needs (ci/tools/ci-build.sh, ci/tools/keys/*.key, ci/tools/windows-pins.sh,
# .github/workflows/{ci-deep,harness-fault-arms}.yml) and stubs curl/gpg on
# PATH so no network is used. Each case name is asserted individually.
#
# Usage: ci/tools/test_bump_versions.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUMP_SCRIPT="$REPO_ROOT/ci/tools/bump-versions.sh"

fail=0
SANDBOXES=()
cleanup_sandboxes() {
    local dir
    for dir in "${SANDBOXES[@]}"; do
        rm -rf -- "$dir"
    done
}
trap cleanup_sandboxes EXIT
say() { printf '%s\n' "$*"; }
ok() { printf 'OK: %s\n' "$*"; }
bad() {
    printf 'FAIL: %s\n' "$*"
    fail=1
}

# The sandbox's current pins. Every stubbed feed answers these unless a case
# overrides it, so a case changes exactly the pins it names.
CUR_STABLE=1.30.4
CUR_MAINLINE=1.31.4
CUR_ANGIE=1.12.1
CUR_PCRE2=10.44
CUR_ZLIB=1.3.1
CUR_OPENSSL=4.0.1
CUR_ZSTD=1.5.7

# make_sandbox VARNAME  -- creates a scratch repo layout under a temp dir and
# assigns its path to VARNAME.
make_sandbox() {
    # shellcheck disable=SC2034  # nameref out-parameter, assigned for the caller
    local -n out="$1"
    local dir
    dir="$(mktemp -d "${TMPDIR:-/tmp}/http-zstd-bump-test.XXXXXX")"
    SANDBOXES+=("$dir")
    mkdir -p "$dir/ci/tools/keys" "$dir/.github/workflows"
    cat >"$dir/ci/tools/keys/dummy.key" <<'EOF'
dummy keyring placeholder
EOF
    cat >"$dir/ci/tools/ci-build.sh" <<'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
declare -A ANGIE_SHA256=(
    ["1.12.1"]="aaaa"
)
declare -A NGINX_SHA256=(
    ["1.30.4"]="bbbb"
)
KEYRING_DIR="$SCRIPT_DIR/keys"
EOF
    cat >"$dir/ci/tools/windows-pins.sh" <<'EOF'
# sandbox copy of ci/tools/windows-pins.sh -- data only
# shellcheck shell=sh disable=SC2034
VER_NGINX=1.31.4
SHA_NGINX=cccc1
VER_PCRE2=10.44
SHA_PCRE2=cccc2
VER_OPENSSL=4.0.1
SHA_OPENSSL=cccc3
VER_ZLIB=1.3.1
SHA_ZLIB=cccc4
VER_NASM=3.02
SHA_NASM=cccc5
VER_ZSTD=1.5.7
SHA_ZSTD=cccc6
EOF
    cat >"$dir/.github/workflows/ci-deep.yml" <<'EOF'
env:
  NGINX_VERSION: ""
  HARNESS_NGINX_VERSION: "1.31.4"
jobs:
  build-flavors:
    strategy:
      matrix:
        include:
          - version: "1.31.2"
            label: mainline
          - version: "1.30.4"
            label: stable
          - version: "1.12.1"
            label: angie
EOF
    cat >"$dir/.github/workflows/harness-fault-arms.yml" <<'EOF'
env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true
  HARNESS_NGINX_VERSION: "1.31.4"
EOF
    cp "$BUMP_SCRIPT" "$dir/ci/tools/bump-versions.sh"
    # shellcheck disable=SC2034  # nameref out-parameter, read by the caller
    out="$dir"
}

# stub_bin DIR -- creates PATH-shadowing curl/gpg stubs and prints the bin
# dir to prepend to PATH. Reads NEW_* env for what each feed's "latest"
# should resolve to; any not set answers the sandbox's current pin. FAIL_URL,
# when set, makes every fetch whose URL contains it fail like a dead mirror.
stub_bin() {
    local dir="$1" bindir="$1/bin"
    mkdir -p "$bindir"
    cat >"$bindir/curl" <<EOF
#!/bin/bash
# Fake nginx.org download page / GitHub release APIs / tarball fetch.
[ -z "\${CURL_ARGV_LOG:-}" ] || printf '%s\n' "\$@" >>"\$CURL_ARGV_LOG"
url=""
out=""
prev=""
fail_url="${FAIL_URL:-}"
omit_stable_heading="${OMIT_STABLE_HEADING:-0}"
omit_stable_tarball="${OMIT_STABLE_TARBALL:-0}"
omit_legacy_heading="${OMIT_LEGACY_HEADING:-0}"
for a in "\$@"; do
    case "\$a" in http*) url="\$a" ;; esac
    [ "\$prev" = "-o" ] && out="\$a"
    [ "\$prev" = "--config" ] && [ "\$a" = "-" ] && cat >>"\${CURL_HEADER_LOG:-/dev/null}"
    prev="\$a"
done
if [ -n "\$fail_url" ]; then
    case "\$url" in *"\$fail_url"*) echo "curl: (22) stub: \$url unreachable" >&2; exit 22 ;; esac
fi
case "\$url" in
    *nginx.org/en/download.html*)
        if [ "\$omit_stable_heading" = 1 ]; then
            echo "Mainline versionnginx-${NEW_MAINLINE:-$CUR_MAINLINE}.tar.gz nginx-${NEW_STABLE:-$CUR_STABLE}.tar.gz"
        elif [ "\$omit_stable_tarball" = 1 ]; then
            echo "Mainline versionnginx-${NEW_MAINLINE:-$CUR_MAINLINE}.tar.gzStable versionLegacy versionnginx-1.28.0.tar.gz"
        elif [ "\$omit_legacy_heading" = 1 ]; then
            echo "Mainline versionnginx-${NEW_MAINLINE:-$CUR_MAINLINE}.tar.gzStable versionLegacy nginx-1.28.0.tar.gz"
        else
            echo "Mainline versionnginx-${NEW_MAINLINE:-$CUR_MAINLINE}.tar.gzStable versionnginx-${NEW_STABLE:-$CUR_STABLE}.tar.gzLegacy versionnginx-1.28.0.tar.gz"
        fi
        exit 0 ;;
    *api.github.com/repos/webserver-llc/angie/releases/latest*)
        echo "{\"tag_name\": \"${NEW_ANGIE:-$CUR_ANGIE}\"}"
        exit 0 ;;
    *api.github.com/repos/PCRE2Project/pcre2/releases/latest*)
        echo "{\"tag_name\": \"pcre2-${NEW_PCRE2:-$CUR_PCRE2}\"}"
        exit 0 ;;
    *api.github.com/repos/madler/zlib/releases/latest*)
        echo "{\"tag_name\": \"v${NEW_ZLIB:-$CUR_ZLIB}\"}"
        exit 0 ;;
    *api.github.com/repos/openssl/openssl/releases/latest*)
        echo "{\"tag_name\": \"openssl-${NEW_OPENSSL:-$CUR_OPENSSL}\"}"
        exit 0 ;;
    *api.github.com/repos/facebook/zstd/releases/latest*)
        echo "{\"tag_name\": \"v${NEW_ZSTD:-$CUR_ZSTD}\"}"
        exit 0 ;;
esac
# tarball / .asc fetch: write a stand-in whose bytes depend only on the
# file name, so the same tarball from two hosts (zlib) hashes the same and
# a case can predict the digest the script records.
[ -n "\$out" ] && echo "dummy \${url##*/}" > "\$out"
exit 0
EOF
    cat >"$bindir/gpg" <<'EOF'
#!/bin/bash
# Accept any --import / --verify as success (hermetic stub).
exit 0
EOF
    chmod +x "$bindir/curl" "$bindir/gpg"
    if [ "${FAIL_SORT:-0}" = 1 ]; then
        cat >"$bindir/sort" <<'EOF'
#!/bin/sh
exit 42
EOF
        chmod +x "$bindir/sort"
    fi
    echo "$bindir"
}

# The digest the stub tarball for FILE hashes to.
stub_sha() { printf 'dummy %s\n' "$1" | sha256sum | awk '{print $1}'; }

# run_case NAME [NEW_X=value ...] -- runs bump-versions.sh in a fresh sandbox
# with the stubbed feeds answering the given "latest" values and returns its
# exit status; sandbox path is left in SANDBOX for the caller to inspect.
run_case() {
    shift
    make_sandbox SANDBOX
    local bindir
    bindir="$(
        for kv in "$@"; do export "${kv?}"; done
        stub_bin "$SANDBOX"
    )"
    (
        cd "$SANDBOX"
        PATH="$bindir:$PATH" bash ci/tools/bump-versions.sh >"$SANDBOX/out.log" 2>&1
    )
    return $?
}

pins_line() { grep -E "^$1=" "$SANDBOX/ci/tools/windows-pins.sh"; }
harness_line() { grep -c 'HARNESS_NGINX_VERSION: "'"$1"'"' "$SANDBOX/.github/workflows/$2"; }

say "== case: stable-only bump =="
if run_case stable-only NEW_STABLE=1.30.5; then
    if grep -q 'version: "1.30.5"' "$SANDBOX/.github/workflows/ci-deep.yml" \
        && grep -q '\["1.30.5"\]' "$SANDBOX/ci/tools/ci-build.sh"; then
        ok "stable-only: matrix and sha256 pin both updated"
    else
        bad "stable-only: pin(s) missing after bump"
    fi
else
    bad "stable-only: script exited non-zero unexpectedly: $(cat "$SANDBOX/out.log")"
fi

say "== case: angie-only bump =="
if run_case angie-only NEW_ANGIE=1.13.0; then
    if grep -q 'version: "1.13.0"' "$SANDBOX/.github/workflows/ci-deep.yml" \
        && grep -q '\["1.13.0"\]' "$SANDBOX/ci/tools/ci-build.sh"; then
        ok "angie-only: matrix and sha256 pin both updated"
    else
        bad "angie-only: pin(s) missing after bump"
    fi
else
    bad "angie-only: script exited non-zero unexpectedly: $(cat "$SANDBOX/out.log")"
fi

say "== case: both bump =="
if run_case both NEW_STABLE=1.30.5 NEW_ANGIE=1.13.0; then
    if grep -q 'version: "1.30.5"' "$SANDBOX/.github/workflows/ci-deep.yml" \
        && grep -q 'version: "1.13.0"' "$SANDBOX/.github/workflows/ci-deep.yml" \
        && grep -q '\["1.30.5"\]' "$SANDBOX/ci/tools/ci-build.sh" \
        && grep -q '\["1.13.0"\]' "$SANDBOX/ci/tools/ci-build.sh"; then
        ok "both: matrix and sha256 pins all updated"
    else
        bad "both: pin(s) missing after bump"
    fi
else
    bad "both: script exited non-zero unexpectedly: $(cat "$SANDBOX/out.log")"
fi

say "== case: no-change =="
if run_case no-change; then
    if grep -q 'CHANGED=0' "$SANDBOX/out.log"; then
        ok "no-change: script reports CHANGED=0 and exits 0"
    else
        bad "no-change: expected CHANGED=0, got: $(cat "$SANDBOX/out.log")"
    fi
else
    bad "no-change: script exited non-zero unexpectedly: $(cat "$SANDBOX/out.log")"
fi

say "== case: mainline bump (harness pin in both workflows + Windows nginx pin; matrix entry untouched) =="
if run_case mainline NEW_MAINLINE=1.31.5; then
    if [ "$(harness_line 1.31.5 ci-deep.yml)" = 1 ] \
        && [ "$(harness_line 1.31.5 harness-fault-arms.yml)" = 1 ] \
        && [ "$(pins_line VER_NGINX)" = "VER_NGINX=1.31.5" ] \
        && [ "$(pins_line SHA_NGINX)" = "SHA_NGINX=$(stub_sha nginx-1.31.5.tar.gz)" ] \
        && grep -q 'version: "1.31.2"' "$SANDBOX/.github/workflows/ci-deep.yml" \
        && grep -q 'version: "1.30.4"' "$SANDBOX/.github/workflows/ci-deep.yml" \
        && ! grep -q '1.31.5' "$SANDBOX/ci/tools/ci-build.sh"; then
        ok "mainline: both harness pins and the Windows nginx pin+digest updated, matrix and ci-build.sh untouched"
    else
        bad "mainline: unexpected result: $(cat "$SANDBOX/out.log")"
    fi
else
    bad "mainline: script exited non-zero unexpectedly: $(cat "$SANDBOX/out.log")"
fi

say "== case: windows library bumps (pcre2, zlib, openssl, zstd) =="
if run_case windows-libs NEW_PCRE2=10.48 NEW_ZLIB=1.3.2 NEW_OPENSSL=4.0.2 NEW_ZSTD=1.5.8; then
    if [ "$(pins_line VER_PCRE2)" = "VER_PCRE2=10.48" ] \
        && [ "$(pins_line SHA_PCRE2)" = "SHA_PCRE2=$(stub_sha pcre2-10.48.tar.gz)" ] \
        && [ "$(pins_line VER_ZLIB)" = "VER_ZLIB=1.3.2" ] \
        && [ "$(pins_line SHA_ZLIB)" = "SHA_ZLIB=$(stub_sha zlib-1.3.2.tar.gz)" ] \
        && [ "$(pins_line VER_OPENSSL)" = "VER_OPENSSL=4.0.2" ] \
        && [ "$(pins_line SHA_OPENSSL)" = "SHA_OPENSSL=$(stub_sha openssl-4.0.2.tar.gz)" ] \
        && [ "$(pins_line VER_ZSTD)" = "VER_ZSTD=1.5.8" ] \
        && [ "$(pins_line SHA_ZSTD)" = "SHA_ZSTD=$(stub_sha zstd-1.5.8.tar.gz)" ] \
        && [ "$(pins_line VER_NGINX)" = "VER_NGINX=1.31.4" ] \
        && [ "$(pins_line SHA_NASM)" = "SHA_NASM=cccc5" ]; then
        ok "windows-libs: all four version+digest pairs updated, nginx and nasm untouched"
    else
        bad "windows-libs: unexpected pins: $(cat "$SANDBOX/ci/tools/windows-pins.sh") -- $(cat "$SANDBOX/out.log")"
    fi
else
    bad "windows-libs: script exited non-zero unexpectedly: $(cat "$SANDBOX/out.log")"
fi

say "== case: release feed behind the pin (must hold, never move backwards) =="
if run_case backwards NEW_OPENSSL=3.5.5; then
    if grep -q 'CHANGED=0' "$SANDBOX/out.log" \
        && grep -q 'not moving a pin backwards' "$SANDBOX/out.log" \
        && [ "$(pins_line VER_OPENSSL)" = "VER_OPENSSL=4.0.1" ] \
        && [ "$(pins_line SHA_OPENSSL)" = "SHA_OPENSSL=cccc3" ]; then
        ok "backwards: reported the hold, CHANGED=0, pin untouched"
    else
        bad "backwards: unexpected result: $(cat "$SANDBOX/out.log")"
    fi
else
    bad "backwards: script exited non-zero unexpectedly: $(cat "$SANDBOX/out.log")"
fi

say "== case: every nginx/Angie feed behind its pin (all must hold) =="
if run_case backwards-webservers NEW_STABLE=1.30.3 NEW_ANGIE=1.11.0 NEW_MAINLINE=1.31.3; then
    if grep -q 'CHANGED=0' "$SANDBOX/out.log" \
        && [ "$(grep -c 'not moving a pin backwards' "$SANDBOX/out.log")" -eq 4 ] \
        && grep -q 'version: "1.30.4"' "$SANDBOX/.github/workflows/ci-deep.yml" \
        && grep -q 'version: "1.12.1"' "$SANDBOX/.github/workflows/ci-deep.yml" \
        && [ "$(pins_line VER_NGINX)" = "VER_NGINX=1.31.4" ] \
        && [ "$(harness_line 1.31.4 ci-deep.yml)" = 1 ] \
        && [ "$(harness_line 1.31.4 harness-fault-arms.yml)" = 1 ]; then
        ok "backwards webservers: all four pins held without edits"
    else
        bad "backwards webservers: unexpected result: $(cat "$SANDBOX/out.log")"
    fi
else
    bad "backwards webservers: script exited non-zero: $(cat "$SANDBOX/out.log")"
fi

say "== case: version comparator failure is fatal, never a backwards hold =="
if run_case comparator-failure NEW_ANGIE=1.11.0 FAIL_SORT=1; then
    bad "comparator-failure: updater exited 0 after sort -V failed"
elif ! grep -q 'FATAL: could not compare versions' "$SANDBOX/out.log"; then
    bad "comparator-failure: missing fatal diagnostic: $(cat "$SANDBOX/out.log")"
else
    ok "comparator-failure: failed closed with a fatal diagnostic"
fi

say "== case: transient fetch failure part-way (must edit NOTHING: every digest is fetched before any file is touched) =="
# Stable resolves first and its tarball fetch succeeds; the angie tarball
# fetch then fails. Before the resolve/apply split, the stable matrix and
# digest edits had already landed by then, leaving a half-bumped tree.
if run_case transient NEW_STABLE=1.30.5 NEW_ANGIE=1.13.0 FAIL_URL=angie-1.13.0.tar.gz; then
    bad "transient: script exited 0 despite a failed tarball fetch"
elif grep -q '1.30.5' "$SANDBOX/.github/workflows/ci-deep.yml" || grep -q '1.30.5' "$SANDBOX/ci/tools/ci-build.sh"; then
    bad "transient: the stable bump was written before the angie fetch failed (partial edit): $(cat "$SANDBOX/out.log")"
elif ! grep -q 'bump nginx stable: 1.30.4 -> 1.30.5' "$SANDBOX/out.log"; then
    bad "transient: the stable bump was not even resolved: $(cat "$SANDBOX/out.log")"
elif ! grep -q 'could not fetch' "$SANDBOX/out.log"; then
    bad "transient: exited non-zero but did not name the failed fetch: $(cat "$SANDBOX/out.log")"
else
    ok "transient: named the failed fetch, exited non-zero, no file edited"
fi

say "== case: missing nasm pin (not bumped, but required by build-windows.sh -- must FAIL before any edit) =="
make_sandbox SANDBOX
sed -i '/^SHA_NASM=/d' "$SANDBOX/ci/tools/windows-pins.sh"
before_pins="$(cat "$SANDBOX/ci/tools/windows-pins.sh")"
before_matrix="$(cat "$SANDBOX/.github/workflows/ci-deep.yml")"
bindir="$(NEW_STABLE=1.30.5 stub_bin "$SANDBOX")"
set +e
(
    cd "$SANDBOX"
    PATH="$bindir:$PATH" bash ci/tools/bump-versions.sh >"$SANDBOX/out.log" 2>&1
)
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
    bad "missing-nasm: script exited 0 with SHA_NASM missing from windows-pins.sh"
elif [ "$before_pins" != "$(cat "$SANDBOX/ci/tools/windows-pins.sh")" ] || [ "$before_matrix" != "$(cat "$SANDBOX/.github/workflows/ci-deep.yml")" ]; then
    bad "missing-nasm: a file was mutated before the missing pin was reported (partial edit)"
elif ! grep -q 'does not set SHA_NASM' "$SANDBOX/out.log"; then
    bad "missing-nasm: exited non-zero but did not name the missing pin: $(cat "$SANDBOX/out.log")"
else
    ok "missing-nasm: exited non-zero, named the missing pin, and edited nothing"
fi

say "== case: apply-phase failure on the SECOND file (must leave EVERY tracked file byte-for-byte unchanged) =="
make_sandbox SANDBOX
# The stable entry is well-formed, the angie entry is drifted: the stable
# bump lands (on the staged copy), then the angie mutator fails. Before the
# staged apply, ci-deep.yml and ci-build.sh already carried the stable bump.
cat >"$SANDBOX/.github/workflows/ci-deep.yml" <<'EOF'
env:
  HARNESS_NGINX_VERSION: "1.31.4"
jobs:
  build-flavors:
    strategy:
      matrix:
        include:
          - version: "1.31.2"
            label: mainline
          - version: "1.30.4"
            label: stable
          - label: angie
            version: "1.12.1"
EOF
declare -A before=()
for f in .github/workflows/ci-deep.yml .github/workflows/harness-fault-arms.yml ci/tools/ci-build.sh ci/tools/windows-pins.sh; do
    before[$f]="$(cat "$SANDBOX/$f")"
done
bindir="$(NEW_STABLE=1.30.5 NEW_ANGIE=1.13.0 stub_bin "$SANDBOX")"
set +e
(
    cd "$SANDBOX"
    PATH="$bindir:$PATH" bash ci/tools/bump-versions.sh >"$SANDBOX/out.log" 2>&1
)
rc=$?
set -e
changed=""
for f in "${!before[@]}"; do
    [ "${before[$f]}" = "$(cat "$SANDBOX/$f")" ] || changed="$changed $f"
done
if [ "$rc" -eq 0 ]; then
    bad "apply-failure: script exited 0 despite the drifted angie entry"
elif [ -n "$changed" ]; then
    bad "apply-failure: tracked file(s) changed despite the failed mutator:$changed -- $(cat "$SANDBOX/out.log")"
elif ! grep -q 'bump nginx stable: 1.30.4 -> 1.30.5' "$SANDBOX/out.log" || ! grep -q 'no matrix entry matched' "$SANDBOX/out.log"; then
    bad "apply-failure: unexpected log: $(cat "$SANDBOX/out.log")"
elif ! grep -Fq -- '.github/workflows/ci-deep.yml' "$SANDBOX/out.log" || grep -Fq -- 'updates/.github/workflows/ci-deep.yml' "$SANDBOX/out.log"; then
    bad "apply-failure: diagnostic did not name the tracked repository path: $(cat "$SANDBOX/out.log")"
else
    ok "apply-failure: the stable bump was resolved, the angie mutator failed, every tracked file unchanged"
fi

say "== case: authenticated release queries keep the token out of curl argv =="
make_sandbox SANDBOX
bindir="$(stub_bin "$SANDBOX")"
argv_log="$SANDBOX/curl.argv"
header_log="$SANDBOX/curl.header"
token='test-token-not-for-output'
if (
    cd "$SANDBOX"
    GH_TOKEN="$token" CURL_ARGV_LOG="$argv_log" CURL_HEADER_LOG="$header_log" \
        PATH="$bindir:$PATH" bash ci/tools/bump-versions.sh >"$SANDBOX/out.log" 2>&1
); then
    if grep -Fq "$token" "$argv_log"; then
        bad "token-argv: the GitHub token appeared in curl arguments"
    elif ! grep -Fxq -- '--config' "$argv_log" || ! grep -Fxq -- '-' "$argv_log"; then
        bad "token-argv: authenticated queries did not use stdin config: $(cat "$argv_log")"
    elif ! grep -Fqx "header = \"Authorization: Bearer $token\"" "$header_log"; then
        bad "token-argv: the stdin header did not carry the bearer token"
    else
        ok "token-argv: authenticated header used stdin, carried the token, and kept argv clean"
    fi
else
    bad "token-argv: script exited non-zero unexpectedly: $(cat "$SANDBOX/out.log")"
fi

say "== case: missing stable section heading fails closed without edits =="
make_sandbox SANDBOX
declare -A before_heading=()
for f in .github/workflows/ci-deep.yml .github/workflows/harness-fault-arms.yml ci/tools/ci-build.sh ci/tools/windows-pins.sh; do
    before_heading[$f]="$(cat "$SANDBOX/$f")"
done
bindir="$(OMIT_STABLE_HEADING=1 stub_bin "$SANDBOX")"
set +e
(
    cd "$SANDBOX"
    PATH="$bindir:$PATH" bash ci/tools/bump-versions.sh >"$SANDBOX/out.log" 2>&1
)
rc=$?
set -e
changed=""
for f in "${!before_heading[@]}"; do
    [ "${before_heading[$f]}" = "$(cat "$SANDBOX/$f")" ] || changed="$changed $f"
done
if [ "$rc" -eq 0 ]; then
    bad "missing-heading: script exited 0 after the stable heading disappeared"
elif [ -n "$changed" ]; then
    bad "missing-heading: tracked file(s) changed despite the parse failure:$changed"
elif ! grep -Fq 'has no "Stable version" section -- refusing to guess' "$SANDBOX/out.log"; then
    bad "missing-heading: unexpected log: $(cat "$SANDBOX/out.log")"
else
    ok "missing-heading: failed closed, named the missing section, and edited nothing"
fi

say "== case: stable section without a tarball cannot borrow the legacy release =="
make_sandbox SANDBOX
declare -A before_empty_section=()
for f in .github/workflows/ci-deep.yml .github/workflows/harness-fault-arms.yml ci/tools/ci-build.sh ci/tools/windows-pins.sh; do
    before_empty_section[$f]="$(cat "$SANDBOX/$f")"
done
bindir="$(OMIT_STABLE_TARBALL=1 stub_bin "$SANDBOX")"
set +e
(
    cd "$SANDBOX"
    PATH="$bindir:$PATH" bash ci/tools/bump-versions.sh >"$SANDBOX/out.log" 2>&1
)
rc=$?
set -e
changed=""
for f in "${!before_empty_section[@]}"; do
    [ "${before_empty_section[$f]}" = "$(cat "$SANDBOX/$f")" ] || changed="$changed $f"
done
if [ "$rc" -eq 0 ]; then
    bad "empty-section: script exited 0 after the stable tarball disappeared"
elif [ -n "$changed" ]; then
    bad "empty-section: tracked file(s) changed despite the parse failure:$changed"
elif ! grep -Fq 'could not determine NEW_STABLE' "$SANDBOX/out.log"; then
    bad "empty-section: unexpected log: $(cat "$SANDBOX/out.log")"
else
    ok "empty-section: failed closed instead of borrowing the legacy tarball"
fi

say "== case: missing next-section boundary cannot expose a later tarball =="
make_sandbox SANDBOX
declare -A before_missing_boundary=()
for f in .github/workflows/ci-deep.yml .github/workflows/harness-fault-arms.yml ci/tools/ci-build.sh ci/tools/windows-pins.sh; do
    before_missing_boundary[$f]="$(cat "$SANDBOX/$f")"
done
bindir="$(OMIT_LEGACY_HEADING=1 stub_bin "$SANDBOX")"
set +e
(
    cd "$SANDBOX"
    PATH="$bindir:$PATH" bash ci/tools/bump-versions.sh >"$SANDBOX/out.log" 2>&1
)
rc=$?
set -e
changed=""
for f in "${!before_missing_boundary[@]}"; do
    [ "${before_missing_boundary[$f]}" = "$(cat "$SANDBOX/$f")" ] || changed="$changed $f"
done
if [ "$rc" -eq 0 ]; then
    bad "missing-boundary: script exited 0 after the legacy heading disappeared"
elif [ -n "$changed" ]; then
    bad "missing-boundary: tracked file(s) changed despite the parse failure:$changed"
elif ! grep -Fq 'has no "Legacy version" boundary after "Stable version"' "$SANDBOX/out.log"; then
    bad "missing-boundary: unexpected log: $(cat "$SANDBOX/out.log")"
else
    ok "missing-boundary: failed closed instead of exposing a later tarball"
fi

say "== case: install failure on the SECOND changed file rolls back the first =="
make_sandbox SANDBOX
declare -A before_install=()
for f in .github/workflows/ci-deep.yml .github/workflows/harness-fault-arms.yml ci/tools/ci-build.sh ci/tools/windows-pins.sh; do
    before_install[$f]="$(cat "$SANDBOX/$f")"
done
bindir="$(NEW_STABLE=1.30.5 NEW_ANGIE=1.13.0 stub_bin "$SANDBOX")"
set +e
(
    cd "$SANDBOX"
    BUMP_VERSIONS_TEST_FAIL_INSTALL_AT=2 PATH="$bindir:$PATH" bash ci/tools/bump-versions.sh >"$SANDBOX/out.log" 2>&1
)
rc=$?
set -e
changed=""
for f in "${!before_install[@]}"; do
    [ "${before_install[$f]}" = "$(cat "$SANDBOX/$f")" ] || changed="$changed $f"
done
if [ "$rc" -eq 0 ]; then
    bad "install-failure: script exited 0 despite the injected failure"
elif [ -n "$changed" ]; then
    bad "install-failure: tracked file(s) changed despite rollback:$changed"
elif ! grep -q 'injected install failure at changed file 2' "$SANDBOX/out.log"; then
    bad "install-failure: unexpected log: $(cat "$SANDBOX/out.log")"
else
    ok "install-failure: every tracked file remained byte-identical"
fi

say "== case: interruption after the FIRST replacement rolls it back =="
make_sandbox SANDBOX
declare -A before_interrupt=()
for f in .github/workflows/ci-deep.yml .github/workflows/harness-fault-arms.yml ci/tools/ci-build.sh ci/tools/windows-pins.sh; do
    before_interrupt[$f]="$(cat "$SANDBOX/$f")"
done
bindir="$(NEW_STABLE=1.30.5 NEW_ANGIE=1.13.0 stub_bin "$SANDBOX")"
set +e
(
    cd "$SANDBOX"
    BUMP_VERSIONS_TEST_INTERRUPT_INSTALL_AT=1 PATH="$bindir:$PATH" bash ci/tools/bump-versions.sh >"$SANDBOX/out.log" 2>&1
)
rc=$?
set -e
changed=""
for f in "${!before_interrupt[@]}"; do
    [ "${before_interrupt[$f]}" = "$(cat "$SANDBOX/$f")" ] || changed="$changed $f"
done
if [ "$rc" -eq 0 ]; then
    bad "install-interrupt: script exited 0 despite the injected TERM"
elif [ -n "$changed" ]; then
    bad "install-interrupt: tracked file(s) changed despite rollback:$changed"
elif [ "$rc" -ne 143 ]; then
    bad "install-interrupt: expected status 143, got $rc: $(cat "$SANDBOX/out.log")"
else
    ok "install-interrupt: the replaced file was restored byte-identically"
fi

say "== case: format-drift (matrix entry does not match -- must FAIL LOUDLY, no partial edit) =="
make_sandbox SANDBOX
# Corrupt the matrix so version/label are no longer adjacent the way the
# script's pattern expects -- simulates a future reformat/reorder.
cat >"$SANDBOX/.github/workflows/ci-deep.yml" <<'EOF'
env:
  HARNESS_NGINX_VERSION: "1.31.4"
jobs:
  build-flavors:
    strategy:
      matrix:
        include:
          - label: mainline
            version: "1.31.2"
          - label: stable
            version: "1.30.4"
          - label: angie
            version: "1.12.1"
EOF
before_matrix="$(cat "$SANDBOX/.github/workflows/ci-deep.yml")"
before_build="$(cat "$SANDBOX/ci/tools/ci-build.sh")"
bindir="$(NEW_STABLE=1.30.5 stub_bin "$SANDBOX")"
set +e
(
    cd "$SANDBOX"
    PATH="$bindir:$PATH" bash ci/tools/bump-versions.sh >"$SANDBOX/out.log" 2>&1
)
rc=$?
set -e
after_matrix="$(cat "$SANDBOX/.github/workflows/ci-deep.yml")"
after_build="$(cat "$SANDBOX/ci/tools/ci-build.sh")"
if [ "$rc" -eq 0 ]; then
    bad "format-drift: script exited 0 on a no-op replacement (should FAIL LOUDLY)"
elif [ "$before_matrix" != "$after_matrix" ] || [ "$before_build" != "$after_build" ]; then
    bad "format-drift: files were mutated despite the failed match (partial edit)"
elif ! grep -qi 'no matrix entry matched' "$SANDBOX/out.log"; then
    bad "format-drift: exited non-zero but did not report the no-op match: $(cat "$SANDBOX/out.log")"
else
    ok "format-drift: exited non-zero, reported the no-op, and left both files untouched"
fi

say "== case: pins-file drift (a VER_ line missing -- must FAIL LOUDLY before ANY edit) =="
make_sandbox SANDBOX
sed -i '/^VER_PCRE2=/d' "$SANDBOX/ci/tools/windows-pins.sh"
before_pins="$(cat "$SANDBOX/ci/tools/windows-pins.sh")"
before_matrix="$(cat "$SANDBOX/.github/workflows/ci-deep.yml")"
# A stable bump is pending too: the pins check must run before it lands.
bindir="$(NEW_STABLE=1.30.5 NEW_PCRE2=10.48 stub_bin "$SANDBOX")"
set +e
(
    cd "$SANDBOX"
    PATH="$bindir:$PATH" bash ci/tools/bump-versions.sh >"$SANDBOX/out.log" 2>&1
)
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
    bad "pins-drift: script exited 0 with a pin missing from windows-pins.sh"
elif [ "$before_pins" != "$(cat "$SANDBOX/ci/tools/windows-pins.sh")" ] \
    || [ "$before_matrix" != "$(cat "$SANDBOX/.github/workflows/ci-deep.yml")" ]; then
    bad "pins-drift: a file was mutated before the missing pin was reported (partial edit)"
elif ! grep -q 'does not set VER_PCRE2' "$SANDBOX/out.log"; then
    bad "pins-drift: exited non-zero but did not name the missing pin: $(cat "$SANDBOX/out.log")"
else
    ok "pins-drift: exited non-zero, named the missing pin, and edited nothing"
fi

say "== case: harness drift (the two workflows disagree -- must FAIL LOUDLY, no edit) =="
make_sandbox SANDBOX
sed -i 's/HARNESS_NGINX_VERSION: "1.31.4"/HARNESS_NGINX_VERSION: "1.31.3"/' "$SANDBOX/.github/workflows/harness-fault-arms.yml"
before_arms="$(cat "$SANDBOX/.github/workflows/harness-fault-arms.yml")"
before_pins="$(cat "$SANDBOX/ci/tools/windows-pins.sh")"
bindir="$(NEW_MAINLINE=1.31.5 stub_bin "$SANDBOX")"
set +e
(
    cd "$SANDBOX"
    PATH="$bindir:$PATH" bash ci/tools/bump-versions.sh >"$SANDBOX/out.log" 2>&1
)
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
    bad "harness-drift: script exited 0 with the two harness pins disagreeing"
elif [ "$before_arms" != "$(cat "$SANDBOX/.github/workflows/harness-fault-arms.yml")" ] \
    || [ "$before_pins" != "$(cat "$SANDBOX/ci/tools/windows-pins.sh")" ]; then
    bad "harness-drift: a file was mutated despite the disagreement (partial edit)"
elif ! grep -q 'must build the same nginx' "$SANDBOX/out.log"; then
    bad "harness-drift: exited non-zero but did not report the disagreement: $(cat "$SANDBOX/out.log")"
else
    ok "harness-drift: exited non-zero, reported the disagreement, and edited nothing"
fi

if [ "$fail" -eq 0 ]; then
    say "all bump-versions.sh cases pass"
else
    say "one or more bump-versions.sh cases FAILED"
fi
exit "$fail"
