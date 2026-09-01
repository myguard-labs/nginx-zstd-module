#!/usr/bin/env bash
#
# Hermetic regression test for audit A30-F4: ci/tools/bump-versions.sh used
# stale pre-move paths (tools/keys/, tools/ci-build.sh) that do not exist
# after the tools/ -> ci/tools/ move, so a real bump could not import the
# PGP keyring and a matrix/pin replacement that matched nothing failed
# silently, leaving a partial edit.
#
# This test builds a scratch copy of the repo layout the script actually
# needs (ci/tools/ci-build.sh, ci/tools/keys/*.key, .github/workflows/
# ci-deep.yml matrix) and stubs curl/gpg/sha256sum on PATH so no network is
# used. It drives bump-versions.sh --covered by a scenario cases-array so
# each case name is asserted individually.
#
# Usage: ci/tools/test_bump_versions.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUMP_SCRIPT="$REPO_ROOT/ci/tools/bump-versions.sh"

fail=0
say() { printf '%s\n' "$*"; }
ok() { printf 'OK: %s\n' "$*"; }
bad() {
    printf 'FAIL: %s\n' "$*"
    fail=1
}

# make_sandbox VARNAME  -- creates a scratch repo layout under a temp dir and
# assigns its path to VARNAME.
make_sandbox() {
    # shellcheck disable=SC2034  # nameref out-parameter, assigned for the caller
    local -n out="$1"
    local dir
    dir="$(mktemp -d)"
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
    cat >"$dir/.github/workflows/ci-deep.yml" <<'EOF'
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
    cp "$BUMP_SCRIPT" "$dir/ci/tools/bump-versions.sh"
    # shellcheck disable=SC2034  # nameref out-parameter, read by the caller
    out="$dir"
}

# stub_bin DIR -- creates PATH-shadowing curl/gpg/sha256sum stubs and prints
# the bin dir to prepend to PATH. Reads NEW_STABLE / NEW_ANGIE env for what
# "latest" should resolve to.
stub_bin() {
    local dir="$1" bindir="$1/bin"
    mkdir -p "$bindir"
    cat >"$bindir/curl" <<EOF
#!/bin/bash
# Fake nginx.org download page / angie GitHub API / tarball fetch.
for a in "\$@"; do
    case "\$a" in
        *nginx.org/en/download.html*)
            echo "Stable versionnginx-${NEW_STABLE}.tar.gz"
            exit 0 ;;
        *api.github.com*angie*releases/latest*)
            echo "{\"tag_name\": \"${NEW_ANGIE}\"}"
            exit 0 ;;
        -o) : ;;
    esac
done
# tarball / .asc fetch: write a dummy file at -o target if present.
out=""
prev=""
for a in "\$@"; do
    if [ "\$prev" = "-o" ]; then out="\$a"; fi
    prev="\$a"
done
[ -n "\$out" ] && echo "dummy-tarball-bytes" > "\$out"
exit 0
EOF
    cat >"$bindir/gpg" <<'EOF'
#!/bin/bash
# Accept any --import / --verify as success (hermetic stub).
exit 0
EOF
    chmod +x "$bindir/curl" "$bindir/gpg"
    echo "$bindir"
}

# run_case NAME NEW_STABLE NEW_ANGIE  -- runs bump-versions.sh in $1's sandbox
# with the given "latest" values and returns its exit status; sandbox path is
# left in SANDBOX for the caller to inspect.
run_case() {
    local ns="$2" na="$3"
    make_sandbox SANDBOX
    local bindir
    bindir="$(NEW_STABLE="$ns" NEW_ANGIE="$na" stub_bin "$SANDBOX")"
    (
        cd "$SANDBOX"
        PATH="$bindir:$PATH" NEW_STABLE="$ns" NEW_ANGIE="$na" \
            bash ci/tools/bump-versions.sh >"$SANDBOX/out.log" 2>&1
    )
    return $?
}

say "== case: stable-only bump =="
if run_case stable-only "1.30.5" "1.12.1"; then
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
if run_case angie-only "1.30.4" "1.13.0"; then
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
if run_case both "1.30.5" "1.13.0"; then
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
if run_case no-change "1.30.4" "1.12.1"; then
    if grep -q 'CHANGED=0' "$SANDBOX/out.log"; then
        ok "no-change: script reports CHANGED=0 and exits 0"
    else
        bad "no-change: expected CHANGED=0, got: $(cat "$SANDBOX/out.log")"
    fi
else
    bad "no-change: script exited non-zero unexpectedly: $(cat "$SANDBOX/out.log")"
fi

say "== case: format-drift (matrix entry does not match -- must FAIL LOUDLY, no partial edit) =="
make_sandbox SANDBOX
# Corrupt the matrix so version/label are no longer adjacent the way the
# script's pattern expects -- simulates a future reformat/reorder.
cat >"$SANDBOX/.github/workflows/ci-deep.yml" <<'EOF'
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
bindir="$(NEW_STABLE=1.30.5 NEW_ANGIE=1.12.1 stub_bin "$SANDBOX")"
set +e
(
    cd "$SANDBOX"
    PATH="$bindir:$PATH" NEW_STABLE=1.30.5 NEW_ANGIE=1.12.1 \
        bash ci/tools/bump-versions.sh >"$SANDBOX/out.log" 2>&1
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

if [ "$fail" -eq 0 ]; then
    say "all bump-versions.sh cases pass"
else
    say "one or more bump-versions.sh cases FAILED"
fi
exit "$fail"
