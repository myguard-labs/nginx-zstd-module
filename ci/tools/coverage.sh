#!/bin/bash
# ci/tools/coverage.sh -- publish a coverage REPORT for src/, never a gate.
#
# Coverage is the cheapest number to inflate: a test that touches a line and
# asserts nothing still moves it, so a floor buys the metric and sells the
# thing it was standing in for. This script has no --fail-under default and
# no exit-nonzero-on-threshold path; COVERAGE_FAIL_UNDER exists only for a
# downstream adopter that has decided otherwise (step 26 note in PROMPT.md).
#
# Usage: ci/tools/coverage.sh [flavor] [version]
#   Runs ci-build.sh in "coverage" mode (separate .build tree, --coverage
#   compiled in), runs ci/t/ against the instrumented binary so .gcda files
#   land next to the .gcno objects, then reports with gcovr FILTERED TO src/
#   -- unfiltered gcovr walks the whole configured nginx tree (order 200k
#   lines of upstream C) and buries the module's own number in noise.
#
# Env:
#   COVERAGE_FAIL_UNDER  optional; if set, gcovr --fail-under-line is used.
#                        Unset by default -- see the header note above.
#
# gcovr flag note: --object-directory is used, NOT --gcov-object-directory,
# which fails argparse on gcovr below 7.0. --object-directory is accepted by
# every gcovr version this script has been run against (verified on 7.2).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
cd "$MODULE_DIR"

FLAVOR="${1:-nginx}"
VERSION="${2:-}"

command -v gcovr >/dev/null || {
    echo "ERROR: gcovr not found (pip install gcovr / apt-get install gcovr)" >&2
    exit 2
}

echo "== coverage: building $FLAVOR ${VERSION:-<mainline>} in coverage mode =="
bash "$SCRIPT_DIR/ci-build.sh" "$FLAVOR" "$VERSION" coverage

# ci-build.sh resolves an empty VERSION to the current mainline; recover the
# resolved value from the build tree it actually created rather than
# re-resolving (a second nginx.org scrape could race a release and disagree).
BUILD_ROOT="${BUILD_ROOT:-$MODULE_DIR/.build}"
SRCDIR="$(find "$BUILD_ROOT" -maxdepth 1 -type d -name "${FLAVOR}-*-coverage" | sort -V | tail -1)"
if [ -z "$SRCDIR" ] || [ ! -d "$SRCDIR" ]; then
    echo "ERROR: no coverage build tree found under $BUILD_ROOT" >&2
    exit 1
fi
echo "Coverage build tree: $SRCDIR"

BIN="$SRCDIR/objs/$FLAVOR"
[ -x "$BIN" ] || { echo "ERROR: $BIN not found or not executable" >&2; exit 1; }

echo "== coverage: exercising the binary via ci/t/ =="
export TEST_NGINX_BINARY="$MODULE_DIR/${SRCDIR#"$MODULE_DIR"/}/objs/$FLAVOR"
export TEST_NGINX_TIMEOUT="${TEST_NGINX_TIMEOUT:-20}"
export TEST_NGINX_SERVROOT="/tmp/nginx-servroot-coverage-filter"
mkdir -p "$TEST_NGINX_SERVROOT"
prove -v ci/t/00-filter.t ci/t/02-conf-warn.t

touch -d @1541504307 ci/t/suite/test ci/t/suite/test.zst
export TEST_NGINX_SERVROOT="$MODULE_DIR/ci/t/servroot-static"
mkdir -p "$TEST_NGINX_SERVROOT"
prove -v ci/t/01-static.t

echo "== coverage: gcovr over src/ only =="
REPORT_DIR="$MODULE_DIR/.build/coverage-report"
mkdir -p "$REPORT_DIR"

# gcovr's --filter/--gcov-filter narrow the REPORT and which gcda match a
# pattern, but gcovr still WALKS every .gcda under the search path first --
# the module's own .o/.gcno/.gcda land flat in objs/ (as
# ngx_http_zstd_<name>_module_modules.*), alongside gcda for the WHOLE
# upstream core (order 200k lines) this addon-module build also compiles
# from scratch, and upstream's gcda resolve to a source layout gcovr can't
# find from here -- a hard error, not a filtered-out line, even under
# --gcov-filter. Pass the module's own .gcda as explicit search_paths so
# gcovr never opens an upstream one at all.
# The addon module's .gcda land at objs/addon/src/, mirroring the
# --add-dynamic-module path nginx's configure stages the module source into
# -- NOT flat in objs/ (that directory holds .gcno for a *_modules.c shim
# that is a compile-time registration stub, never itself executed, so it
# never gets a matching .gcda).
mapfile -t MODULE_GCDA < <(find "$SRCDIR/objs/addon" -name 'ngx_http_zstd_*.gcda')
if [ "${#MODULE_GCDA[@]}" -eq 0 ]; then
    echo "ERROR: no .gcda for the zstd module under $SRCDIR/objs -- ci/t/ did not" \
        "exercise the coverage-instrumented binary" >&2
    exit 1
fi

# Even given only the module's OWN .gcda, gcov still resolves an inlined
# call target's compilation unit and reports on gcda for upstream objects
# (ngx_event.c, ngx_open_file_cache.c, ...) that are not under $MODULE_DIR --
# a real gcov behaviour, not a gcovr bug. Those errors are non-fatal to the
# run (gcovr logs and continues) and --filter drops them from the report
# regardless; --gcov-ignore-errors=no_working_dir_found silences the noise
# without hiding a real parse failure in the module's own files.
GCOVR_ARGS=(
    --root "$MODULE_DIR"
    --filter "$MODULE_DIR/src/"
    --object-directory "$SRCDIR/objs"
    --gcov-ignore-errors=no_working_dir_found
    --print-summary
    --xml "$REPORT_DIR/coverage.xml"
    --html-details "$REPORT_DIR/coverage.html"
    "${MODULE_GCDA[@]}"
)
if [ -n "${COVERAGE_FAIL_UNDER:-}" ]; then
    GCOVR_ARGS+=(--fail-under-line "$COVERAGE_FAIL_UNDER")
fi

gcovr "${GCOVR_ARGS[@]}"

echo "== coverage: report written to $REPORT_DIR =="
