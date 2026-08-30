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
#   COVERAGE_HARNESS     optional, default 1. When 1, the coverage tree is
#                        built with the TEST_HARNESS probe compiled in and the
#                        ci/t/harness-scenarios/* scenarios are run against it
#                        after the Test::Nginx suites, so the libzstd FAULT
#                        paths (which no ci/t/ test can reach -- there is no
#                        way to make libzstd fail from the outside) are counted
#                        instead of being reported as dead lines. Set to 0 to
#                        reproduce the pre-harness number.
#
# gcovr flag note: --object-directory is used, NOT --gcov-object-directory,
# which fails argparse on gcovr below 7.0. --object-directory is accepted by
# every gcovr version this script has been run against (verified on 7.2).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=ci/linter/lib.sh
. "$MODULE_DIR/ci/linter/lib.sh"
cd "$MODULE_DIR"

collect_module_gcda() {
    mapfile_checked MODULE_GCDA find "$1" -name 'ngx_http_zstd_*.gcda'
}

if [ "${1:-}" = "--selftest-work-list" ]; then
    collect_module_gcda "${2:?usage: coverage.sh --selftest-work-list DIR}"
    exit 0
fi

FLAVOR="${1:-nginx}"
VERSION="${2:-}"

command -v gcovr >/dev/null || {
    echo "ERROR: gcovr not found (pip install gcovr / apt-get install gcovr)" >&2
    exit 2
}

COVERAGE_HARNESS="${COVERAGE_HARNESS:-1}"

echo "== coverage: building $FLAVOR ${VERSION:-<mainline>} in coverage mode =="
if [ "$COVERAGE_HARNESS" = "1" ]; then
    # BOTH switches, always together. TEST_HARNESS=1 alone compiles the probe
    # sources and still yields a probe-free .so -- measured in this repo
    # (packaged=0 probe symbols, TEST_HARNESS=1 alone=0, both=18). With a
    # probe-free .so every scenario below would SKIP or fail to arm, and the
    # coverage number would silently be the pre-harness one while claiming
    # otherwise. Verified compatible with --coverage: the coverage tree builds
    # clean with the probe in and emits .gcno for every unit.
    echo "   (with TEST_HARNESS -- fault paths will be exercised)"
    TEST_HARNESS=1 CFLAGS="${CFLAGS:-} -DNGX_TEST_HARNESS" \
        bash "$SCRIPT_DIR/ci-build.sh" "$FLAVOR" "$VERSION" coverage
else
    bash "$SCRIPT_DIR/ci-build.sh" "$FLAVOR" "$VERSION" coverage
fi

# ci-build.sh resolves an empty VERSION to the current mainline; recover the
# resolved value from the build tree it actually created rather than
# re-resolving (a second nginx.org scrape could race a release and disagree).
BUILD_ROOT="${BUILD_ROOT:-$MODULE_DIR/.build}"
if [ -n "$VERSION" ]; then
    # An explicit version names exactly one tree. Globbing here instead would
    # silently report on whatever version sorts highest -- ask for 1.30.4 with a
    # 1.31.2 tree present and you get a coverage figure for the wrong binary,
    # which reads as a real measurement.
    SRCDIR="$BUILD_ROOT/${FLAVOR}-${VERSION}-coverage"
else
    SRCDIR="$(find "$BUILD_ROOT" -maxdepth 1 -type d -name "${FLAVOR}-*-coverage" | sort -V | tail -1)"
fi
if [ -z "$SRCDIR" ] || [ ! -d "$SRCDIR" ]; then
    echo "ERROR: no coverage build tree found under $BUILD_ROOT" >&2
    [ -n "$VERSION" ] && echo "       expected: $SRCDIR" >&2
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

# The harness scenarios. These are the ONLY thing in this repo that reaches
# the libzstd failure arms: a ZSTD_compressStream2() error cannot be provoked
# from outside the process, so every ci/t/ test above walks the success path
# and the error branches read as dead lines. Running them here folds those
# branches into the same .gcda set the report is built from.
#
# Failure here is NOT fatal to the report. This script publishes a number and
# is explicitly never a gate (see the header); a scenario that cannot boot on
# some host should cost the run those lines and say so, not abort a coverage
# report the rest of which is valid. The scenario suites themselves gate in
# CI -- harness-fault-arms.yml on every PR, harness-memcheck monthly.
if [ "$COVERAGE_HARNESS" = "1" ]; then
    echo "== coverage: exercising the fault paths via ci/t/harness-scenarios =="
    if [ ! -x "$MODULE_DIR/ci/t/harness/ci/prober/run-scenario.sh" ]; then
        echo "WARNING: harness submodule not checked out" \
             "(git submodule update --init ci/t/harness) --" \
             "fault-path lines will report as uncovered" >&2
    else
        # Build the prober's own C tools if they are not there yet; the engine
        # does not build them and a missing binary bails the scenario.
        if [ ! -x "$MODULE_DIR/ci/t/harness/ci/prober/prober" ]; then
            bash "$MODULE_DIR/ci/t/harness/ci/prober/build.sh" || true
        fi

        # VERSION may be empty (ci-build.sh resolves mainline itself), but
        # run-scenario.sh needs a concrete flavor/version pair to recompute
        # the same build path lib.sh will. Recover it from the tree that was
        # actually built rather than re-resolving -- a second nginx.org scrape
        # could race a release and disagree, which is the same reasoning the
        # SRCDIR block above uses.
        scen_version="${SRCDIR##*/}"          # e.g. nginx-1.31.4-coverage
        scen_version="${scen_version%-coverage}"
        scen_version="${scen_version#"$FLAVOR-"}"

        for scen in fault-arms alloc-neutral; do
            scen_dir="$MODULE_DIR/ci/t/harness-scenarios/$scen"
            [ -d "$scen_dir" ] || continue
            echo "-- scenario: $scen"
            (
                cd "$MODULE_DIR/ci/t/harness/ci/prober"
                # PROBER_ALLOW_LOG exempts exactly the [alert] the module logs
                # for a DELIBERATELY injected libzstd failure. Without it the
                # prober's log scrape reds the run for the fault it was asked
                # to inject. It cannot exempt a sanitizer/valgrind diagnostic
                # (PROBER_SANITIZER_RE is never exemptable), so it does not
                # weaken anything else.
                PROBER_ROOT="$MODULE_DIR" \
                PROBER_BUILD="$SRCDIR" \
                PROBER_MODULE=ngx_http_zstd_filter_module.so \
                PROBER_DIRECTIVE=zstd_probe \
                PROBER_PROBE="zstd_probe;" \
                PROBER_ALLOW_LOG='zstd: ZSTD_compressStream2\(\) failed' \
                    ./run-scenario.sh "$scen_dir" "$FLAVOR" "$scen_version"
            ) || echo "WARNING: scenario $scen did not pass;" \
                      "its lines will be missing from the report" >&2
        done
    fi
fi

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
collect_module_gcda "$SRCDIR/objs/addon"
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
