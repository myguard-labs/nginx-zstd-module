#!/usr/bin/env bash
# Run the compression module's nginx-module-testkit consumer scenarios
# (compression/t/harness-scenarios/*) through the harness engine at
# ci/t/harness (the submodule master carries; same pin).
#
# Usage:
#   compression/tools/run_testkit_scenarios.sh --build DIR --version V \
#       [--expect-skip] [scenario ...]
#
#   --build DIR      nginx build tree whose objs/ holds BOTH
#                    ngx_http_compression_filter_module.so and the harness
#                    reference probe ngx_http_test_ref_module.so
#                    (zero-hook shape: the probe is a separate .so, the
#                    compression module carries no probe hooks).
#   --version V      server version, for the engine's build lookup.
#   --expect-skip    invert the verdict: every scenario must SKIP cleanly
#                    (used against a probe-less tree -- the import-prompt's
#                    both-directions rule: a staged tree must produce real
#                    assertions AND an unstaged tree must SKIP rather than
#                    fail; neither half alone can tell a wired-up leg from
#                    a permanently-skipping one).
#
# A run with zero real assertions ("1..0 # SKIP", or all-SKIP TAP) fails
# unless --expect-skip: a permanently-skipping leg is indistinguishable
# from a green one in a job summary, which is the vacuous pass the
# import-prompt warns fails most integrations.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
BUILD=""
VERSION=""
FLAVOR="nginx"
EXPECT_SKIP=0
SCENARIOS=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --build) BUILD="${2:?}"; shift 2 ;;
        --version) VERSION="${2:?}"; shift 2 ;;
        --flavor) FLAVOR="${2:?}"; shift 2 ;;
        --expect-skip) EXPECT_SKIP=1; shift ;;
        -*) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
        *) SCENARIOS+=("$1"); shift ;;
    esac
done

[ -n "$BUILD" ] || { echo "ERROR: --build is required" >&2; exit 2; }
[ -n "$VERSION" ] || { echo "ERROR: --version is required" >&2; exit 2; }

if [ "${#SCENARIOS[@]}" -eq 0 ]; then
    while IFS= read -r d; do
        SCENARIOS+=("$(basename "$d")")
    done < <(find "$ROOT/compression/t/harness-scenarios" -mindepth 1 \
             -maxdepth 1 -type d | sort)
fi

RUN_SCENARIO="$ROOT/ci/t/harness/ci/prober/run-scenario.sh"
[ -x "$RUN_SCENARIO" ] || {
    echo "ERROR: harness engine not found/executable: $RUN_SCENARIO" >&2
    echo "       (git submodule update --init ci/t/harness)" >&2
    exit 2
}

export PROBER_ROOT="$ROOT"
export PROBER_BUILD="$BUILD"
# Zero-hook: the probe directive lives in the harness's reference module,
# not in the compression .so.
export PROBER_MODULE="${PROBER_MODULE:-ngx_http_test_ref_module.so}"
export PROBER_DIRECTIVE="${PROBER_DIRECTIVE:-test_ref_probe}"
export PROBER_PROBE="${PROBER_PROBE:-test_ref_probe;}"

overall=0
for s in "${SCENARIOS[@]}"; do
    dir="$ROOT/compression/t/harness-scenarios/$s"
    [ -d "$dir" ] || { echo "ERROR: no such scenario: $dir" >&2; exit 2; }

    out="$("$RUN_SCENARIO" "$dir" "$FLAVOR" "$VERSION" 2>&1)" && rc=0 || rc=$?

    real_asserts="$(printf '%s\n' "$out" \
                    | grep -cE '^(not )?ok [0-9]+' || true)"
    skipped_all=0
    if printf '%s\n' "$out" | grep -qE '^1\.\.0 # SKIP'; then
        skipped_all=1
    fi

    if [ "$EXPECT_SKIP" -eq 1 ]; then
        # rc must ALSO be 0: a harness can emit "1..0 # SKIP" and then
        # die -- an expected-skip verdict on a failed run would bank a
        # green for a broken engine (CodeRabbit, round 5).
        if [ "$skipped_all" -eq 1 ] && [ "$rc" -eq 0 ]; then
            echo "ok (expected SKIP) $s"
        else
            echo "FAIL $s: expected a clean SKIP against this tree, got rc=$rc with $real_asserts assertion line(s)"
            printf '%s\n' "$out" | tail -15 | sed 's/^/  /'
            overall=1
        fi
        continue
    fi

    if [ "$rc" -ne 0 ]; then
        echo "FAIL $s (rc=$rc)"
        printf '%s\n' "$out" | sed 's/^/  /'
        overall=1
        continue
    fi

    if [ "$skipped_all" -eq 1 ] || [ "$real_asserts" -eq 0 ]; then
        echo "FAIL $s: vacuous run (no real assertions; SKIP=$skipped_all)"
        printf '%s\n' "$out" | tail -10 | sed 's/^/  /'
        overall=1
        continue
    fi

    # Property witness: the scenario's own title metric must have been
    # genuinely evaluated, not SKIPped -- an all-oracle-SKIP run still
    # emits 7 'ok' lines and would read green without this.
    if [ "$s" = "alloc-neutral" ] \
       && ! printf '%s\n' "$out" \
            | grep -qE '^ok 3 - cycle_used was flat'; then
        echo "FAIL $s: the cycle_used oracle did not genuinely run"
        printf '%s\n' "$out" | sed 's/^/  /'
        overall=1
        continue
    fi

    echo "pass $s ($real_asserts assertions)"
done

exit "$overall"
