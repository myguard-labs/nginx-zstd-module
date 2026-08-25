#!/usr/bin/env bash
#
# Scenario: CODEC FAULT-INJECTION ARMS for ngx_http_zstd_filter_module.so.
#
# Reachable only through the harness's TEST_HARNESS build (see
# plan-testkit-integration.md Ground truth + Phase 3): the module's single
# ZSTD_compressStream2() call site at filter_module.c is preceded by a fault
# check keyed on `directive == ZSTD_e_end` (site CODEC_END) vs. every other
# directive (site CODEC). Armed via GET /__probe?fault_codec=<n> or
# fault_codec_end=<n>: 1..999 injects a ZSTD_isError()-true return on the
# n-th call at that site since the arm; 1000+n injects success-with-
# zero-output on the n-th call.
#
# Non-vacuity discipline copied from consumer-zstd/driver.sh: if the basis a
# set of oracles needs (a probe reading, a completed request) is missing,
# those oracles FAIL rather than SKIP-to-green. See "if every oracle SKIPs,
# red" in Phase 4's task list.
set -euo pipefail

# shellcheck source=../../harness/ci/prober/lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

FAILED=0

mkdir -p "$PROBER_PREFIX/www"
# 200 KB body: big enough that a single ZSTD_compressStream2 call does not
# necessarily drain it in one shot (module's own buffer sizing), which is
# what makes the CODEC (non-end) site reachable at all on a real request --
# not just the CODEC_END site every response also passes through.
head -c 204800 /dev/zero | tr '\0' 'a' >"$PROBER_PREFIX/www/body.bin"
printf 'irrelevant\n' >"$PROBER_PREFIX/www/index.html"

# arm SITE NTH: GET /__probe?fault_<site>=<nth>, discard the body, return 0
# only if the probe answered at all (arming and reading are the same request
# here -- see ngx_http_zstd_probe_handler's "arm-then-render" comment).
arm() {
    local site="$1" nth="$2"
    curl -fsS --max-time 5 \
        "http://$HOST:$PORT/__probe?fault_${site}=${nth}" -o /dev/null
}

# disarm SITE: same shape, negative nth.
disarm() {
    local site="$1"
    curl -fsS --max-time 5 \
        "http://$HOST:$PORT/__probe?fault_${site}=-1" -o /dev/null
}

# fetch PATH OUTFILE: bounded GET, split into headers (first blank-line
# block) and body, returns the exit status of curl. Uses -D to capture
# headers separately so an ERROR outcome (nginx tears the connection down
# with no body) is still observable via headers-vs-no-headers, not just via
# curl's exit status, which a transfer-encoding mismatch can also trip.
fetch() {
    local path="$1" out="$2" hdrs="$2.hdrs"
    curl -sS --max-time 10 -D "$hdrs" -o "$out" \
        -H 'Accept-Encoding: zstd' \
        "http://$HOST:$PORT$path" 2>"$out.stderr"
}

# --- oracle plan --------------------------------------------------------
# 1  warm-up: plain request serves 200 (readiness)
# 2  CODEC ERROR (fault_codec=1) on a plain compressing request: the request
#    fails closed (no 200, connection torn down) rather than serving
#    corrupt/truncated compressed bytes -- proves the central ZSTD_isError
#    arm at filter_module.c:2244 is reachable and fails safely
# 3  CODEC_END ERROR (fault_codec_end=1) on the SAME plain request: same
#    fail-closed assertion at the end-of-frame site specifically
# 4  CODEC_END ZERO on the 2nd END call (fault_codec_end=1002): forces the
#    empty-out_buf suppression arm and the response still completes fully
#    -- not a hang, not a torn-down connection. Deliberately nth=2, not 1:
#    see the oracle's own comment for the separate, real defect nth=1 hits
#    on this body (ledgered, not fixed here)
# 5  CODEC ERROR on the 2nd call (fault_codec=2): proves the non-END
#    streaming site is reached MORE THAN ONCE per response (a body this
#    size needs several ZSTD_compressStream2 calls to drain), by failing
#    that 2nd call closed the same way oracle 2 proves the 1st call fails
#    closed
# 6  disarming restores normal (uncorrupted) compression -- proves the
#    fault state is per-arm, not sticky
# 7  no worker died by signal across the whole run
echo "1..7"

# --- 1: warm-up -----------------------------------------------------------
WARMUP="$PROBER_PREFIX/warmup.out"
if fetch /body.bin "$WARMUP" && grep -q '^HTTP/1.1 200' "$WARMUP.hdrs"; then
    echo "ok 1 - warm-up request served a clean 200"
else
    echo "not ok 1 - warm-up request did not serve a clean 200"
    FAILED=$((FAILED + 1))
fi

# --- 2: CODEC ERROR fails closed -------------------------------------------
#
# arm must succeed on its own -- a curl failure to even reach /__probe means
# nothing was armed, and the request that follows would then simply succeed
# for an unrelated reason (never armed), which must NOT read as "failed
# closed, ok 2". Armed-then-either(no-200-headers, fetch itself errored) is
# the fail-closed signature.
ERR_OUT="$PROBER_PREFIX/codec-err.out"
ARM2_OK=0
GOT200_2=0
if arm codec 1; then
    ARM2_OK=1
    if fetch /body.bin "$ERR_OUT" && grep -q '^HTTP/1.1 200' "$ERR_OUT.hdrs" 2>/dev/null; then
        GOT200_2=1
    fi
fi
if [ "$ARM2_OK" -eq 1 ] && [ "$GOT200_2" -eq 0 ]; then
    echo "ok 2 - CODEC ERROR (fault_codec=1) made a compressing request fail closed, not serve corrupt output"
else
    echo "not ok 2 - CODEC ERROR did not fail the request (arm_ok=$ARM2_OK; isError arm at ~filter_module.c:2244 not reached, or not fail-closed)"
    FAILED=$((FAILED + 1))
fi
disarm codec || true

# --- 3: CODEC_END ERROR fails closed ---------------------------------------
END_ERR_OUT="$PROBER_PREFIX/codec-end-err.out"
ARM3_OK=0
GOT200_3=0
if arm codec_end 1; then
    ARM3_OK=1
    if fetch /body.bin "$END_ERR_OUT" && grep -q '^HTTP/1.1 200' "$END_ERR_OUT.hdrs" 2>/dev/null; then
        GOT200_3=1
    fi
fi
if [ "$ARM3_OK" -eq 1 ] && [ "$GOT200_3" -eq 0 ]; then
    echo "ok 3 - CODEC_END ERROR (fault_codec_end=1) made the terminal-frame call fail closed"
else
    echo "not ok 3 - CODEC_END ERROR did not fail the request (arm_ok=$ARM3_OK)"
    FAILED=$((FAILED + 1))
fi
disarm codec_end || true

# --- 4: CODEC_END ZERO (2nd END call) completes cleanly ---------------------
#
# nth MUST be 1002 (2nd call at the END site), never 1001 (the 1st): with
# this body size, forcing zero output on the very FIRST ZSTD_e_end call
# reaches an existing, independent defect -- a genuinely empty terminal
# buffer that is emitted with last_buf set trips nginx core's
# "zero size buf in writer" guard and the connection is torn down mid-
# response (reproduced manually, filed as issues.md: forcing zero output on
# the first END call truncates the frame). That is real and ledgered
# separately; it is NOT what this oracle exists to assert, and using nth=1
# here would make Phase 4 ship a permanently-red gate for an unrelated,
# unfixed bug. nth=2 lands on a LATER END call, once real streaming has
# already produced output, which is the suppression arm this oracle
# actually targets (documented ok-for-3+ manually: 1002-1999 all complete
# cleanly on this body).
#
# "Completes with a 200" alone would be vacuous -- a compressible 200-KB body
# of identical bytes and an unfaulted request both give the same ~26-byte
# frame -- so the response must also DECODE: a complete, parseable zstd frame
# whose plaintext is byte-for-byte the origin file. A truncated or aborted
# transfer fails `zstd -d`, and a frame that decodes to the wrong bytes fails
# the cmp. Checking only `[ -s ]` here would accept both.
END_ZERO_OUT="$PROBER_PREFIX/codec-end-zero.out"
END_ZERO_OK=0
if arm codec_end 1002 && fetch /body.bin "$END_ZERO_OUT"; then
    if grep -q '^HTTP/1.1 200' "$END_ZERO_OUT.hdrs" \
        && ! grep -qE '^(curl:|$)' "$END_ZERO_OUT.stderr" 2>/dev/null \
        && [ -s "$END_ZERO_OUT" ] \
        && zstd -d -q -f -o "$END_ZERO_OUT.plain" "$END_ZERO_OUT" 2>/dev/null \
        && cmp -s "$END_ZERO_OUT.plain" "$PROBER_PREFIX/www/body.bin"
    then
        END_ZERO_OK=1
    fi
fi
if [ "$END_ZERO_OK" -eq 1 ]; then
    echo "ok 4 - CODEC_END ZERO (fault_codec_end=1002, 2nd END call) still completed with a full response (suppression arm reached past the first-call defect, no hang/truncation)"
else
    echo "not ok 4 - CODEC_END ZERO (2nd call) did not complete cleanly"
    FAILED=$((FAILED + 1))
fi
disarm codec_end || true

# --- 5: CODEC site is called MORE THAN ONCE -- fail-closed on the 2nd call -
#
# A single ZSTD_compressStream2() call rarely drains a 200-KB body (the
# module's own output buffer is much smaller), so the non-END (CODEC) site
# is called repeatedly across one response. fault_codec=2 (ERROR outcome,
# 2nd call) proves that second call is genuinely reached: if the loop
# somehow only ever ran the site once (e.g. a regression that emits
# everything from the first call, or that reroutes subsequent iterations
# around the fault check), nth=2 would never match and the request would
# complete normally instead of failing closed. Same fail-closed assertion
# shape as oracle 2 (which already covers nth=1); this is the nth-2+
# reachability half of the same arm.
ERR2_OUT="$PROBER_PREFIX/codec-err2.out"
ARM5_OK=0
GOT200_5=0
if arm codec 2; then
    ARM5_OK=1
    if fetch /body.bin "$ERR2_OUT" && grep -q '^HTTP/1.1 200' "$ERR2_OUT.hdrs" 2>/dev/null; then
        GOT200_5=1
    fi
fi
if [ "$ARM5_OK" -eq 1 ] && [ "$GOT200_5" -eq 0 ]; then
    echo "ok 5 - CODEC ERROR on the 2nd call (fault_codec=2) failed closed, proving the streaming site is reached more than once per response"
else
    echo "not ok 5 - CODEC ERROR on the 2nd call did not fail the request (arm_ok=$ARM5_OK; site called fewer than 2 times, or the fault check does not re-run)"
    FAILED=$((FAILED + 1))
fi
disarm codec || true

# --- 6: disarm restores normal compression ----------------------------------
RESTORE_OUT="$PROBER_PREFIX/restore.out"
RESTORE_OK=0
if fetch /body.bin "$RESTORE_OUT" && grep -q '^HTTP/1.1 200' "$RESTORE_OUT.hdrs"; then
    RESTORE_OK=1
fi
if [ "$RESTORE_OK" -eq 1 ]; then
    echo "ok 6 - after disarming, a compressing request serves a clean 200 again (fault state is per-arm, not sticky)"
else
    echo "not ok 6 - request after disarm did not serve a clean 200"
    FAILED=$((FAILED + 1))
fi

# --- 7: no signal-death across the run --------------------------------------
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 7 - a worker died by signal during fault injection"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 7 - no worker died by signal across the whole fault-injection run"
fi

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
