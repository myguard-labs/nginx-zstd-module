#!/usr/bin/env bash
#
# Scenario: ZSTD_CCtx_setParameter() CALL COUNT, DICTIONARY MODES.
#
# Pins the per-mode instrumentation this item's done criterion asks for.
# Both dictionary paths live here because zstd_dict_file is http{}-context
# (see nginx.conf's comment for why a genuinely dict-free arm cannot share
# this conf) -- the no-dict reference count (3) is measured separately in
# the sibling setparam-call-count-nodict scenario.
#
#   /cdict/  trained CDict (zlcf->dict, refCDict): only compressionLevel is
#            in zstd.h's refCDict-superseded "compression parameters" block
#            (ZSTD_CCtx_refCDict() takes it from the CDict's own baked
#            ZSTD_compressionParameters). windowLog is NOT superseded --
#            ZSTD_resetCCtx_byAttachingCDict()/ZSTD_resetCCtx_byCopyingCDict()
#            (zstd_compress.c) both restore it from the CCtx's own applied
#            params right after copying the CDict's other cParams, so
#            init_cctx keeps setting it here -> 2 calls (windowLog, LDM).
#   /dcz/    negotiated raw-content CDict: level is superseded by the
#            config-time CDict, while windowLog (the dcz-aware per-request
#            value), LDM and checksumFlag(dcz) still apply -> 3 calls.
#
# THE OUTPUT-IDENTITY HALF. A call count on its own is satisfied by a
# response that is fast and wrong, so every oracle here is paired with a
# byte-for-byte decode against the origin -- the same shape as
# codec-call-count/driver.sh, and for the same reason (see its header).
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

FAILED=0
N=0

ok()    { N=$((N + 1)); echo "ok $N - $1"; }
notok() { N=$((N + 1)); echo "not ok $N - $1"; FAILED=1; }
diag()  { echo "# $1"; }

WWW="$PROBER_PREFIX/www"
mkdir -p "$WWW" "$PROBER_PREFIX/tmp"

# Larger than 2**20 (zstd_window_log 20 in nginx.conf, both arms): a body
# smaller than the window cap lets zstd shrink the FRAME's encoded window to
# fit the content regardless of what ZSTD_c_windowLog was set to, which would
# make the cap assertion below pass whether or not the cap was actually
# applied. Random bytes so the compressor cannot fold the whole body into a
# handful of long matches and shrink the decode/measure cost.
awk 'BEGIN {
    srand(42)
    n = 1200000
    for (i = 0; i < n; i++) {
        printf "%c", 97 + int(rand() * 26)
    }
}' >"$WWW/index.html"

DICT_FILE="$(dirname "$PROBER_SERVER_BIN")/setparam-call-count.dict"
DICT_SHA_B64="$(openssl dgst -sha256 -binary "$DICT_FILE" 2>/dev/null \
                | openssl base64 -A 2>/dev/null || true)"

reset_counter() {
    curl -fsS --max-time 5 "http://$HOST:$PORT/__probe?setparam_reset=1" \
        -o /dev/null
}

read_counter() {
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    prober_probe_field "$body" "setparam_calls" || return 1
}

# measure LABEL PATH ENC EXPECT [EXTRA_HEADER...]
measure() {
    local label="$1" path="$2" enc="$3" expect="$4"; shift 4
    local hdrs="$PROBER_PREFIX/tmp/${label}.hdrs"
    local body="$PROBER_PREFIX/tmp/${label}.bin"
    local -a extra=(-H 'Accept-Encoding: zstd')
    local h
    for h in "$@"; do extra+=(-H "$h"); done

    if ! reset_counter; then
        notok "$label: probe did not answer setparam_reset"
        notok "$label: response decodes byte-for-byte to the origin"
        notok "$label: setParameter call count is $expect"
        return
    fi

    if ! curl -sS --max-time 15 -D "$hdrs" -o "$body" "${extra[@]}" \
             "http://$HOST:$PORT$path" 2>"$body.err"; then
        notok "$label: request failed or timed out"
        notok "$label: response decodes byte-for-byte to the origin"
        notok "$label: setParameter call count is $expect"
        return
    fi

    if ! grep -qi "^content-encoding:[[:space:]]*$enc" "$hdrs"; then
        diag "$label: headers were: $(tr -d '\r' <"$hdrs" | tr '\n' ' ')"
        notok "$label: response carried Content-Encoding: $enc"
        notok "$label: response decodes byte-for-byte to the origin"
        notok "$label: setParameter call count is $expect"
        return
    fi
    ok "$label: response carried Content-Encoding: $enc"

    if zstd -d -q -f -o "$body.dec" "$body" -D "$DICT_FILE" 2>/dev/null \
       && cmp -s "$body.dec" "$WWW/index.html"; then
        ok "$label: response decodes byte-for-byte to the origin"
    else
        notok "$label: response decodes byte-for-byte to the origin"
    fi

    local got
    got="$(read_counter || echo -1)"
    if [ "$got" -eq "$expect" ]; then
        ok "$label: setParameter call count is $expect"
    else
        diag "$label: setparam_calls=$got expected=$expect"
        notok "$label: setParameter call count is $expect (got $got)"
    fi
}

# assert_window_cap LABEL FRAME_FILE WINDOW_LOG: parse the compressed
# frame's own Window_Descriptor via `zstd -l -v` and require it to be
# EXACTLY 2**WINDOW_LOG. This is the direct regression check for the
# windowLog-is-NOT-superseded-by-cdict finding: the setParameter call
# count above proves windowLog was SET on the CCtx, but not that the
# resulting FRAME actually carries the operator's cap -- a build that
# silently dropped the CCtx-side set (the exact bug ZSTD_resetCCtx_
# byAttachingCDict()/ZSTD_resetCCtx_byCopyingCDict() would produce, see
# nginx.conf's comment) still passes the call-count oracle if something
# else pushes the count back to 2 by coincidence, but the frame itself
# would then carry libzstd's level-derived window instead of 1 MiB. The
# fixture is 1200000 bytes, larger than 2**20, specifically so the window
# cannot shrink to fit content and mask an uncapped default.
assert_window_cap() {
    local label="$1" frame="$2" wlog="$3"
    local want=$((1 << wlog))
    local got

    got="$(zstd -l -v "$frame" 2>/dev/null \
        | grep -oP 'Window Size:.*\(\K[0-9]+(?= B\))' | head -1)"

    if [ -z "$got" ]; then
        notok "$label: frame window size is $want B (zstd -l -v produced no Window Size line)"
        return
    fi

    if [ "$got" -eq "$want" ]; then
        ok "$label: frame window size is $want B"
    else
        diag "$label: frame Window Size=$got B expected=$want B"
        notok "$label: frame window size is $want B (got $got B)"
    fi
}

echo "1..12"

# /cdict/: no dcz negotiation header, so init_cctx takes the zlcf->dict
# branch. level is superseded-by-cdict and skipped; windowLog is NOT
# superseded (restored from the CCtx's own params by
# ZSTD_resetCCtx_by{Attaching,Copying}CDict()) and stays set alongside LDM.
measure "cdict" "/cdict/index.html" "zstd" 2
assert_window_cap "cdict" "$PROBER_PREFIX/tmp/cdict.bin" 20

if [ -n "$DICT_SHA_B64" ]; then
    # Disarming also resets the dcz-only attachment counter. This brackets
    # exactly the two requests below while leaving the config-time build
    # count intact.
    curl -fsS --max-time 5 \
        "http://$HOST:$PORT/__probe?fault_dczdict=-1" -o /dev/null

    measure "dcz" "/dcz/index.html" "dcz" 3 \
        "Accept-Encoding: zstd, dcz" \
        "Available-Dictionary: :$DICT_SHA_B64:"

    BUILDS_AFTER_FIRST="$(prober_probe_field \
        "$(prober_probe_body "$HOST" "$PORT")" dcz_cdict_builds || echo -1)"
    CALLS_AFTER_FIRST="$(prober_probe_field \
        "$(prober_probe_body "$HOST" "$PORT")" dcz_cdict_refs || echo -1)"
    if [ "$BUILDS_AFTER_FIRST" -eq 1 ]; then
        ok "dcz: one raw-content CDict was built at configuration load"
    else
        diag "dcz: dcz_cdict_builds=$BUILDS_AFTER_FIRST expected=1"
        notok "dcz: one raw-content CDict was built at configuration load"
    fi
    if [ "$CALLS_AFTER_FIRST" -eq 1 ]; then
        ok "dcz: first request attached the prepared CDict once"
    else
        diag "dcz: dcz_cdict_refs=$CALLS_AFTER_FIRST expected=1"
        notok "dcz: first request attached the prepared CDict once"
    fi

    REUSE_BODY="$PROBER_PREFIX/tmp/dcz-reuse.bin"
    if curl -sS --max-time 15 -o "$REUSE_BODY" \
           -H 'Accept-Encoding: zstd, dcz' \
           -H "Available-Dictionary: :$DICT_SHA_B64:" \
           "http://$HOST:$PORT/dcz/index.html" \
       && zstd -d -q -f -o "$REUSE_BODY.dec" "$REUSE_BODY" \
               -D "$DICT_FILE" 2>/dev/null \
       && cmp -s "$REUSE_BODY.dec" "$WWW/index.html"
    then
        ok "dcz: repeated request decodes byte-for-byte with the raw dictionary"
    else
        notok "dcz: repeated request decodes byte-for-byte with the raw dictionary"
    fi

    REUSE_PROBE="$(prober_probe_body "$HOST" "$PORT" || true)"
    BUILDS_AFTER_REUSE="$(prober_probe_field "$REUSE_PROBE" \
        dcz_cdict_builds || echo -1)"
    CALLS_AFTER_REUSE="$(prober_probe_field "$REUSE_PROBE" \
        dcz_cdict_refs || echo -1)"
    if [ "$BUILDS_AFTER_REUSE" -eq 1 ] && [ "$CALLS_AFTER_REUSE" -eq 2 ]; then
        ok "dcz: repeated request reused one prebuilt CDict (1 build, 2 attachments)"
    else
        diag "dcz: builds=$BUILDS_AFTER_REUSE calls=$CALLS_AFTER_REUSE expected=1/2"
        notok "dcz: repeated request reused one prebuilt CDict (1 build, 2 attachments)"
    fi
else
    # NOT a SKIP -- see codec-call-count/driver.sh's identical reasoning:
    # openssl(1) is a hard requires-gate, so reaching here means the hash
    # derivation failed for some other reason (unreadable/truncated
    # dictionary), and a SKIP would read as a pass to anything grepping
    # for the oracle.
    notok "dcz: response carried Content-Encoding: dcz (could not derive the dictionary hash from $DICT_FILE)"
    notok "dcz: response decodes byte-for-byte to the origin (no dictionary hash)"
    notok "dcz: setParameter call count is 3 (no dictionary hash)"
    notok "dcz: one raw-content CDict was built at configuration load (no dictionary hash)"
    notok "dcz: first request attached the prepared CDict once (no dictionary hash)"
    notok "dcz: repeated request decodes byte-for-byte with the raw dictionary (no dictionary hash)"
    notok "dcz: repeated request reused one prebuilt CDict (no dictionary hash)"
fi

# error log carries no crit/alert/emerg: this scenario injects no faults.
if grep -qE '\[(crit|alert|emerg)\]' "$ELOG" 2>/dev/null; then
    diag "$(grep -E '\[(crit|alert|emerg)\]' "$ELOG" | head -3)"
    notok "error log carries no crit/alert/emerg lines"
else
    ok "error log carries no crit/alert/emerg lines"
fi

exit "$FAILED"
