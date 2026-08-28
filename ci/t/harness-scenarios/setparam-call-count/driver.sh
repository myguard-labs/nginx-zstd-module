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
#   /cdict/  trained CDict (zlcf->dict, refCDict): compressionLevel and
#            windowLog are in zstd.h's refCDict-superseded "compression
#            parameters" block, so init_cctx now skips setting them --
#            only enableLongDistanceMatching remains -> 1 call.
#   /dcz/    negotiated raw prefix (ctx->dcz_dict, refPrefix): refPrefix
#            does NOT override sticky parameters, so level, windowLog
#            (the dcz-aware value, set once, not twice), LDM and
#            checksumFlag(dcz) all apply -> 4 calls.
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
printf 'the quick brown fox jumps over the lazy dog, dictionary setparam count fixture\n' \
    >"$WWW/index.html"

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

echo "1..7"

# /cdict/: no dcz negotiation header, so init_cctx takes the zlcf->dict
# branch. level and windowLog superseded-by-cdict -> only LDM is set.
measure "cdict" "/cdict/index.html" "zstd" 1

if [ -n "$DICT_SHA_B64" ]; then
    measure "dcz" "/dcz/index.html" "dcz" 4 \
        "Accept-Encoding: zstd, dcz" \
        "Available-Dictionary: :$DICT_SHA_B64:"
else
    # NOT a SKIP -- see codec-call-count/driver.sh's identical reasoning:
    # openssl(1) is a hard requires-gate, so reaching here means the hash
    # derivation failed for some other reason (unreadable/truncated
    # dictionary), and a SKIP would read as a pass to anything grepping
    # for the oracle.
    notok "dcz: response carried Content-Encoding: dcz (could not derive the dictionary hash from $DICT_FILE)"
    notok "dcz: response decodes byte-for-byte to the origin (no dictionary hash)"
    notok "dcz: setParameter call count is 4 (no dictionary hash)"
fi

# error log carries no crit/alert/emerg: this scenario injects no faults.
if grep -qE '\[(crit|alert|emerg)\]' "$ELOG" 2>/dev/null; then
    diag "$(grep -E '\[(crit|alert|emerg)\]' "$ELOG" | head -3)"
    notok "error log carries no crit/alert/emerg lines"
else
    ok "error log carries no crit/alert/emerg lines"
fi

exit "$FAILED"
