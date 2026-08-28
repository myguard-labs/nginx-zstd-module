#!/usr/bin/env bash
#
# Scenario: ZSTD_CCtx_setParameter() CALL COUNT, NO-DICTIONARY MODE.
#
# Pins the per-mode instrumentation this item's done criterion asks for. The
# no-dict mode takes NEITHER the zlcf->dict (CDict) NOR the ctx->dcz_dict
# (raw prefix) branch in ngx_http_zstd_filter_init_cctx(), so every
# parameter the location configures is a live CCtx parameter and none of
# them is superseded-by-cdict: level, windowLog, and (with zstd_long on)
# enableLongDistanceMatching are all genuinely applied -> 3 calls.
#
# This is the reference count the dictionary-mode oracles in the sibling
# setparam-call-count scenario are measured AGAINST: level and windowLog
# drop out under a trained CDict specifically because refCDict supersedes
# them (zstd.h), and this arm is what proves they were being set at all
# when nothing supersedes them.
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
mkdir -p "$WWW"
printf 'the quick brown fox jumps over the lazy dog, nodict setparam count fixture\n' \
    >"$WWW/index.html"

reset_counter() {
    curl -fsS --max-time 5 "http://$HOST:$PORT/__probe?setparam_reset=1" \
        -o /dev/null
}

read_counter() {
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    prober_probe_field "$body" "setparam_calls" || return 1
}

echo "1..3"

if ! reset_counter; then
    notok "reset: probe did not answer setparam_reset"
    notok "response decodes byte-for-byte to the origin"
    notok "setParameter call count is 3"
    exit 1
fi

RAW="$PROBER_PREFIX/tmp"
mkdir -p "$RAW"
HDRS="$RAW/nodict.hdrs"
BODY="$RAW/nodict.bin"

if curl -sS --max-time 15 -D "$HDRS" -o "$BODY" \
        -H 'Accept-Encoding: zstd' \
        "http://$HOST:$PORT/index.html" 2>"$RAW/nodict.err"; then
    ok "request succeeded"
else
    notok "request succeeded"
    diag "curl stderr: $(cat "$RAW/nodict.err" 2>/dev/null || true)"
fi

if grep -qi '^content-encoding:[[:space:]]*zstd' "$HDRS" 2>/dev/null; then
    :
else
    diag "headers: $(tr -d '\r' <"$HDRS" 2>/dev/null | tr '\n' ' ')"
fi

if zstd -d -q -f -o "$BODY.dec" "$BODY" 2>/dev/null \
   && cmp -s "$BODY.dec" "$WWW/index.html"; then
    ok "response decodes byte-for-byte to the origin"
else
    notok "response decodes byte-for-byte to the origin"
fi

GOT="$(read_counter || echo -1)"
if [ "$GOT" -eq 3 ]; then
    ok "setParameter call count is 3 (level, windowLog, LDM -- none superseded)"
else
    diag "setparam_calls=$GOT expected=3"
    notok "setParameter call count is 3 (got $GOT)"
fi

if grep -qE '\[(crit|alert|emerg)\]' "$ELOG" 2>/dev/null; then
    diag "$(grep -E '\[(crit|alert|emerg)\]' "$ELOG" | head -3)"
fi

exit "$FAILED"
