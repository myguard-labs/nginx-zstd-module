#!/usr/bin/env bash
# Unit fixture for ngx_http_compression_static_dio_err_should_log()
# (parent #320, the directio hard-error log rate limit).
#
# The function is `static` inside compression/ngx_http_compression_static.c,
# so it is extracted verbatim by its signature (fails loudly if renamed or
# reshaped) together with the window constant, and compiled standalone
# against a fake clock (test_dio_err_ratelimit_unit.c). Nothing here is a
# hand-copied duplicate that could drift from the shipped function.
set -euo pipefail
cd "$(dirname "$0")/../.."

SRC="compression/ngx_http_compression_static.c"
CC="${CC:-cc}"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/compression-dio-ratelimit.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

SIG='ngx_http_compression_static_dio_err_should_log('
SIG_LINE="$(grep -n "^${SIG}" "$SRC" | head -1 | cut -d: -f1)"
if [ -z "$SIG_LINE" ]; then
    echo "FAIL: could not locate ${SIG}) in $SRC" >&2
    exit 1
fi
START_LINE=$((SIG_LINE - 1))
if ! sed -n "${START_LINE}p" "$SRC" | grep -q '^static ngx_uint_t$'; then
    echo "FAIL: line $START_LINE of $SRC is not the function's 'static ngx_uint_t' return line" >&2
    exit 1
fi
REL_END="$(tail -n "+${START_LINE}" "$SRC" | grep -n '^}' | head -1 | cut -d: -f1)"
END_LINE=$((START_LINE + REL_END - 1))
WINDOW_LINE="$(grep -n '^#define NGX_HTTP_COMPRESSION_STATIC_DIO_ERR_WINDOW' "$SRC" | head -1 | cut -d: -f1)"
if [ -z "$WINDOW_LINE" ]; then
    echo "FAIL: could not locate the window constant in $SRC" >&2
    exit 1
fi

{
    sed -n "${WINDOW_LINE}p" "$SRC"
    sed -n "${START_LINE},${END_LINE}p" "$SRC"
} | tr -d '\r' > "$OUT/dio_err_ratelimit.inc"

if ! grep -q 'smcf->dio_err_window_start' "$OUT/dio_err_ratelimit.inc" \
    || ! grep -q 'smcf->dio_err_suppressed' "$OUT/dio_err_ratelimit.inc"; then
    echo "FAIL: the extracted function no longer keeps its state in the main conf" >&2
    exit 1
fi

"$CC" -std=c99 -Wall -Wextra -Werror -I "$OUT" \
    -o "$OUT/unit" compression/tools/test_dio_err_ratelimit_unit.c
"$OUT/unit"
