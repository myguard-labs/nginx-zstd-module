#!/usr/bin/env bash
#
# Unit fixture for the $compression_ratio split. The arithmetic is the
# parent's ngx_http_zstd_ratio_parts() in ../src/ngx_http_zstd_ratio.h,
# THE authoritative copy (upstream #310); the fixture includes that header
# directly, so there is no extracted or hand-copied duplicate here to
# drift from production. What is this module's own -- and what this script
# pins -- is that $compression_ratio routes through it: the check is bound
# to the variable HANDLER's body, not the whole file, so a helper call
# elsewhere plus inline arithmetic back in the handler still fails.
set -euo pipefail

cd "$(dirname "$0")/.."

HDR=../src/ngx_http_zstd_ratio.h
SRC=ngx_http_compression_module.c
CC="${CC:-cc}"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/compression-ratio-scaling-unit.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

for marker in 'ngx_http_zstd_ratio_parts(uint64_t bytes_in' \
    'remainder <= UINT64_MAX / 10'; do
    if ! grep -q "$marker" "$HDR"; then
        echo "FAIL: $HDR lacks marker: $marker" >&2
        exit 1
    fi
done

if ! grep -Fq '#include "../src/ngx_http_zstd_ratio.h"' "$SRC"; then
    echo "FAIL: $SRC no longer includes the shared ratio header" >&2
    exit 1
fi

handler_body() {
    sed -n '/^ngx_http_compression_ratio_variable(ngx_http_request_t \*r,$/,/^}/p' "$1"
}

assert_routes_through_helper() {
    local body
    body="$(handler_body "$1")"
    if [ -z "$body" ]; then
        echo "FAIL: could not cut ngx_http_compression_ratio_variable() out of $1" >&2
        return 1
    fi
    if ! printf '%s\n' "$body" |
        grep -q 'ngx_http_zstd_ratio_parts(ctx->bytes_in, ctx->bytes_out'; then
        echo "FAIL: \$compression_ratio no longer calls ngx_http_zstd_ratio_parts()" >&2
        return 1
    fi
    # Any multiply or divide on the byte counters inside the handler is
    # inline ratio arithmetic; the helper call carries neither operator and
    # the bytes_out == 0 guard is a comparison.
    if printf '%s\n' "$body" | grep -Eq 'bytes_(in|out)[^;]*[*/]|[*/][^;]*bytes_(in|out)'; then
        echo "FAIL: \$compression_ratio computes the ratio inline again" >&2
        return 1
    fi
}

assert_routes_through_helper "$SRC"

# Negative control: the old arithmetic back in the handler must go red.
sed 's|^    ngx_http_zstd_ratio_parts(ctx->bytes_in, ctx->bytes_out,$|    ratio_int = (ngx_uint_t) (ctx->bytes_in * 1000 / ctx->bytes_out / 1000);|' \
    "$SRC" >"$OUT/mutant.c"
if ! grep -q 'bytes_in \* 1000' "$OUT/mutant.c"; then
    echo "FAIL: mutant did not apply (handler call site moved?)" >&2
    exit 1
fi
if assert_routes_through_helper "$OUT/mutant.c" >/dev/null 2>&1; then
    echo "FAIL: inline-arithmetic mutant passed the routing check" >&2
    exit 1
fi

cp tools/test_ratio_scaling_unit.c "$OUT/"
"$CC" -std=gnu99 -O2 -Wall -Wextra -Werror -I"$(pwd)/tools" \
    -o "$OUT/test_ratio_scaling_unit" "$OUT/test_ratio_scaling_unit.c"
timeout 60s "$OUT/test_ratio_scaling_unit"
