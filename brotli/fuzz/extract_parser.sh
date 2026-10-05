#!/usr/bin/env bash
#
# Slice the verbatim bodies of the Accept-Encoding parser out of the
# shipped ../ngx_http_brotli_common.h into generated_parser.inc: the
# skip-quoted helper, the qvalue evaluator, the generic coding-weight
# walker and the br wrapper, in definition order so the .inc compiles
# standalone.
#
# This keeps the fuzz target locked to production code: there is no
# hand-maintained copy of the parser. If a function can no longer be
# found, fail loudly rather than fuzz nothing.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEADER="$FUZZ_DIR/../ngx_http_brotli_common.h"
OUT="$FUZZ_DIR/generated_parser.inc"

if [ ! -f "$HEADER" ]; then
    echo "✗ cannot find $HEADER" >&2
    exit 1
fi

# The leading sub() strips a CR so extraction also works from a Windows
# checkout smudged to CRLF (core.autocrlf=true): the `$0 == "}"`
# terminator and the anchored regexes below otherwise never match and
# the build fails with the "header layout changed?" error misleadingly.
awk '
    { sub(/\r$/, "") }
    /^static (ngx_inline )?(ngx_int_t|u_char \*)$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_brotli_(skip_quoted|eval_qvalue|coding_weight_ex|coding_weight|accept_encoding)\(/ {
        capture = 1; pending = 0; print buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$HEADER" >"$OUT"

if ! grep -q 'ngx_http_brotli_skip_quoted' "$OUT" ||
    ! grep -q 'ngx_http_brotli_eval_qvalue' "$OUT" ||
    ! grep -Eq '^ngx_http_brotli_coding_weight_ex\(' "$OUT" ||
    ! grep -Eq '^ngx_http_brotli_coding_weight\(' "$OUT" ||
    ! grep -q 'ngx_http_brotli_accept_encoding' "$OUT" ||
    [ "$(tail -n1 "$OUT")" != "}" ]; then
    echo "✗ failed to extract the Accept-Encoding parser from $HEADER" >&2
    echo "  (header layout changed? update extract_parser.sh)" >&2
    rm -f "$OUT"
    exit 1
fi

LINES=$(wc -l <"$OUT")
echo "✓ extracted ngx_http_brotli_skip_quoted() + ngx_http_brotli_eval_qvalue()" \
    "+ ngx_http_brotli_coding_weight_ex() + ngx_http_brotli_coding_weight()" \
    "+ ngx_http_brotli_accept_encoding()" \
    "— $LINES lines -> $OUT"
