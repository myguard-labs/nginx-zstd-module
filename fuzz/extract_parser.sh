#!/usr/bin/env bash
#
# Slice the verbatim bodies of the Accept-Encoding parser out of the
# shipped ../ngx_http_zstd_common.h into generated_parser.inc. That is
# both ngx_http_zstd_eval_qvalue() (the qvalue evaluator) and its caller
# ngx_http_zstd_accept_encoding(), in definition order so the .inc
# compiles standalone.
#
# This keeps the fuzz target locked to production code: there is no
# hand-maintained copy of the parser. If the function signature or body
# changes upstream, the next fuzz build picks it up automatically. If a
# function can no longer be found, we fail loudly rather than fuzz nothing.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEADER="$FUZZ_DIR/../ngx_http_zstd_common.h"
OUT="$FUZZ_DIR/generated_parser.inc"

if [ ! -f "$HEADER" ]; then
    echo "✗ cannot find $HEADER" >&2
    exit 1
fi

# Extract each function from its return-type line through the matching
# closing brace at column 0 (nginx style: definitions close with a bare
# `}` in col 1). Both target functions share the `static ngx_int_t`
# return-type line, so match on the following definition line. Capture
# them in source order (eval_qvalue precedes accept_encoding) so the
# generated .inc compiles without a forward declaration.
awk '
    /^static ngx_int_t$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_zstd_(eval_qvalue|accept_encoding)\(/ {
        capture = 1; pending = 0; print buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$HEADER" > "$OUT"

if ! grep -q 'ngx_http_zstd_eval_qvalue' "$OUT" \
   || ! grep -q 'ngx_http_zstd_accept_encoding' "$OUT" \
   || [ "$(tail -n1 "$OUT")" != "}" ]; then
    echo "✗ failed to extract the Accept-Encoding parser from $HEADER" >&2
    echo "  (header layout changed? update extract_parser.sh)" >&2
    rm -f "$OUT"
    exit 1
fi

LINES=$(wc -l < "$OUT")
echo "✓ extracted ngx_http_zstd_eval_qvalue() + ngx_http_zstd_accept_encoding()" \
     "— $LINES lines -> $OUT"
