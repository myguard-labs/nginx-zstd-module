#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Slice the verbatim body of the .zst frame-header probe out of the shipped
# ../../src/ngx_http_zstd_static_module.c into generated_static_probe.inc.
# That is ngx_http_zstd_static_probe_frame() -- the pure arithmetic half of
# the static module's serve-time frame check, which decides from the first
# bytes of a .zst file whether the leading frame may be served.
#
# Same contract as extract_parser.sh / extract_dcz.sh: this keeps the unit
# test locked to production code. There is no hand-maintained copy of the
# probe; if the function body changes upstream, the next unit-test build
# picks it up automatically. If the function can no longer be found, we fail
# loudly rather than test nothing.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$FUZZ_DIR/../../src/ngx_http_zstd_static_module.c"
OUT="$FUZZ_DIR/generated_static_probe.inc"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi

# Same extraction shape as extract_parser.sh: match the two-line
# `static ngx_int_t` / function-name declaration style, then capture
# through the matching closing brace at column 0. The leading sub()
# strips a CR for CRLF checkouts, same reason as extract_parser.sh.
awk '
    { sub(/\r$/, "") }
    /^static (ngx_int_t|u_char \*)$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_zstd_static_probe_frame\(/ {
        capture = 1; pending = 0; print buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$SRC" >"$OUT"

if ! grep -q 'ngx_http_zstd_static_probe_frame' "$OUT" ||
    [ "$(tail -n1 "$OUT")" != "}" ]; then
    echo "✗ failed to extract ngx_http_zstd_static_probe_frame() from $SRC" >&2
    echo "  (function signature/layout changed? update extract_static_probe.sh)" >&2
    rm -f "$OUT"
    exit 1
fi

LINES=$(wc -l <"$OUT")
echo "✓ extracted ngx_http_zstd_static_probe_frame() — $LINES lines -> $OUT"
