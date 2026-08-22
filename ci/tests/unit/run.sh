#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/tests/unit/run.sh -- build and run the Accept-Encoding parser unit tests.
#
#   ci/tests/unit/run.sh            # regenerate the parser slice, build, run
#   ci/tests/unit/run.sh clean      # remove build products
#   COVERAGE=1 ci/tests/unit/run.sh # also instrument, so ci/tools/coverage.sh
#                                   # can gcov src/ afterwards
#
# Env:
#   CC   compiler (default cc). Takes a full driver line, so CC="gcc -m32"
#        runs the suite as a 32-bit binary.
#
# Exit: 0 all checks passed, 1 a check failed or the parser-extraction
# guard tripped.
#
# Runs in well under a second, needs no nginx build tree, no network and no
# root: unlike the skeleton's scan core, the Accept-Encoding parser is pure,
# self-contained ASCII walking (see the header comment atop
# src/ngx_http_zstd_common.h) that needs only ngx_strncasecmp() /
# ngx_strcasestrn(), which ci/fuzz/ngx_shim.h reproduces as faithful, cited
# copies of the upstream src/core/ngx_string.c implementations. There is
# therefore no dependency on ci/tools/nginx-tree.sh or a .build/ tree here --
# this layer is deliberately the cheapest one, so it is the one a derived
# change can afford to run on every save.
#
# WHAT IT DOES *NOT* DO: it does not re-implement the parser. This script
# runs ci/fuzz/extract_parser.sh first, exactly as the fuzz build does, so
# the tests always link the SHIPPED src/ngx_http_zstd_common.h -- never a
# hand-copied version that can drift from production.
#
# -Werror applies throughout: unlike the skeleton's scan-core layer, there is
# no upstream translation unit linked in here to exempt.
#
# See test_accept_encoding.c's header comment for the list of mutations this
# suite has been observed to catch (each named there, with the check that
# went red).

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
FUZZ_DIR="$ROOT/ci/fuzz"
BIN="$DIR/test_accept_encoding"

if [ "${1:-}" = "clean" ]; then
    rm -f "$BIN" "$DIR"/*.o "$DIR"/*.gcda "$DIR"/*.gcno
    echo "unit test binary removed"
    exit 0
fi

# Regenerate the extracted parser slice so this binary always links the
# shipped src/ngx_http_zstd_common.h, never a stale copy.
# test_accept_encoding.c includes ci/fuzz/ headers by RELATIVE path, so a static
# analyser invoked from anywhere parses it without -I flags. That is deliberate:
# an analyser that cannot resolve an include skips the whole TU and reports no
# findings, which is indistinguishable from a clean result.
bash "$FUZZ_DIR/extract_parser.sh"

CC="${CC:-cc}"

OWN_CFLAGS=(-g -O1 -Wall -Wextra -Wshadow -Werror)

if [ "${COVERAGE:-0}" = 1 ]; then
    OWN_CFLAGS+=(--coverage)
    LINK_EXTRA=(--coverage)
else
    LINK_EXTRA=()
fi

echo "==> Building $BIN with ${CC}"
# shellcheck disable=SC2086  # $CC may legitimately carry flags (e.g. "gcc -m32")
$CC "${OWN_CFLAGS[@]}" -I"$FUZZ_DIR" -c "$DIR/test_accept_encoding.c" \
    -o "$DIR/test_accept_encoding.o"
# shellcheck disable=SC2086
$CC "${LINK_EXTRA[@]}" -o "$BIN" "$DIR/test_accept_encoding.o"

echo "==> Running"
# Bounded: a regression in the quoted-string walk can hang the scanner outright
# (one of the documented mutations does exactly that). Without a local timeout
# the job burns its whole 15-minute budget and the log never says which layer
# failed.
timeout 60s "$BIN"
