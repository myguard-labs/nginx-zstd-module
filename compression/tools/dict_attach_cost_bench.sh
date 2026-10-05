#!/usr/bin/env bash
#
# Build and run the per-request dictionary-attach cost microbenchmark
# (dict_attach_cost_bench.c). A measurement tool, not a test: it prints
# a table and exits 0 unless a build or a request fails. Both libraries
# must be discoverable through pkg-config; a missing one is a SKIP so a
# CI runner without brotli does not fail on a tool it cannot build.
set -euo pipefail

cd "$(dirname "$0")/.."

CC="${CC:-cc}"
SRC="tools/dict_attach_cost_bench.c"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/compression-dict-attach-bench.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

for lib in libzstd libbrotlienc; do
    if ! pkg-config --exists "$lib" 2>/dev/null; then
        echo "SKIP: $lib not found via pkg-config" >&2
        exit 0
    fi
done

read -r -a CFLAGS <<<"$(pkg-config --cflags libzstd libbrotlienc) -Wall -Wextra -O2"
read -r -a LIBS <<<"$(pkg-config --libs libzstd libbrotlienc)"

"$CC" "${CFLAGS[@]}" -o "$OUT/dict_attach_cost_bench" "$SRC" "${LIBS[@]}"
"$OUT/dict_attach_cost_bench"
