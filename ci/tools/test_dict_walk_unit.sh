#!/bin/bash
# Unit fixture for the strict-mode dictionary path walk,
# ngx_http_zstd_dict_file_open_strict() and its per-directory check, in
# src/ngx_http_zstd_dict_file.h -- THE authoritative copy, included
# directly. The four system calls the walk makes are function-like macros
# over scripted fakes in test_dict_walk_unit.c, so every exit is reached
# deterministically, including the ones no shell fixture can stage. No
# nginx tree, no zstd needed -- pure C, POSIX only.
set -euo pipefail

# ci/tools/ -> ci/ -> repo root.
cd "$(dirname "$0")/../.."

HDR="src/ngx_http_zstd_dict_file.h"
SRC="src/ngx_http_zstd_filter_module.c"
CC="${CC:-cc}"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/zstd-dict-walk-unit.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

for marker in 'ngx_http_zstd_dict_file_open_strict(ngx_str_t \*path, int flags,' \
    'ngx_http_zstd_dict_file_check_dir(int fd, ngx_http_zstd_dict_walk_t \*walk)' \
    'NGX_HTTP_ZSTD_DICT_WALK_DIR_WRITABLE' 'O_NOFOLLOW'; do
    if ! grep -q "$marker" "$HDR"; then
        echo "FAIL: $HDR lacks marker: $marker" >&2
        exit 1
    fi
done

# Production must route strict mode through the header's walk and must not
# open path components on its own: an openat() CALL anywhere in the module
# (an identifier as its first argument -- the diagnostics only ever spell
# it with a quote or an empty list) is the walk restored inside it.
if ! grep -q 'ngx_http_zstd_dict_file_open_strict(path, flags, &walk)' "$SRC"; then
    echo "FAIL: $SRC no longer routes strict mode through ngx_http_zstd_dict_file_open_strict()" >&2
    exit 1
fi
if grep -Eq 'openat\([A-Za-z_]' "$SRC"; then
    echo "FAIL: $SRC calls openat() on its own again; the walk belongs in $HDR" >&2
    exit 1
fi

# Every refusal the walk can report must have a message in the module's
# switch: a code added to the header without a case is a silent refusal.
for code in $(sed -n '/^typedef enum {$/,/^} ngx_http_zstd_dict_walk_rc_t;$/p' "$HDR" \
              | grep -o 'NGX_HTTP_ZSTD_DICT_WALK_[A-Z_]*' | sort -u); do
    if ! grep -q "case $code:" "$SRC"; then
        echo "FAIL: $SRC has no diagnostic for $code" >&2
        exit 1
    fi
done

"$CC" -std=gnu99 -Wall -Wextra -Werror -O1 -I ci/tools \
    -o "$OUT/test_dict_walk_unit" ci/tools/test_dict_walk_unit.c
"$OUT/test_dict_walk_unit"

echo "OK: dict walk unit fixture (against $HDR)"
