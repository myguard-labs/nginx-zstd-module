#!/bin/bash
# Repeatable level-3 dcz raw-prefix profile (A31-dcz-profile).
set -euo pipefail

cd "$(dirname "$0")/../.."

CC="${CC:-cc}"
SRC="ci/tools/dcz_refprefix_profile.c"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/zstd-dcz-refprefix-profile.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

if ! pkg-config --exists libzstd 2>/dev/null; then
    echo "SKIP: libzstd not found via pkg-config" >&2
    exit 0
fi

read -r -a CFLAGS <<<"$(pkg-config --cflags libzstd) -Wall -Wextra -Werror -O2"
read -r -a LIBS <<<"$(pkg-config --libs libzstd)"

"$CC" "${CFLAGS[@]}" -o "$OUT/dcz_refprefix_profile" "$SRC" "${LIBS[@]}"
"$OUT/dcz_refprefix_profile"
