#!/usr/bin/env bash
# Pin distinct, truthful diagnostics for the running brotli_max_length
# abort (the zstd siblings' #283 shape): a declared length the stream
# overran must be named as such, with the byte count reached and the
# pledge, and the chunked/unknown case must not borrow that wording. The
# refusal itself needs a misdeclaring or chunked upstream no fixture here
# stages deterministically, so this is a source contract with a mutant
# control -- the same shape the siblings use.
set -euo pipefail

cd "$(dirname "$0")/.."          # tools -> repo root

work=$(mktemp -d "${TMPDIR:-/tmp}/brotli-max-length-diag.XXXXXX")
trap 'rm -rf "$work"' EXIT

# CR-stripped copy (Windows working trees are CRLF; CI is LF).
src="$work/filter.c"
tr -d '\r' < filter/ngx_http_brotli_filter_module.c > "$src"

assert_contract() {
    local file=$1
    grep -Fq 'if (ctx->content_length >= 0) {' "$file" || return 1
    grep -Fq '"%uL bytes on a response with declared "' "$file" || return 1
    grep -Fq '"Content-Length %O; aborting to protect the "' "$file" || return 1
    grep -Fq '"%uL bytes on a response with no "' "$file" || return 1
    grep -Fq 'ctx->bytes_in, ctx->content_length);' "$file" || return 1
}

assert_contract "$src"

cp "$src" "$work/mutant.c"
sed -i 's/"%uL bytes on a response with declared "/"%uL bytes on a response with no "/' \
    "$work/mutant.c"
if assert_contract "$work/mutant.c" >/dev/null 2>&1; then
    echo 'FAIL: lying-known-length diagnostic mutant did not make the contract red' >&2
    exit 1
fi

echo 'OK: known/unknown max-length abort diagnostics and negative control'
