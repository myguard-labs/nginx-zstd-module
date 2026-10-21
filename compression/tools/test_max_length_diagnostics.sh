#!/usr/bin/env bash
# Pin distinct, truthful diagnostics for the running compression_max_length
# abort (the parent's #283 shape): a declared length the stream overran
# must be named as such, with the byte count reached and the pledge, and
# the chunked/unknown case must not borrow that wording. The refusal
# itself needs a misdeclaring or chunked upstream that no fixture here can
# stage deterministically, so this is a source contract with a mutant
# control -- the same shape the parent uses.
set -euo pipefail

cd "$(dirname "$0")/.."

src=ngx_http_compression_module.c

assert_contract() {
    local file=$1
    grep -Fq 'if (ctx->pledged_size >= 0) {' "$file" || return 1
    grep -Fq '"%uL bytes on a response with "' "$file" || return 1
    grep -Fq '"declared Content-Length %O; "' "$file" || return 1
    grep -Fq '"%uL bytes on a response with no "' "$file" || return 1
    grep -Fq 'ctx->bytes_in, ctx->pledged_size);' "$file" || return 1
    grep -Fq 'ctx->pledged_size = r->headers_out.content_length_n;' "$file" \
        || return 1
}

assert_contract "$src"

work=$(mktemp -d "${TMPDIR:-/tmp}/compression-max-length-diag.XXXXXX")
trap 'rm -rf "$work"' EXIT
cp "$src" "$work/module.c"
sed -i 's/"declared Content-Length %O; "/"no Content-Length; "/' "$work/module.c"
if assert_contract "$work/module.c" >/dev/null 2>&1; then
    echo 'FAIL: lying-known-length diagnostic mutant did not make the contract red' >&2
    exit 1
fi

echo 'OK: known/unknown max-length abort diagnostics and negative control'
