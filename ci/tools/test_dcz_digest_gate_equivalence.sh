#!/bin/sh
# Differential test for the Available-Dictionary framing-gate deduplication.
#
# ngx_http_zstd_dcz_negotiate() used to repeat the four-condition RFC 8941
# framing check that ngx_http_zstd_dcz_decode_digest() already performs. The
# duplicate gate was removed and the helper now distinguishes its two failure
# classes by return value (NGX_DECLINED framing / NGX_ERROR payload) so the
# caller can still emit two distinct diagnostics.
#
# This compares the OLD (duplicated-gate) and NEW (single-gate) decision
# functions over the boundary inputs the gate exists for, and asserts they
# agree on both the accept/reject verdict and which message is selected.
# Exit 0 = identical, non-zero = a behaviour difference.
set -eu
cd "$(dirname "$0")"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
${CC:-cc} -O2 -Wall -o "$out/t" test_dcz_digest_gate_equivalence.c
"$out/t"
