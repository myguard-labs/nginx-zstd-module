#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)

# The advisory must be a real compiler decision, not parsed -E output.
grep -q 'ngx_feature="libzstd 1.5.6 or newer"' "$root/auto/zstd"
if grep -q -- '-x c -E -' "$root/auto/zstd"; then
	exit 1
fi

# Static OpenSSL integration is optional even when nginx requested OpenSSL:
# headers/functions must be compile-probed before the macro is defined.
grep -q 'ngx_feature="OpenSSL EVP SHA-256 headers"' "$root/filter/config"
grep -Fq 'ngx_feature_path="$CORE_INCS"' "$root/filter/config"
grep -q 'OPENSSL/.openssl/include' "$root/filter/config"
grep -Fq '${USE_OPENSSL:-NO}' "$root/filter/config"
if grep -Fq '[ "$USE_OPENSSL" = YES -a ' "$root/filter/config"; then
	exit 1
fi

# Exercise the authoritative reorder helper and its hard-failure control.
grep -Fq '. "$_ngx_zstd_root/filter/reorder-static.sh"' "$root/filter/config"
. "$root/filter/reorder-static.sh"
# Consumed by the sourced helper.
# shellcheck disable=SC2034
ngx_module_name=ngx_http_zstd_filter_module
# shellcheck disable=SC2034
next=ngx_http_gzip_filter_module
HTTP_FILTER_MODULES='ngx_http_gzip_filter_module ngx_http_range_header_filter_module'
ngx_http_zstd_reorder_static_filter
[ "$HTTP_FILTER_MODULES" = 'ngx_http_gzip_filter_module ngx_http_zstd_filter_module ngx_http_range_header_filter_module' ]

HTTP_FILTER_MODULES=ngx_http_range_header_filter_module
if ngx_http_zstd_reorder_static_filter >/dev/null 2>&1; then
	echo 'absent reorder anchor unexpectedly succeeded' >&2
	exit 1
fi

echo 'build config policy: PASS'
