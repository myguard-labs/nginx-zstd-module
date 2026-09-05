#!/bin/sh
# The static-build anchor policy, evaluated on the real selectors (the
# parent's filter/reorder-static.sh plus compression/auto/reorder.sh --
# the same files config sources), against every build shape that matters:
# which compressor this filter must land immediately after, and that the
# reorder then places it there. Registration order is chain order
# REVERSED, so "after X in the list" means "runs before X".
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)

. "$root/filter/reorder-static.sh"
. "$root/compression/auto/reorder.sh"

# Consumed by the sourced helpers.
# shellcheck disable=SC2034
ngx_module_name=ngx_http_compression_filter_module

expect_anchor() {
    want=$1
    got=`ngx_http_compression_static_next`
    if [ "$got" != "$want" ]; then
        echo "FAIL: anchor for [$HTTP_FILTER_MODULES] gzip=$HTTP_GZIP: got $got, want $want" >&2
        exit 1
    fi
}

expect_order() {
    next=`ngx_http_compression_static_next`
    ngx_http_zstd_reorder_static_filter
    case " $HTTP_FILTER_MODULES " in
        *" $next ngx_http_compression_filter_module "*) ;;
        *)
            echo "FAIL: reorder did not place the filter after $next: $HTTP_FILTER_MODULES" >&2
            exit 1
        ;;
    esac
}

# 1. Everything built: the standalone zstd filter is the last compressor
#    in the list (it anchors after brotli), so it is our anchor -- this
#    filter then runs before zstd, brotli and gzip.
HTTP_GZIP=YES
HTTP_FILTER_MODULES='ngx_http_gzip_filter_module ngx_http_brotli_filter_module ngx_http_zstd_filter_module ngx_http_range_header_filter_module'
expect_anchor ngx_http_zstd_filter_module
expect_order

# 2. Brotli and gzip, no standalone zstd: the parent's selector applies and
#    prefers brotli, so this filter runs before brotli (the case the review
#    on #117 flagged: anchoring at gzip here hands brotli the first shot).
HTTP_FILTER_MODULES='ngx_http_gzip_filter_module ngx_http_brotli_filter_module ngx_http_range_header_filter_module'
expect_anchor ngx_http_brotli_filter_module
expect_order

# 3. gzip only.
HTTP_FILTER_MODULES='ngx_http_gzip_filter_module ngx_http_range_header_filter_module'
expect_anchor ngx_http_gzip_filter_module
expect_order

# 4. No compressor at all (gzip-less build): range-header.
HTTP_GZIP=NO
HTTP_FILTER_MODULES='ngx_http_range_header_filter_module'
expect_anchor ngx_http_range_header_filter_module
expect_order

# 5. A name that merely CONTAINS the zstd filter's name must fool neither
#    the selector nor the reorder: the anchor stays gzip, the filter lands
#    directly after gzip, and the look-alike survives untouched.
HTTP_FILTER_MODULES='ngx_http_gzip_filter_module ngx_http_zstd_filter_module_extra ngx_http_range_header_filter_module'
HTTP_GZIP=YES
expect_anchor ngx_http_gzip_filter_module
expect_order
case " $HTTP_FILTER_MODULES " in
    *" ngx_http_zstd_filter_module_extra "*) ;;
    *)
        echo "FAIL: reorder mangled the look-alike module: $HTTP_FILTER_MODULES" >&2
        exit 1
    ;;
esac

# Fail-closed control: an absent anchor must stop the build.
HTTP_FILTER_MODULES='ngx_http_range_header_filter_module'
next=ngx_http_gzip_filter_module
if ngx_http_zstd_reorder_static_filter >/dev/null 2>&1; then
    echo 'FAIL: absent anchor unexpectedly reordered' >&2
    exit 1
fi

echo 'static filter order policy: PASS'
