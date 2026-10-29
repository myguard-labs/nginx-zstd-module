# shellcheck shell=sh disable=SC2154
#
# Static-build anchor for the compression filter. Sourced by ../config
# after the parent's filter/reorder-static.sh, and exercised directly by
# tools/test_static_filter_order.sh, so the test evaluates this policy
# rather than a copy of it.
#
# HTTP_FILTER_MODULES lists modules in REGISTRATION order, and each filter
# prepends itself to the body chain when it registers -- so a module placed
# LATER in the list runs EARLIER in the chain. Two consequences decide the
# anchor:
#
#   - this filter must run after every content-transforming filter (SSI,
#     sub, addition, ...), which the parent's rule guarantees by anchoring
#     at gzip or later;
#   - it must run BEFORE any other compressor built alongside it. The first
#     filter to set Content-Encoding wins, and a unified module that elects
#     among zstd, br and gzip has to get that first shot over a standalone
#     zstd or brotli filter left in the build (a migration, or a packaging
#     slip) -- otherwise the standalone module compresses and this one
#     stands aside on the Content-Encoding it finds.
#
# So the anchor is the LAST compressor present: the parent's standalone
# zstd filter (which itself anchors after brotli), else the parent's own
# selector (brotli, then gzip, then pagespeed, then range-header). The
# gzip defer/veto contract is unaffected either way: gzip stays earlier in
# the list, so this filter always runs before it.
#
# Reads: $HTTP_FILTER_MODULES, $HTTP_GZIP. Echoes the chosen anchor.
ngx_http_compression_static_next() {
    if echo " $HTTP_FILTER_MODULES " | grep " ngx_http_zstd_filter_module " >/dev/null; then
        echo ngx_http_zstd_filter_module
    else
        ngx_http_zstd_static_next
    fi
}
