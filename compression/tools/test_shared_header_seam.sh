#!/bin/sh
# The compression side of the #270 seam: production consumes the parent's
# authoritative headers and carries NO copy of what they define. The
# parent's ci/tools/test_probe_header_seam.sh guards src/filter/static/ci;
# this module's sources are the consumer tree it does not scan, and a
# transplant creeping back here is exactly the drift the headers exist to
# end.
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
comp="$root/compression"

# production includes
grep -Fq '#include "../src/ngx_http_zstd_frame_probe.h"' \
    "$comp/ngx_http_compression_static.c"
grep -Fq '#include "../src/ngx_http_zstd_cache_control.h"' \
    "$comp/ngx_http_compression_module.c"
grep -Fq '#include "../src/ngx_http_zstd_ratio.h"' \
    "$comp/ngx_http_compression_module.c"

# no local definition (column-0 name followed by "(") of anything the
# headers define -- under the parent's names OR this module's old ones
count_defs() {
    grep -r -n -h "^$1(" "$2" | grep -c . || true
}

for fn in ngx_http_zstd_static_probe_frame ngx_http_zstd_static_probe_reuse \
    ngx_http_zstd_cache_control_directive_end \
    ngx_http_zstd_cache_control_value_no_transform \
    ngx_http_zstd_cache_control_no_transform \
    ngx_http_zstd_ratio_parts \
    ngx_http_compression_static_probe_frame \
    ngx_http_compression_static_probe_reuse \
    ngx_http_compression_cc_value_no_transform \
    ngx_http_compression_no_transform \
    ngx_http_compression_ratio_parts; do
    n=$(count_defs "$fn" "$comp")
    if [ "$n" -ne 0 ]; then
        echo "shared-header seam: $fn is defined $n time(s) under compression/" >&2
        exit 1
    fi
done

# Detection control: a header copied back under compression/ must be caught.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/compression"
cp "$comp"/*.c "$comp"/*.h "$tmp/compression/"
cp "$root/src/ngx_http_zstd_ratio.h" "$tmp/compression/ratio_copy.h"
n=$(count_defs ngx_http_zstd_ratio_parts "$tmp/compression")
if [ "$n" -ne 1 ]; then
    echo "shared-header seam: detection control missed a copied header ($n)" >&2
    exit 1
fi

echo 'shared-header seam: PASS'
