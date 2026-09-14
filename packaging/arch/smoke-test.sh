#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause

set -euo pipefail

work_dir=$(mktemp -d)
cleanup() {
    nginx -s stop >/dev/null 2>&1 || true
    rm -rf -- "${work_dir:?}"
}
trap cleanup EXIT

test -f /usr/lib/nginx/modules/ngx_http_zstd_filter_module.so
test -f /usr/lib/nginx/modules/ngx_http_zstd_static_module.so

sed -i '/^http {/a\    types_hash_max_size 4096;\n    gzip_vary on;\n    zstd on;\n    zstd_static on;' \
    /etc/nginx/nginx.conf
head -c 4096 /dev/zero | tr '\0' A >/usr/share/nginx/html/zstd.txt
printf 'uncompressed fallback\n' >/usr/share/nginx/html/static.txt
printf 'served by zstd_static\n' >"$work_dir/static.expected"
zstd --quiet --force -o /usr/share/nginx/html/static.txt.zst \
    "$work_dir/static.expected"

nginx -t
nginx

curl --connect-timeout 2 --max-time 10 --fail --silent --show-error \
    --dump-header "$work_dir/headers" \
    --compressed --output "$work_dir/zstd.txt" \
    --header 'Accept-Encoding: zstd' \
    http://127.0.0.1/zstd.txt
grep -Fqi 'Content-Encoding: zstd' "$work_dir/headers"
cmp /usr/share/nginx/html/zstd.txt "$work_dir/zstd.txt"

curl --connect-timeout 2 --max-time 10 --fail --silent --show-error \
    --dump-header "$work_dir/static.headers" \
    --compressed --output "$work_dir/static.txt" \
    --header 'Accept-Encoding: zstd' \
    http://127.0.0.1/static.txt
grep -Fqi 'Content-Encoding: zstd' "$work_dir/static.headers"
cmp "$work_dir/static.expected" "$work_dir/static.txt"

nginx -s stop
