#!/usr/bin/env bash
# Pin the ZSTD_STATIC_LINKING_ONLY contract (the parent repo's #237/#250
# pair, taken to this module's shape): the define never rides CFLAGS, so
# the ONE accepted ZSTDLIB_STATIC_API import is ZSTD_getCParams — the
# level->cparams table the browser window cap needs, self-defined in its
# own TU (ngx_http_compression_zstd.c) with the ABI caveat stated there.
# Everything else must stay stable public API: the estimator family the
# parent forbids must never appear as a dynamic import.
#
# The target is whatever the build produced — the statically-added nginx
# binary (this CI) or a dynamic module .so. Both anti-vacuity directions
# are asserted: libzstd must be a DT_NEEDED and ZSTD_getCParams must be
# present, so an empty or wrongly-targeted scan cannot pass silently.
set -euo pipefail

target="${1:?usage: check_zstd_linkage.sh <nginx-binary-or-module.so>}"

if ! readelf -d "$target" | grep -Eq 'NEEDED.*libzstd'; then
	echo "FAIL: $target has no libzstd DT_NEEDED entry" >&2
	readelf -d "$target" | grep NEEDED >&2 || true
	exit 1
fi

imports="$(nm -D --undefined-only "$target" | awk '{print $NF}')"

if ! grep -qx ZSTD_getCParams <<<"$imports"; then
	echo "FAIL: $target does not import ZSTD_getCParams -- the scan is" \
		"not looking at the module's zstd linkage (wrong target?)" >&2
	exit 1
fi

for sym in ZSTD_createCCtxParams ZSTD_CCtxParams_setParameter \
	ZSTD_estimateCStreamSize_usingCCtxParams ZSTD_freeCCtxParams \
	ZSTD_estimateCCtxSize ZSTD_estimateCStreamSize; do
	if grep -qx "$sym" <<<"$imports"; then
		echo "FAIL: $target imports static-only libzstd symbol $sym" \
			"beyond the accepted ZSTD_getCParams" >&2
		exit 1
	fi
done

echo "OK: $target links libzstd dynamically; ZSTD_getCParams is the only" \
	"ZSTDLIB_STATIC_API import"
