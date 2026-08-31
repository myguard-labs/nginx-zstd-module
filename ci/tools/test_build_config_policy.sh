#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)

# The advisory must be a real compiler decision, not parsed -E output.
grep -q 'ngx_feature="libzstd 1.5.6 or newer"' "$root/auto/zstd"
! grep -q -- '-x c -E -' "$root/auto/zstd"

# Static OpenSSL integration is optional even when nginx requested OpenSSL:
# headers/functions must be compile-probed before the macro is defined.
grep -q 'ngx_feature="OpenSSL EVP SHA-256 headers"' "$root/filter/config"
grep -q 'ngx_feature_path="$CORE_INCS"' "$root/filter/config"
grep -q 'OPENSSL/.openssl/include' "$root/filter/config"
grep -q '\${USE_OPENSSL:-NO}' "$root/filter/config"
! grep -q '\[ "$USE_OPENSSL" = YES -a ' "$root/filter/config"

# Exercise the reorder invariant and its hard-failure negative control.
reorder() {
    modules=$1
    name=ngx_http_zstd_filter_module
    next=ngx_http_gzip_filter_module
    case " $modules " in
        *" $next "*) ;;
        *) return 1 ;;
    esac
    modules=$(printf '%s\n' " $modules " \
        | sed "s/ $name / /" \
        | sed "s/ $next / $next $name /" \
        | sed 's/^ *//;s/ *$//')
    case " $modules " in
        *" $next $name "*) printf '%s\n' "$modules" ;;
        *) return 1 ;;
    esac
}

result=$(reorder 'ngx_http_gzip_filter_module ngx_http_range_header_filter_module')
[ "$result" = 'ngx_http_gzip_filter_module ngx_http_zstd_filter_module ngx_http_range_header_filter_module' ]
if reorder 'ngx_http_range_header_filter_module' >/dev/null 2>&1; then
    echo 'absent reorder anchor unexpectedly succeeded' >&2
    exit 1
fi

echo 'build config policy: PASS'
