#!/bin/bash
# Build and test zstd-nginx-module against nginx or angie.
#
#   tools/ci-build.sh [flavor] [version]
#     flavor : nginx (default) | angie
#     version: source version, e.g. 1.31.2. Omit (or pass "" with flavor=nginx)
#              to resolve the current mainline release from nginx.org.
#
# Built tree persists at .build/<flavor>-<version>/objs/{<flavor>,ngx_http_zstd_*.so}
# so a caller (a CI job) can find the binary and both dynamic modules after
# the script exits — unlike the old single-nginx version of this script, which
# built under /tmp and deleted it on exit. NO_CACHE=1 forces a from-scratch
# rebuild of a given flavor/version pair.
#
# nginx tarballs are verified via PGP (nginx.org's own recommended method,
# https://nginx.org/en/pgp_keys.html) — no sha256sum file is published for
# them. angie.software does not publish a PGP signature for release tarballs,
# so angie tarballs are instead checked against a pinned sha256 recorded
# below, computed once from an HTTPS fetch (same approach the sibling
# nginx-skeleton-module repo uses for both flavors). A version not in the
# table still builds (this script tracks moving releases; refusing to build
# an unpinned version would break every future version bump until someone
# updates the table first) but prints a loud warning so the gap is visible.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(dirname "$SCRIPT_DIR")"

FLAVOR="${1:-nginx}"
VERSION="${2:-}"

case "$FLAVOR" in
    nginx|angie) ;;
    *)
        echo "ERROR: unsupported flavor: $FLAVOR (want: nginx|angie)" >&2
        exit 2
        ;;
esac

if [ -z "$VERSION" ]; then
    if [ "$FLAVOR" != "nginx" ]; then
        echo "ERROR: a version is required for flavor=$FLAVOR" >&2
        exit 2
    fi
    # Resolve the current mainline release; nginx.org only keeps the newest
    # mainline tarball, so a hardcoded version eventually 404s.
    VERSION="$(curl -fsSL https://nginx.org/en/download.html \
        | grep -oP 'nginx-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.gz)' \
        | sort -V | tail -1)"
    if [ -z "$VERSION" ]; then
        echo "ERROR: could not resolve mainline nginx version from nginx.org" >&2
        exit 1
    fi
fi

# --- pinned sha256 for angie tarballs we've actually verified ---
declare -A ANGIE_SHA256=(
    ["1.11.5"]="b5f297c6df2a74b9d0091a7cdd747fffd2d0e1d0be43632da61c1c7539db2043"
)

ROOT="${BUILD_ROOT:-$MODULE_DIR/.build}"
NO_CACHE="${NO_CACHE:-0}"
ZSTD_MODULE_DIR="$MODULE_DIR"

case "$FLAVOR" in
    nginx)
        DIR="nginx-${VERSION}"
        URL="https://nginx.org/download/${DIR}.tar.gz"
        ;;
    angie)
        DIR="angie-${VERSION}"
        URL="https://download.angie.software/files/${DIR}.tar.gz"
        ;;
esac

SRCDIR="$ROOT/${FLAVOR}-${VERSION}"
TARBALL="$ROOT/${DIR}.tar.gz"

echo "=========================================================================="
echo "  zstd-nginx-module CI Build"
echo "=========================================================================="
echo ""
echo "Module: $ZSTD_MODULE_DIR"
echo "Flavor: $FLAVOR  Version: $VERSION"
echo "Build tree: $SRCDIR"
echo ""

mkdir -p "$ROOT"

if [ "$NO_CACHE" = "1" ]; then
    rm -rf "$SRCDIR" "$TARBALL"
fi

echo "=========================================================================="
echo "Phase 1: Downloading $FLAVOR $VERSION"
echo "=========================================================================="
echo ""

if [ ! -f "$TARBALL" ]; then
    wget -q -O "$TARBALL" "$URL"
    echo "✓ Downloaded ${DIR}.tar.gz"

    if [ "$FLAVOR" = "nginx" ]; then
        # Always fetch over HTTPS and verify the detached PGP signature
        # against the nginx release-signing keys before unpacking. A plain
        # HTTP download lets a network attacker swap the source that we then
        # configure and compile.
        wget -q "${URL}.asc" -O "${TARBALL}.asc"

        gnupghome="$(mktemp -d)"
        export GNUPGHOME="$gnupghome"
        chmod 700 "$gnupghome"
        for key in nginx_signing mdounin maxim sb thresh pluknet arut; do
            wget -q "https://nginx.org/keys/${key}.key" -O - 2>/dev/null \
                | gpg --quiet --import 2>/dev/null || true
        done

        if gpg --quiet --verify "${TARBALL}.asc" "$TARBALL"; then
            echo "✓ PGP signature verified for ${DIR}.tar.gz"
        else
            echo "✗ PGP signature verification FAILED for ${DIR}.tar.gz" >&2
            rm -rf "$gnupghome" "$TARBALL" "${TARBALL}.asc"
            exit 1
        fi
        rm -rf "$gnupghome"
        unset GNUPGHOME
    else
        EXPECTED="${ANGIE_SHA256[$VERSION]:-}"
        if [ -n "$EXPECTED" ]; then
            ACTUAL="$(sha256sum "$TARBALL" | awk '{print $1}')"
            if [ "$ACTUAL" != "$EXPECTED" ]; then
                echo "✗ sha256 mismatch for ${DIR}.tar.gz" >&2
                echo "  expected: $EXPECTED" >&2
                echo "  actual:   $ACTUAL" >&2
                rm -f "$TARBALL"
                exit 1
            fi
            echo "✓ sha256 verified for ${DIR}.tar.gz"
        else
            echo "WARNING: no pinned sha256 for angie $VERSION -- add one to" \
                 "ANGIE_SHA256 in tools/ci-build.sh (downloaded tarball is" \
                 "UNVERIFIED)" >&2
        fi
    fi
else
    echo "✓ Using cached ${DIR}.tar.gz"
fi

if [ ! -d "$SRCDIR" ]; then
    tar -xzf "$TARBALL" -C "$ROOT"
    mv "$ROOT/$DIR" "$SRCDIR"
fi

cd "$SRCDIR"

echo ""
echo "=========================================================================="
echo "Phase 2: Configuring $FLAVOR with zstd module"
echo "=========================================================================="
echo ""

./configure \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/"$FLAVOR" \
    --with-http_ssl_module \
    --with-http_gzip_static_module \
    --with-http_realip_module \
    --with-http_v2_module \
    --add-dynamic-module="$ZSTD_MODULE_DIR" \
    2>&1 | tail -5

echo "✓ Configuration complete"

echo ""
echo "=========================================================================="
echo "Phase 3: Compiling $FLAVOR"
echo "=========================================================================="
echo ""

make -j"$(nproc)" 2>&1 | tail -10

echo ""
echo "=========================================================================="
echo "Phase 4: Verifying compiled modules"
echo "=========================================================================="
echo ""

if [ -f objs/ngx_http_zstd_filter_module.so ]; then
    echo "✓ Filter module compiled: objs/ngx_http_zstd_filter_module.so"
    file objs/ngx_http_zstd_filter_module.so
else
    echo "✗ Filter module NOT found!"
    exit 1
fi

if [ -f objs/ngx_http_zstd_static_module.so ]; then
    echo "✓ Static module compiled: objs/ngx_http_zstd_static_module.so"
    file objs/ngx_http_zstd_static_module.so
else
    echo "✗ Static module NOT found!"
    exit 1
fi

if [ ! -f "objs/$FLAVOR" ]; then
    echo "✗ $FLAVOR binary NOT found!"
    exit 1
fi

echo ""
echo "=========================================================================="
echo "✓ Build successful!"
echo "=========================================================================="
echo ""
echo "Server + modules ready in: $SRCDIR/objs/"
echo "  - $FLAVOR"
echo "  - ngx_http_zstd_filter_module.so"
echo "  - ngx_http_zstd_static_module.so"
