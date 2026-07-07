#!/bin/bash
# Build and test zstd-nginx-module against nginx
# Usage: ./tools/ci-build.sh [nginx-version]
# Default: latest mainline, resolved from nginx.org (not pinned).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(dirname "$SCRIPT_DIR")"
if [ -n "${1:-}" ]; then
    NGINX_VERSION="$1"
else
    # Resolve the current mainline release; nginx.org only keeps the newest
    # mainline tarball, so a hardcoded version eventually 404s.
    NGINX_VERSION="$(curl -fsSL https://nginx.org/en/download.html \
        | grep -oP 'nginx-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.gz)' \
        | sort -V | tail -1)"
    if [ -z "$NGINX_VERSION" ]; then
        echo "ERROR: could not resolve mainline nginx version from nginx.org" >&2
        exit 1
    fi
fi
BUILD_DIR="/tmp/nginx-build-$$"
ZSTD_MODULE_DIR="$MODULE_DIR"

echo "=========================================================================="
echo "  zstd-nginx-module CI Build"
echo "=========================================================================="
echo ""
echo "Module: $ZSTD_MODULE_DIR"
echo "Nginx version: $NGINX_VERSION"
echo "Build directory: $BUILD_DIR"
echo ""

# Cleanup on exit
cleanup() {
    echo ""
    echo "Cleaning up..."
    rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Download nginx
echo "=========================================================================="
echo "Phase 1: Downloading nginx $NGINX_VERSION"
echo "=========================================================================="
echo ""

tarball="nginx-${NGINX_VERSION}.tar.gz"

# Always fetch over HTTPS and verify the detached PGP signature against the
# nginx release-signing keys before unpacking. A plain HTTP download lets a
# network attacker swap the source that we then configure and compile.
if [ ! -f "$tarball" ]; then
    wget -q "https://nginx.org/download/${tarball}"
    echo "✓ Downloaded ${tarball}"
else
    echo "✓ Using cached ${tarball}"
fi

# Detached signature.
wget -q "https://nginx.org/download/${tarball}.asc" -O "${tarball}.asc"

# nginx release-signing public keys (served over HTTPS by nginx.org). Import
# whichever exist so verification keeps working as the active signer rotates.
gnupghome="$(mktemp -d)"
export GNUPGHOME="$gnupghome"
chmod 700 "$gnupghome"
for key in nginx_signing mdounin maxim sb thresh pluknet arut; do
    wget -q "https://nginx.org/keys/${key}.key" -O - 2>/dev/null \
        | gpg --quiet --import 2>/dev/null || true
done

if gpg --quiet --verify "${tarball}.asc" "$tarball"; then
    echo "✓ PGP signature verified for ${tarball}"
else
    echo "✗ PGP signature verification FAILED for ${tarball}" >&2
    rm -rf "$gnupghome"
    exit 1
fi
rm -rf "$gnupghome"
unset GNUPGHOME

tar xzf "$tarball"
cd "nginx-${NGINX_VERSION}"

echo ""
echo "=========================================================================="
echo "Phase 2: Configuring nginx with zstd module"
echo "=========================================================================="
echo ""

./configure \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --with-http_ssl_module \
    --with-http_gzip_static_module \
    --with-http_realip_module \
    --with-http_v2_module \
    --add-dynamic-module="$ZSTD_MODULE_DIR" \
    2>&1 | tail -5

echo "✓ Configuration complete"

echo ""
echo "=========================================================================="
echo "Phase 3: Compiling nginx"
echo "=========================================================================="
echo ""

make -j$(nproc) 2>&1 | tail -10

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

echo ""
echo "=========================================================================="
echo "✓ Build successful!"
echo "=========================================================================="
echo ""
echo "Modules ready:"
echo "  - objs/ngx_http_zstd_filter_module.so"
echo "  - objs/ngx_http_zstd_static_module.so"
echo ""
echo "Build directory: $BUILD_DIR"
echo "(Will be cleaned up on exit)"
