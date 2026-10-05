#!/bin/bash
# Build ngx_brotli against a PGP-verified nginx source tree.
#
#   tools/ci-build.sh [mode] [version]
#     mode   : system (default) | bundled
#              system  — link the system libbrotli found via pkg-config
#                        (the filter/config system-first path)
#              bundled — cmake-build deps/brotli into deps/brotli/c/../out
#                        first, then link it (the fallback path)
#     version: nginx version, e.g. 1.31.3. Omit to resolve the current
#              mainline release from nginx.org.
#
# Built tree persists at .build/nginx-<version>/objs/ so a CI job can run
# tests against the binary after the script exits. NO_CACHE=1 forces a
# from-scratch rebuild.
#
# nginx tarballs are verified via PGP against the signer keys VENDORED in
# tools/keys/ (committed to this repo) — never fetched from nginx.org at
# build time, so an origin compromise cannot substitute tarball, signature
# and keys together. Same provenance model as nginx-zstd-module's
# tools/ci-build.sh, which this is adapted from.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(dirname "$SCRIPT_DIR")"

MODE="${1:-system}"
VERSION="${2:-}"

case "$MODE" in
    system | bundled) ;;
    *)
        echo "ERROR: unsupported mode: $MODE (want: system|bundled)" >&2
        exit 2
        ;;
esac

if [ -z "$VERSION" ]; then
    # Resolve the current mainline release; nginx.org only keeps the newest
    # mainline tarball, so a hardcoded version eventually 404s.
    VERSION="$(curl -fsSL https://nginx.org/en/download.html |
        grep -oP 'nginx-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.gz)' |
        sort -V | tail -1 || true)"
    if [ -z "$VERSION" ]; then
        echo "ERROR: could not resolve mainline nginx version from nginx.org" >&2
        exit 1
    fi
fi

KEYRING_DIR="$SCRIPT_DIR/keys"
ROOT="${BUILD_ROOT:-$MODULE_DIR/.build}"
NO_CACHE="${NO_CACHE:-0}"

DIR="nginx-${VERSION}"
URL="https://nginx.org/download/${DIR}.tar.gz"
SRCDIR="$ROOT/$DIR"
TARBALL="$ROOT/${DIR}.tar.gz"

echo "== ngx_brotli build: mode=$MODE nginx=$VERSION tree=$SRCDIR"

mkdir -p "$ROOT"

if [ "$NO_CACHE" = "1" ]; then
    # deps/brotli/out too (CodeRabbit on the graft): the bundled-mode
    # static lib is exactly what you are trying to rebuild when you
    # reach for NO_CACHE=1 on a bundled link failure
    rm -rf "$SRCDIR" "$TARBALL" "$MODULE_DIR/deps/brotli/out"
fi

if [ ! -f "$TARBALL" ]; then
    wget -q -O "$TARBALL" "$URL"
fi

# Verification always runs, cache hit or fresh download — a cached tarball
# is exactly as untrusted as a fresh one until re-checked.
if [ ! -f "${TARBALL}.asc" ]; then
    wget -q "${URL}.asc" -O "${TARBALL}.asc"
fi

gnupghome="$(mktemp -d)"
trap 'rm -rf "$gnupghome"' EXIT
export GNUPGHOME="$gnupghome"
chmod 700 "$gnupghome"
shopt -s nullglob
keyfiles=("$KEYRING_DIR"/*.key)
shopt -u nullglob
if [ ${#keyfiles[@]} -eq 0 ]; then
    echo "ERROR: no vendored keys found in $KEYRING_DIR" >&2
    rm -rf "$gnupghome" "$TARBALL" "${TARBALL}.asc"
    exit 1
fi
for keyfile in "${keyfiles[@]}"; do
    # LOUD on failure (CodeRabbit on the graft): a corrupt vendored key
    # is a supply-chain trust-root problem and must not die silently
    # under set -e with its diagnostics eaten
    gpg --import "$keyfile" || {
        echo "ERROR: importing $keyfile failed" >&2
        exit 1
    }
done

# The keyring directory alone is not the trust root: every file in it
# is imported, so a key added there (or swapped for another) would be
# trusted by the verify below without anyone having decided to trust
# it. The PRIMARY-key fingerprint that made the signature must also be
# one of these, the nginx release signers as vendored in tools/keys/
# (arut, maxim, the three nginx signing keys, pluknet, sb, thresh).
# Adding a signer is two deliberate edits: the key file and this list.
NGINX_SIGNER_FPRS="
43387825DDB1BB97EC36BA5D007C8D7C15D87369
41DB92713D3BF4BFF3EE91069C5E7FA2F54977D4
8540A6F18833A80E9C1653A42FD21310B49F6B46
573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62
9E9BE90EACBCDE69FE9B204CBCDCD8A38D88A2B3
D6786CE303D9A9022998DC6CC8464D549AF75C0A
7338973069ED3F443F4D37DFA64FD5B17ADB39A8
13C82A63B603576156E30A4EA0EA981B66B0D967
"

if gpg_status="$(gpg --quiet --status-fd 1 --verify \
                     "${TARBALL}.asc" "$TARBALL" 2>/dev/null)"; then
    # VALIDSIG's last field is the primary key's fingerprint, also when
    # a signing subkey made the signature
    signer="$(printf '%s\n' "$gpg_status" |
        awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $NF; exit }')"
    if [ -z "$signer" ] ||
        ! printf '%s\n' "$NGINX_SIGNER_FPRS" | grep -Fxq "$signer"; then
        echo "ERROR: ${DIR}.tar.gz is signed, but not by a pinned nginx" \
             "release key" >&2
        printf '%s\n' "$gpg_status" | grep -E 'VALIDSIG|GOODSIG' >&2 || true
        rm -rf "$gnupghome" "$TARBALL" "${TARBALL}.asc"
        exit 1
    fi
    echo "== PGP signature verified for ${DIR}.tar.gz (signer $signer)"
else
    echo "ERROR: PGP signature verification FAILED for ${DIR}.tar.gz" >&2
    rm -rf "$gnupghome" "$TARBALL" "${TARBALL}.asc"
    exit 1
fi
rm -rf "$gnupghome"
unset GNUPGHOME

if [ ! -d "$SRCDIR" ]; then
    tar -xzf "$TARBALL" -C "$ROOT"
fi

# The deps/brotli pin is google/brotli's v1.2.0 RELEASE commit, and must
# stay a release: a gitlink is an opaque SHA, so this assertion is what
# turns "happens to be the release" into "cannot silently drift to an
# arbitrary master commit". Bumping to a NEW release means updating BOTH
# the gitlink and this pair, in one deliberate commit.
BROTLI_PIN_TAG="v1.2.0"
BROTLI_PIN_SHA="028fb5a23661f123017c060daa546b55cf4bde29"

if [ "$MODE" = "bundled" ]; then
    # The bundled path expects prebuilt static libs in deps/brotli/c/../out
    # (filter/config links -L<out> -lbrotlienc -lbrotlicommon).
    if [ ! -f "$MODULE_DIR/deps/brotli/c/include/brotli/encode.h" ]; then
        echo "ERROR: bundled mode needs the submodule:" \
             "git submodule update --init" >&2
        exit 1
    fi

    have_sha="$(git -C "$MODULE_DIR/deps/brotli" rev-parse HEAD 2>/dev/null || true)"
    if [ "$have_sha" != "$BROTLI_PIN_SHA" ]; then
        echo "ERROR: deps/brotli is at ${have_sha:-<unreadable>}, expected" \
             "$BROTLI_PIN_SHA (the $BROTLI_PIN_TAG release commit)." \
             "If this is a deliberate release bump, update BROTLI_PIN_TAG/" \
             "BROTLI_PIN_SHA beside the gitlink in the same commit." >&2
        exit 1
    fi
    # tags may be absent on shallow submodule fetches; the describe is a
    # nicer confirmation when they are present, never a failure when not
    if tag="$(git -C "$MODULE_DIR/deps/brotli" describe --tags --exact-match 2>/dev/null)"; then
        echo "== deps/brotli pinned at release $tag ($BROTLI_PIN_SHA)"
    else
        echo "== deps/brotli pinned at $BROTLI_PIN_SHA ($BROTLI_PIN_TAG)"
    fi
    if [ ! -f "$MODULE_DIR/deps/brotli/out/libbrotlienc.a" ]; then
        cmake -S "$MODULE_DIR/deps/brotli" -B "$MODULE_DIR/deps/brotli/out" \
            -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
            -DBROTLI_BUILD_TOOLS=OFF > /dev/null
        cmake --build "$MODULE_DIR/deps/brotli/out" -j "$(nproc)" > /dev/null
    fi
    # Hide the system pkg-config module so filter/config's system-first
    # probe cannot short-circuit the path this mode exists to exercise.
    export PKG_CONFIG_LIBDIR=/nonexistent
else
    if ! pkg-config --exists libbrotlienc; then
        echo "ERROR: system mode needs libbrotli dev files" \
             "(pkg-config libbrotlienc)" >&2
        exit 1
    fi
    echo "== system libbrotlienc $(pkg-config --modversion libbrotlienc)"
fi

cd "$SRCDIR"

# NGX_BROTLI_SANITIZE=1 (CI only): build under ASan+UBSan, everything
# fatal. The zstd siblings' round-4 lesson: chain-state code deserves a
# sanitizer pass, and their job's first run caught real (upstream-nginx)
# UB. Both suites here run at warn log level, so nginx core's own
# debug-log UB sites (the nonnull-attribute family the in-flight nginx
# PRs #1671/#1672 and #1679-#1682 address) never execute — no check
# class needs disabling.
san_cc=""
san_ld=""
if [ "${NGX_BROTLI_SANITIZE:-0}" = "1" ]; then
    san_cc="--with-cc-opt=-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all"
    san_ld="--with-ld-opt=-fsanitize=address,undefined"
fi

./configure \
    --with-compat \
    --with-debug \
    --with-http_gzip_static_module \
    ${san_cc:+"$san_cc"} \
    ${san_ld:+"$san_ld"} \
    --add-module="$MODULE_DIR" > /dev/null

# quiet on success, the WHOLE tail on failure (CodeRabbit on the graft):
# tail -3 kept only the make trailer, never the diagnostic -- and this
# module links two different brotli sources across two build modes, so
# link errors are the expected failure class here
build_log="$(mktemp)"
if ! make -j"$(nproc)" > "$build_log" 2>&1; then
    tail -60 "$build_log"
    rm -f "$build_log"
    exit 1
fi
tail -3 "$build_log"
rm -f "$build_log"

test -f objs/nginx
./objs/nginx -V 2>&1
echo "BUILD_OK $SRCDIR/objs/nginx"
