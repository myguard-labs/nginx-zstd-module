#!/bin/bash
#
# Windows/MSVC build of nginx with the zstd module pair, and optionally
# ngx_brotli and headers-more. Produces a static nginx.exe comparable to
# the nginx.org Windows binary, plus the modules.
#
# Prerequisites:
#   1. Visual Studio (or Build Tools) with the C++ workload.
#   2. MSYS2 (https://www.msys2.org/), with git and cmake available in
#      the shell (pacman -S git mingw-w64-x86_64-cmake).
#   3. Strawberry Perl (https://strawberryperl.com/). OpenSSL's Windows
#      build requires a NATIVE perl; the MSYS perl generates paths the
#      MSVC toolchain cannot use. Auto-detected below; override with
#      STRAWBERRY_PERL=/c/path/to/perl/bin if installed elsewhere.
#
# Launching the build shell (the part every old guide gets wrong):
#   1. Open "x64 Native Tools Command Prompt for VS" (runs vcvars64,
#      which sets PATH/INCLUDE/LIB/LIBPATH for cl and link).
#   2. From THAT prompt, start MSYS2 inheriting the environment:
#         set MSYS2_PATH_TYPE=inherit
#         C:\msys64\msys2_shell.cmd -mingw64 -use-full-path -here
#   3. cd to an empty BUILD WORKSPACE directory and run this script
#      from there (it may live anywhere — a repo checkout, a copy, a
#      curl); all sources and the build land in the workspace.
#
# Module toggles (env or edit here):
#   WITH_ZSTD=1 WITH_BROTLI=1 WITH_HEADERS_MORE=1 ./tools/build-windows.sh
#
# Every downloaded tarball is pinned by SHA-256; bumping a VER_* means
# updating its SHA_* alongside (sha256sum <tarball>).
#
# KNOW WHAT YOU ARE BUILDING — Windows nginx caveats (nginx.org's own
# position; this script does not change them):
#   * Effectively single-worker: the win32 event core services
#     connections from one worker via select() (hence the FD_SETSIZE
#     define below). This build is for a LOCAL DEV BOX, not production
#     traffic.
#   * No HTTP/3: deliberately absent from the configure list, not an
#     oversight — nginx's QUIC stack needs UDP capabilities the win32
#     event core does not provide.
#
# Running the result as a Windows service (optional): nginx.exe has no
# service mode of its own; a thin wrapper such as shawl
# (https://github.com/mtkennerly/shawl) works well. From an ADMIN shell:
#     shawl.exe add --name "Local Nginx" --no-log-cmd \
#         --cwd C:/path/to/nginx-1.x.x -- nginx.exe -c conf/nginx.conf
#     sc config "Local Nginx" start=auto
#     sc start  "Local Nginx"
# and to remove:  sc stop "Local Nginx" & sc delete "Local Nginx"

set -euo pipefail

### module toggles #####################################################
WITH_ZSTD=${WITH_ZSTD:-1}
WITH_BROTLI=${WITH_BROTLI:-1}
WITH_HEADERS_MORE=${WITH_HEADERS_MORE:-1}

### version + SHA-256 pins #############################################
VER_NGINX=1.31.3
SHA_NGINX=a7657c50811c2d92d9895395e8b873ef60398142c4db21eb647811c38f6dd525
VER_PCRE2=10.47
SHA_PCRE2=c08ae2388ef333e8403e670ad70c0a11f1eed021fd88308d7e02f596fcd9dc16
VER_OPENSSL=4.0.1
SHA_OPENSSL=2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09
VER_ZLIB=1.3.2
SHA_ZLIB=bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16
VER_NASM=3.02
SHA_NASM=f504227b2f529e658d41629075f0503b38d67d790af345f34eba4af60c6a5998
VER_ZSTD=1.5.7
SHA_ZSTD=eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3

# Module refs — pinned by full commit id like everything else, bumped
# deliberately (a floating branch here once handed a tester a module
# checkout without the MSVC support and a mysterious configure
# failure). Overridable so a fix branch can be tested before it lands:
#   REPO_ZSTD_MODULE=<fork url> REF_ZSTD_MODULE=<branch> (fresh clone
#   required when switching repos — the existing clone's origin wins).
# The zstd-module pin is the squash commit that brought the MSVC
# support this script depends on.
REPO_ZSTD_MODULE=${REPO_ZSTD_MODULE:-https://github.com/myguard-labs/nginx-zstd-module.git}
REF_ZSTD_MODULE=${REF_ZSTD_MODULE:-37cf9ac6b58284ae2da95620f4905930d1277b54}
REPO_BROTLI=${REPO_BROTLI:-https://github.com/mreiden/ngx_brotli.git}
REF_BROTLI=${REF_BROTLI:-a7705082d191df904f25fe82188c4dd87e16ff8d}
REPO_HEADERS_MORE=${REPO_HEADERS_MORE:-https://github.com/openresty/headers-more-nginx-module.git}
REF_HEADERS_MORE=${REF_HEADERS_MORE:-53b0d98d1d57033b90491fd6a3b485ca536edfa7}

########################################################################

# The build workspace is wherever the script is RUN from, not where it
# lives — so a repo checkout can drive a build elsewhere. Patches for
# the cloned modules are applied from the script's own patches/
# directory (bundled: the headers-more MSVC include-order fix, without
# which that module cannot build under the win32 precompiled header)
# and additionally from $DIR_PROJECT/patches/<clone-dir>/*.patch for
# local ones. A standalone copy of this script needs the bundled
# patches directory alongside it (or WITH_HEADERS_MORE=0).
DIR_PROJECT=$(pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# Download + verify + extract one pinned tarball. Extra args narrow
# the extraction to specific archive members.
fetch() { # url sha [paths...]
    local url=$1 sha=$2 file=${1##*/}
    shift 2
    [ -f "$file" ] || curl -fsSL -o "$file" "$url"
    echo "$sha  $file" | sha256sum -c - > /dev/null
    tar xzf "$file" "$@"
}

# Clone at a pinned ref, applying the script's bundled patches and any
# workspace-local ones from patches/<name>/*.patch, idempotently.
# Submodules are synced AFTER the switch so nested pins (e.g.
# ngx_brotli/deps/brotli) follow the checked-out module commit, not
# whatever the clone's default branch pinned.
clone_module() { # dest repo ref
    local dest=$1 repo=$2 ref=$3 p d
    [ -d "$dest" ] || git clone --recurse-submodules "$repo" "$dest"
    git -C "$dest" fetch --quiet origin 2>/dev/null || true
    git -C "$dest" switch --detach "$ref" 2>/dev/null \
        || git -C "$dest" switch "$ref"
    git -C "$dest" submodule sync --recursive --quiet 2>/dev/null || true
    git -C "$dest" submodule update --init --recursive
    for d in "$SCRIPT_DIR/patches/$dest" "$DIR_PROJECT/patches/$dest"; do
        for p in "$d"/*.patch; do
            [ -f "$p" ] || continue
            if git -C "$dest" apply --check "$p" 2>/dev/null; then
                git -C "$dest" apply "$p"
            elif ! git -C "$dest" apply --reverse --check "$p" 2>/dev/null; then
                echo "ERROR: $p neither applies nor is already applied" >&2
                exit 1
            fi
        done
    done
}

### toolchain sanity ###################################################
command -v cl > /dev/null 2>&1 || {
    echo "ERROR: cl not on PATH — launch from the VS Native Tools" \
         "prompt with MSYS2_PATH_TYPE=inherit (see header)" >&2
    exit 1
}

# OpenSSL needs a NATIVE perl (Strawberry); MSYS perl reports msys as
# its OS and emits paths cl cannot consume.
PERL_BIN=
for d in "${STRAWBERRY_PERL:-}" /c/Strawberry/perl/bin /c/strawberry/perl/bin; do
    [ -n "$d" ] && [ -x "$d/perl.exe" ] && { PERL_BIN=$d; break; }
done
if [ -z "$PERL_BIN" ] && command -v perl > /dev/null 2>&1 \
    && [ "$(perl -e 'print $^O')" = "MSWin32" ]; then
    PERL_BIN=$(dirname "$(command -v perl)")
fi
[ -n "$PERL_BIN" ] || {
    echo "ERROR: no native (Strawberry) perl found; install it or set" \
         "STRAWBERRY_PERL=/c/path/to/perl/bin" >&2
    exit 1
}

### sources ############################################################
[ -d "nginx-$VER_NGINX" ] \
    || fetch "https://nginx.org/download/nginx-$VER_NGINX.tar.gz" "$SHA_NGINX"

# nasm for OpenSSL's assembly (fast crypto; drop by adding no-asm to
# --with-openssl-opt below and deleting this block).
if [ ! -x "nasm-$VER_NASM/nasm" ] && [ ! -x "nasm-$VER_NASM/nasm.exe" ]; then
    fetch "https://www.nasm.us/pub/nasm/releasebuilds/$VER_NASM/nasm-$VER_NASM.tar.gz" "$SHA_NASM"
    ( cd "nasm-$VER_NASM" && ./configure > /dev/null && make -j"$(nproc)" )
fi

# libzstd, built static with the static CRT (nginx's cl build is /MT;
# CMake's default /MD would conflict at link). Extract only lib/ and
# build/: the tarball's tests/ tree contains symlinks MSYS tar cannot
# create, which would abort the whole extraction — and this build
# needs neither tests nor programs. Guarded on a marker file, not the
# directory, so a previously aborted extraction self-heals.
if [ "$WITH_ZSTD" = 1 ]; then
    if [ ! -f "zstd-$VER_ZSTD/build/cmake/CMakeLists.txt" ]; then
        fetch "https://github.com/facebook/zstd/releases/download/v$VER_ZSTD/zstd-$VER_ZSTD.tar.gz" "$SHA_ZSTD" \
            "zstd-$VER_ZSTD/lib" "zstd-$VER_ZSTD/build"
    fi
    if [ ! -f "zstd-$VER_ZSTD/out/lib/zstd_static.lib" ]; then
        cmake -B "zstd-$VER_ZSTD/out" -S "zstd-$VER_ZSTD/build/cmake" \
            -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release \
            -DZSTD_BUILD_SHARED=OFF -DZSTD_BUILD_PROGRAMS=OFF \
            -DZSTD_BUILD_TESTS=OFF -DZSTD_USE_STATIC_RUNTIME=ON
        cmake --build "zstd-$VER_ZSTD/out"
    fi
fi

cd "nginx-$VER_NGINX"
mkdir -p objs/lib
cd objs/lib

[ -d "pcre2-$VER_PCRE2" ] \
    || fetch "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$VER_PCRE2/pcre2-$VER_PCRE2.tar.gz" "$SHA_PCRE2"
[ -d "openssl-$VER_OPENSSL" ] \
    || fetch "https://github.com/openssl/openssl/releases/download/openssl-$VER_OPENSSL/openssl-$VER_OPENSSL.tar.gz" "$SHA_OPENSSL"
[ -d "zlib-$VER_ZLIB" ] \
    || fetch "https://zlib.net/zlib-$VER_ZLIB.tar.gz" "$SHA_ZLIB"

[ "$WITH_HEADERS_MORE" = 1 ] \
    && clone_module headers-more-nginx-module "$REPO_HEADERS_MORE" "$REF_HEADERS_MORE"
if [ "$WITH_BROTLI" = 1 ]; then
    clone_module ngx_brotli "$REPO_BROTLI" "$REF_BROTLI"
    if [ ! -d ngx_brotli/deps/brotli/out ]; then
        cmake -B ngx_brotli/deps/brotli/out -S ngx_brotli/deps/brotli \
            -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=OFF -DBROTLI_DISABLE_TESTS=ON \
            -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded
        cmake --build ngx_brotli/deps/brotli/out
    fi
fi
[ "$WITH_ZSTD" = 1 ] \
    && clone_module nginx-zstd-module "$REPO_ZSTD_MODULE" "$REF_ZSTD_MODULE"

cd ../..   # back to nginx-$VER_NGINX

# nasm first for OpenSSL; native perl next; then cl's own directory
# ahead of MSYS /usr/bin so MSVC's link.exe shadows coreutils' link
# (the classic silent breaker of OpenSSL/nginx Windows builds).
PATH="$DIR_PROJECT/nasm-$VER_NASM:$PERL_BIN:$(dirname "$(command -v cl)"):$PATH"

### configure ##########################################################
# Groups: paths/core; the modules the nginx.org Windows binary ships;
# the optional third-party modules per the toggles.
#
# --with-http_v3_module is deliberately NOT here: nginx's QUIC needs
# UDP support the win32 event core lacks (see header caveats).
configure_args=(
    --with-cc=cl
    --prefix=
    --conf-path=conf/nginx.conf
    --pid-path=logs/nginx.pid
    --http-log-path=logs/access.log
    --error-log-path=logs/error.log
    --sbin-path=nginx.exe
    --http-client-body-temp-path=temp/client_body_temp
    --http-proxy-temp-path=temp/proxy_temp
    --http-fastcgi-temp-path=temp/fastcgi_temp
    --http-scgi-temp-path=temp/scgi_temp
    --http-uwsgi-temp-path=temp/uwsgi_temp
    --with-cc-opt=-DFD_SETSIZE=1024
    # nginx.org's Windows binary ships with debug logging compiled in;
    # it costs a few hundred kB — the real size lever is the -opt:ref
    # dead-code elimination added below.
    --with-debug
    --with-pcre="objs/lib/pcre2-$VER_PCRE2"
    --with-zlib="objs/lib/zlib-$VER_ZLIB"
    --with-openssl="objs/lib/openssl-$VER_OPENSSL"
    --with-openssl-opt="no-shared no-module"
    --with-http_ssl_module
    --with-http_v2_module
    --with-http_auth_request_module

    --with-http_addition_module
    --with-http_dav_module
    --with-http_flv_module
    --with-http_gunzip_module
    --with-http_gzip_static_module
    --with-http_mp4_module
    --with-http_random_index_module
    --with-http_realip_module
    --with-http_secure_link_module
    --with-http_slice_module
    --with-http_sub_module
    --with-http_stub_status_module
    --with-mail
    --with-mail_ssl_module
    --with-stream
    --with-stream_ssl_module
)
[ "$WITH_HEADERS_MORE" = 1 ] \
    && configure_args+=( --add-module=objs/lib/headers-more-nginx-module )
[ "$WITH_BROTLI" = 1 ] \
    && configure_args+=( --add-module=objs/lib/ngx_brotli )
if [ "$WITH_ZSTD" = 1 ]; then
    configure_args+=( --add-module=objs/lib/nginx-zstd-module )
    export ZSTD_INC="$DIR_PROJECT/zstd-$VER_ZSTD/lib"
    export ZSTD_LIB="$DIR_PROJECT/zstd-$VER_ZSTD/out/lib"
fi

./configure "${configure_args[@]}"

# nginx's msvc makefile compiles with -WX (warnings as errors), which
# third-party module trees do not survive under -W4; strip it. Also let
# the linker drop unreferenced sections despite /DEBUG.
sed -i 's/ -WX//; s/-link -verbose:lib -debug/-link -verbose:lib -debug -opt:ref -opt:icf/' objs/Makefile
grep -q -- '-opt:ref' objs/Makefile || echo "WARN: link-opt sed did not match"

nmake

echo
echo "== built: $DIR_PROJECT/nginx-$VER_NGINX/objs/nginx.exe"
./objs/nginx.exe -V
