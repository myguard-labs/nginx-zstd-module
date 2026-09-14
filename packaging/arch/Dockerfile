# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

# Base images are pinned; pacman intentionally tracks the live Arch repositories.
# The PKGBUILD's exact nginx dependency fails closed when an ABI rebuild is due.
FROM archlinux:base-devel@sha256:61f7de2dd88cc4ba1fe36c24cfe1a503c3936984492d6405eeab013ce6ac68c5 AS build
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN pacman -Syu --noconfirm --needed nginx nginx-src namcap zstd \
    && pacman -Scc --noconfirm \
    && useradd --create-home --uid 1000 builder \
    && install -d -o builder -g builder /build

WORKDIR /build
COPY --chown=1000:1000 PKGBUILD .SRCINFO ./
USER 1000:1000

RUN diff -u .SRCINFO <(makepkg --printsrcinfo) \
    && makepkg --cleanbuild --clean --noconfirm \
    && namcap PKGBUILD nginx-mod-zstd-*.pkg.tar.zst

FROM scratch AS artifact
COPY --from=build /build/nginx-mod-zstd-*.pkg.tar.zst /

FROM archlinux:base@sha256:b944cc65c5f28665dfd5fdbf5ed2997c88f5bb4a0aefac7ee8a7ef01893e5ed9 AS test
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
HEALTHCHECK NONE

RUN pacman -Syu --noconfirm --needed curl diffutils nginx zstd \
    && pacman -Scc --noconfirm
COPY --from=build /build/nginx-mod-zstd-*.pkg.tar.zst /tmp/
RUN pacman -U --noconfirm /tmp/nginx-mod-zstd-*.pkg.tar.zst \
    && test -f /usr/lib/nginx/modules/ngx_http_zstd_filter_module.so \
    && test -f /usr/lib/nginx/modules/ngx_http_zstd_static_module.so \
    && sed -i '/^http {/a\    types_hash_max_size 4096;\n    gzip_vary on;\n    zstd on;\n    zstd_static on;' \
      /etc/nginx/nginx.conf \
    && head -c 4096 /dev/zero | tr '\0' A > /usr/share/nginx/html/zstd.txt \
    && printf 'uncompressed fallback\n' > /usr/share/nginx/html/static.txt \
    && printf 'served by zstd_static\n' > /tmp/static.expected \
    && zstd --quiet --force -o /usr/share/nginx/html/static.txt.zst \
      /tmp/static.expected \
    && nginx -t \
    && nginx \
    && curl --fail --silent --show-error --dump-header /tmp/headers \
      --compressed --output /tmp/zstd.txt --header 'Accept-Encoding: zstd' \
      http://127.0.0.1/zstd.txt \
    && grep -Fqi 'Content-Encoding: zstd' /tmp/headers \
    && cmp /usr/share/nginx/html/zstd.txt /tmp/zstd.txt \
    && curl --fail --silent --show-error --dump-header /tmp/static.headers \
      --compressed --output /tmp/static.txt --header 'Accept-Encoding: zstd' \
      http://127.0.0.1/static.txt \
    && grep -Fqi 'Content-Encoding: zstd' /tmp/static.headers \
    && cmp /tmp/static.expected /tmp/static.txt \
    && nginx -s stop \
    && rm -f /tmp/nginx-mod-zstd-*.pkg.tar.zst
