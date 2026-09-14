# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

# Base images are pinned; pacman intentionally tracks the live Arch repositories.
# The PKGBUILD's exact nginx dependency fails closed when an ABI rebuild is due.
FROM archlinux:base-devel@sha256:61f7de2dd88cc4ba1fe36c24cfe1a503c3936984492d6405eeab013ce6ac68c5 AS toolchain
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN pacman -Syu --noconfirm --needed nginx nginx-src namcap zstd \
    && pacman -Scc --noconfirm \
    && useradd --create-home --uid 1000 builder \
    && install -d -o builder -g builder /build

USER 1000:1000

FROM toolchain AS build
WORKDIR /build
COPY --chown=1000:1000 PKGBUILD .SRCINFO ./

RUN diff -u .SRCINFO <(makepkg --printsrcinfo) \
    && makepkg --cleanbuild --clean --noconfirm \
    && namcap PKGBUILD nginx-mod-zstd-*.pkg.tar.zst

FROM toolchain AS checkout-build
WORKDIR /home/builder/module
RUN --mount=type=bind,from=checkout,source=.,target=/checkout \
    cp -a /checkout/config /checkout/LICENSE /checkout/auto /checkout/filter \
      /checkout/src /checkout/static .
WORKDIR /home/builder/build
RUN ln -sf /usr/src/nginx/auto . \
    && ln -sf /usr/src/nginx/src . \
    && /usr/src/nginx/configure \
      --with-ld-opt="$LDFLAGS" \
      --with-compat \
      --add-dynamic-module=/home/builder/module \
    && make modules

FROM scratch AS artifact
COPY --from=build /build/nginx-mod-zstd-*.pkg.tar.zst /

FROM archlinux:base@sha256:b944cc65c5f28665dfd5fdbf5ed2997c88f5bb4a0aefac7ee8a7ef01893e5ed9 AS runtime
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
HEALTHCHECK NONE

RUN pacman -Syu --noconfirm --needed curl diffutils nginx zstd \
    && pacman -Scc --noconfirm
COPY smoke-test.sh /usr/local/bin/nginx-zstd-smoke-test

FROM runtime AS release-test
COPY --from=build /build/nginx-mod-zstd-*.pkg.tar.zst /tmp/
RUN pacman -U --noconfirm /tmp/nginx-mod-zstd-*.pkg.tar.zst \
    && nginx-zstd-smoke-test \
    && touch /release-test-passed \
    && rm -f /tmp/nginx-mod-zstd-*.pkg.tar.zst

FROM runtime AS checkout-test
COPY --from=checkout-build /home/builder/build/objs/ngx_http_zstd_filter_module.so /usr/lib/nginx/modules/
COPY --from=checkout-build /home/builder/build/objs/ngx_http_zstd_static_module.so /usr/lib/nginx/modules/
RUN printf '%s\n' \
      'load_module "/usr/lib/nginx/modules/ngx_http_zstd_filter_module.so";' \
      'load_module "/usr/lib/nginx/modules/ngx_http_zstd_static_module.so";' \
      > /etc/nginx/modules.d/20-zstd.conf \
    && nginx-zstd-smoke-test \
    && touch /checkout-test-passed

FROM scratch AS test
COPY --from=release-test /release-test-passed /
COPY --from=checkout-test /checkout-test-passed /
