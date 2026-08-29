/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit fixture for ngx_http_zstd_static_probe_frame().
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef unsigned char  u_char;

#define ngx_memcpy  memcpy

#define ZSTD_MAGICNUMBER              0xFD2FB528U
#define ZSTD_MAGIC_SKIPPABLE_START    0x184D2A50U
#define ZSTD_MAGIC_SKIPPABLE_MASK     0xFFFFFFF0U

#define NGX_HTTP_ZSTD_STATIC_MAX_WINDOW  (8u * 1024u * 1024u)

#if defined(__has_include)
#if __has_include("generated_static_probe.inc")
#include "generated_static_probe.inc"
#else
#define NGX_HTTP_ZSTD_STATIC_FRAME_OK          0
#define NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG  3
#define NGX_HTTP_ZSTD_STATIC_FRAME_RESERVED    5
static ngx_int_t
ngx_http_zstd_static_probe_frame(const u_char *hdr, size_t n, uint64_t *window)
{
    (void) hdr;
    (void) n;
    (void) window;
    fprintf(stderr, "FAIL: generated_static_probe.inc is missing\n");
    return -1;
}
#endif
#else
#include "generated_static_probe.inc"
#endif

static int failures;

static void
check(const char *name, int cond, const char *what)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s: %s\n", name, what);
        failures++;
    }
}

static void
case_reserved_descriptor_bit(void)
{
    static const u_char hdr[] = {
        0x28, 0xB5, 0x2F, 0xFD, 0x08, 0x00, 0x00
    };
    uint64_t window = 0xdeadbeefU;
    ngx_int_t rc;

    rc = ngx_http_zstd_static_probe_frame(hdr, sizeof(hdr), &window);

    check("reserved-bit", rc == NGX_HTTP_ZSTD_STATIC_FRAME_RESERVED,
          "expected reserved descriptor verdict");
    check("reserved-bit", window == 0xdeadbeefU,
          "reserved verdict must not write the window out-param");
}

static void
case_valid_streaming_header(void)
{
    static const u_char hdr[] = {
        0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00
    };
    uint64_t window = 0;
    ngx_int_t rc;

    rc = ngx_http_zstd_static_probe_frame(hdr, sizeof(hdr), &window);

    check("valid-streaming", rc == NGX_HTTP_ZSTD_STATIC_FRAME_OK,
          "expected a small streaming frame header to pass");
}

static void
case_big_window_header(void)
{
    static const u_char hdr[] = {
        0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x88
    };
    uint64_t window = 0;
    ngx_int_t rc;

    rc = ngx_http_zstd_static_probe_frame(hdr, sizeof(hdr), &window);

    check("big-window", rc == NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG,
          "expected oversized-window verdict");
    check("big-window", window == 134217728U,
          "expected decoded 128 MiB window");
}

int
main(void)
{
    case_reserved_descriptor_bit();
    case_valid_streaming_header();
    case_big_window_header();

    if (failures) {
        return 1;
    }

    puts("OK: static probe frame unit");
    return 0;
}
