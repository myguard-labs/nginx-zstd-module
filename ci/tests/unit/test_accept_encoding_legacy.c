/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * nginx 1.22.1-shaped regression checks.  Its ngx_table_elt_t has no next
 * member; repeated request headers remain in headers_in.headers. */
#include "../../fuzz/ngx_shim.h"
#include "../../fuzz/generated_parser.inc"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void
check(int ok, const char *what)
{
    checks++;
    if (ok) {
        printf("ok   %s\n", what);
    } else {
        printf("FAIL %s\n", what);
        failures++;
    }
}

static ngx_int_t
request_decide(const char *first, const char *second)
{
    ngx_table_elt_t    headers[2];
    ngx_http_request_t r;

    memset(&r, 0, sizeof(r));
    memset(headers, 0, sizeof(headers));
    headers[0].key.data = (u_char *) "Accept-Encoding";
    headers[0].key.len = sizeof("Accept-Encoding") - 1;
    headers[0].value.data = (u_char *) first;
    headers[0].value.len = strlen(first);
    headers[1].key.data = (u_char *) "Accept-Encoding";
    headers[1].key.len = sizeof("Accept-Encoding") - 1;
    headers[1].value.data = (u_char *) second;
    headers[1].value.len = strlen(second);
    r.main = &r;
    r.headers_in.accept_encoding = &headers[0];
    r.headers_in.headers.part.elts = headers;
    r.headers_in.headers.part.nelts = 2;

    return ngx_http_zstd_accepts(&r);
}

int
main(void)
{
    check(request_decide("gzip", "zstd") == NGX_OK,
          "legacy list: gzip then zstd accepts");
    check(request_decide("*", "zstd;q=0") == NGX_DECLINED,
          "legacy list: explicit zstd;q=0 overrides wildcard");

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
