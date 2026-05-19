/*
 * Copyright (C) Alex Zhang
 *
 * Shared helpers used by both the filter module and the static module.
 * Included as a static inline header to avoid a separate compilation unit
 * while eliminating the duplication between the two modules.
 */

#ifndef NGX_HTTP_ZSTD_COMMON_H
#define NGX_HTTP_ZSTD_COMMON_H


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*
 * ngx_http_zstd_accept_encoding()
 *
 * Returns NGX_OK  if the Accept-Encoding value contains "zstd" with a
 * non-zero quality value (q > 0), NGX_DECLINED otherwise.
 *
 * Implements RFC 7231 §5.3.4 quality-value parsing:
 *   qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )
 */
/*
 * Evaluate the optional qvalue of a confirmed "zstd" coding token. `p`
 * points at the first byte after the token name (the ';' that starts
 * its parameters, or the element/list terminator). Returns NGX_OK if
 * acceptable (q > 0 or no q), NGX_DECLINED otherwise. Strictly bounded
 * by ae->len: every dereference is guarded against `end`, so it never
 * relies on NUL termination even if called with p == end.
 */
static ngx_int_t
ngx_http_zstd_eval_qvalue(ngx_str_t *ae, u_char *p)
{
    u_char  *end = ae->data + ae->len;

    /* No quality value present → accept */
    if (p >= end || *p != ';') {
        return NGX_OK;
    }

    p++;

    /* Skip whitespace */
    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }

    /* No q= parameter → accept (token present, default q=1) */
    if (!(p + 1 < end && ngx_tolower(p[0]) == 'q' && p[1] == '=')) {
        return NGX_OK;
    }

    p += 2;

    /* Skip whitespace after = */
    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }

    if (p == end) {
        return NGX_OK;
    }

    /*
     * Parse quality value per RFC 7231 §5.3.1:
     *   qvalue = ( "0" [ "." 0*3DIGIT ] )
     *          / ( "1" [ "." 0*3("0") ] )
     * Only "0" and "1" are valid leading digits.
     * Values outside [0,1] or malformed decimals are rejected.
     */
    if (*p == '0') {
        p++;

        /* q=0 with no decimal → not acceptable */
        if (p == end || *p == ',' || *p == ' ' || *p == ';') {
            return NGX_DECLINED;
        }

        /* Must be followed by '.' for a valid decimal */
        if (*p != '.') {
            return NGX_DECLINED;
        }
        p++;

        /* Require at least one digit after the dot */
        if (p == end || *p < '0' || *p > '9') {
            return NGX_DECLINED;
        }

        /* All-zero fractional part → not acceptable */
        while (p < end && *p >= '0' && *p <= '9') {
            if (*p != '0') {
                return NGX_OK;
            }
            p++;
        }

        return NGX_DECLINED;
    }

    if (*p == '1') {
        p++;

        /* q=1 with optional ".0*" suffix → accept */
        if (p < end && *p == '.') {
            p++;
            while (p < end && *p >= '0' && *p <= '9') {
                if (*p != '0') {
                    /* q=1.x where x>0 is invalid per RFC */
                    return NGX_DECLINED;
                }
                p++;
            }
        }

        return NGX_OK;
    }

    /* Leading digit other than 0 or 1: out of [0,1] */
    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_zstd_accept_encoding(ngx_str_t *ae)
{
    u_char  *p   = ae->data;
    u_char  *end = ae->data + ae->len;

    /*
     * RFC 7231 §5.3.4: Accept-Encoding is a comma-separated list of
     *   codings [ OWS ";" OWS "q=" qvalue ]
     *
     * This walks that list bounded strictly by ae->len — it never
     * dereferences past `end` and never relies on NUL termination, so
     * the length-bounded request buffer and the parser agree on the
     * boundary. (The previous implementation used the NUL-bounded
     * ngx_strcasestrn() over a len-bounded buffer; this removes that
     * dual-bound mismatch entirely.)
     *
     * Behaviour is intentionally identical to that prior implementation:
     * the first standalone "zstd" coding token decides the result via
     * its q-value; a substring inside another token ("notzstd") is not
     * a match because the walk compares whole coding names; and "*" is
     * NOT treated as matching zstd (unchanged — a deliberate parity
     * decision, not an RFC interpretation).
     */
    while (p < end) {

        u_char  *tok, *name_end;

        /* Skip OWS and empty list elements (RFC 7230 allows stray
         * commas, e.g. ", ,zstd"). */
        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
            p++;
        }
        if (p == end) {
            break;
        }

        /* The coding name runs until OWS, ';' (params) or ',' (next
         * element). */
        tok = p;
        while (p < end
               && *p != ' ' && *p != '\t' && *p != ';' && *p != ',')
        {
            p++;
        }
        name_end = p;

        /* Step over any OWS between the name and its ';' or ','. */
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        if ((size_t) (name_end - tok) == sizeof("zstd") - 1
            && ngx_strncasecmp(tok, (u_char *) "zstd",
                               sizeof("zstd") - 1) == 0)
        {
            /*
             * Confirmed standalone "zstd" token. If parameters follow
             * (';'), evaluate the q-value; otherwise it is acceptable.
             * eval_qvalue is itself len-bounded.
             */
            if (p < end && *p == ';') {
                return ngx_http_zstd_eval_qvalue(ae, p);
            }
            return NGX_OK;
        }

        /* Not zstd: skip the remainder of this element up to the
         * next comma, then continue with the following element. */
        while (p < end && *p != ',') {
            p++;
        }
    }

    return NGX_DECLINED;
}


/*
 * ngx_http_zstd_ok()
 *
 * Returns NGX_OK if the request is a main request whose client advertises
 * acceptable zstd support (Accept-Encoding contains "zstd" with q > 0).
 * Sets r->gzip_tested / r->gzip_ok as side effects for Vary handling.
 */
static ngx_int_t
ngx_http_zstd_ok(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ae;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    ae = r->headers_in.accept_encoding;
    if (ae == NULL) {
        return NGX_DECLINED;
    }

    if (ae->value.len < sizeof("zstd") - 1) {
        return NGX_DECLINED;
    }

    if (ngx_http_zstd_accept_encoding(&ae->value) != NGX_OK) {
        return NGX_DECLINED;
    }

    r->gzip_tested = 1;
    r->gzip_ok = 0;

    return NGX_OK;
}


#endif /* NGX_HTTP_ZSTD_COMMON_H */
