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
 * Accept-Encoding parsing per RFC 9110 §12.5.3 (Accept-Encoding) and
 * §12.4.2 (quality values).
 *
 *   Accept-Encoding = #( codings [ weight ] )
 *   codings         = content-coding / "identity" / "*"
 *   weight          = OWS ";" OWS "q=" qvalue
 *   qvalue          = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )
 *
 * The two helpers below walk that grammar strictly bounded by ae->len:
 * every dereference is guarded against `end`, so they never rely on NUL
 * termination even when called with p == end (the libFuzzer target depends
 * on this).
 *
 * qvalues are parsed into integer milli-units (0..1000). The decision for
 * zstd considers both an explicit "zstd" coding and the "*" wildcard
 * (§12.5.3: "*" matches any coding not explicitly listed); an explicit
 * "zstd" token overrides the wildcard. Malformed weights (empty "q=", a
 * fourth decimal digit, trailing junk such as "q=1x", or "1.x" with x!=0)
 * make the element non-matching rather than silently defaulting to q=1.
 */


/*
 * Evaluate the optional parameters of a coding token whose name has just
 * been consumed. `p` points at the ';' that introduces the parameters.
 * Returns the weight in milli-units (0..1000) — 1000 when no "q" parameter
 * is present — or -1 if any parameter is malformed. Strictly length-bounded
 * by ae->len. Takes `p` by value: it does not advance the caller's cursor
 * (the caller re-scans to the next ',').
 */
static ngx_int_t
ngx_http_zstd_eval_qvalue(ngx_str_t *ae, u_char *p)
{
    u_char     *end = ae->data + ae->len;
    ngx_int_t   q = 1000;   /* no q parameter → q=1 */

    while (p < end && *p == ';') {

        u_char     *nstart, *nend;
        ngx_int_t   is_q;

        p++;    /* skip ';' */

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        /* parameter name */
        nstart = p;
        while (p < end
               && *p != '=' && *p != ';' && *p != ','
               && *p != ' ' && *p != '\t')
        {
            p++;
        }
        nend = p;
        is_q = (nend - nstart == 1
                && (nstart[0] == 'q' || nstart[0] == 'Q'));

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        if (p < end && *p == '=') {
            p++;

            while (p < end && (*p == ' ' || *p == '\t')) {
                p++;
            }

            if (is_q) {
                /*
                 * Strict qvalue grammar. Leading digit must be 0 or 1.
                 */
                if (p >= end) {
                    return -1;          /* "q=" with no value */
                }

                if (*p == '0') {
                    /* ngx_int_t (not int) so the digit*scale product widens
                     * before the add — avoids a theoretical int overflow
                     * CodeQL flags (the operands are tiny in practice). */
                    ngx_int_t  scale = 100;

                    p++;
                    q = 0;

                    if (p < end && *p == '.') {
                        p++;
                        while (p < end && *p >= '0' && *p <= '9'
                               && scale > 0)
                        {
                            q += (*p - '0') * scale;
                            scale /= 10;
                            p++;
                        }
                    }

                } else if (*p == '1') {
                    int  i = 0;

                    p++;
                    q = 1000;

                    if (p < end && *p == '.') {
                        p++;
                        while (p < end && *p == '0' && i < 3) {
                            p++;
                            i++;
                        }
                    }

                } else {
                    return -1;          /* leading digit not 0 or 1 */
                }

                /*
                 * After a valid qvalue only OWS / ';' / ',' / end may
                 * follow. A fourth decimal digit or trailing junk
                 * (q=1x, q=0.0001) lands here as a non-delimiter byte and
                 * is rejected.
                 */
                if (p < end
                    && *p != ' ' && *p != '\t' && *p != ';' && *p != ',')
                {
                    return -1;
                }

            } else {
                /* non-q parameter: skip its value to the next ';' or ','. */
                while (p < end && *p != ';' && *p != ',') {
                    p++;
                }
            }

        } else {
            /* parameter present without a value */
            if (is_q) {
                return -1;              /* "q" with no "=value" is malformed */
            }
        }

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }
    }

    return q;
}


static ngx_int_t
ngx_http_zstd_accept_encoding(ngx_str_t *ae)
{
    u_char     *p   = ae->data;
    u_char     *end = ae->data + ae->len;
    ngx_int_t   zstd_q = -1;     /* explicit "zstd" weight, -1 = absent */
    ngx_int_t   star_q = -1;     /* "*" wildcard weight,    -1 = absent */

    while (p < end) {

        u_char     *tok, *name_end;
        ngx_int_t   is_zstd, is_star, q;

        /* Skip OWS and empty list elements (RFC 9110 allows stray
         * commas, e.g. ", ,zstd"). */
        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
            p++;
        }
        if (p >= end) {
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

        is_zstd = ((size_t) (name_end - tok) == sizeof("zstd") - 1
                   && ngx_strncasecmp(tok, (u_char *) "zstd",
                                      sizeof("zstd") - 1) == 0);
        is_star = (name_end - tok == 1 && tok[0] == '*');

        /* Step over any OWS between the name and its ';' or ','. */
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        q = 1000;       /* no parameters → q=1 */
        if (p < end && *p == ';') {
            q = ngx_http_zstd_eval_qvalue(ae, p);
        }

        if (q >= 0) {
            if (is_zstd) {
                zstd_q = q;     /* a later duplicate explicit token wins */
            } else if (is_star) {
                star_q = q;
            }
        }
        /* q < 0 → malformed weight: leave this element non-matching. */

        /* Skip the remainder of this element up to the next comma. */
        while (p < end && *p != ',') {
            p++;
        }
    }

    /*
     * An explicit "zstd" token decides the result (even q=0, which then
     * overrides a permissive "*"). With no explicit "zstd", the "*"
     * wildcard applies if present. Acceptable iff the effective weight > 0.
     */
    if (zstd_q >= 0) {
        return zstd_q > 0 ? NGX_OK : NGX_DECLINED;
    }
    if (star_q >= 0) {
        return star_q > 0 ? NGX_OK : NGX_DECLINED;
    }
    return NGX_DECLINED;
}


/*
 * ngx_http_zstd_ok()
 *
 * Returns NGX_OK if the request is a main request whose client advertises
 * acceptable zstd support (Accept-Encoding accepts "zstd" with q > 0, via
 * an explicit token or the "*" wildcard).
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

    /*
     * A "*" wildcard (one byte) can make zstd acceptable, so the old
     * "shorter than 'zstd'" fast-reject is no longer valid; an empty value
     * is still a decline (the walk below returns NGX_DECLINED).
     */
    if (ngx_http_zstd_accept_encoding(&ae->value) != NGX_OK) {
        return NGX_DECLINED;
    }

    r->gzip_tested = 1;
    r->gzip_ok = 0;

    return NGX_OK;
}


#endif /* NGX_HTTP_ZSTD_COMMON_H */
