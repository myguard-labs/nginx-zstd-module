/*
 * Copyright (C) Google Inc.
 *
 * Shared Accept-Encoding parsing used by both the filter module and the
 * static module. Included as a static inline header to avoid a separate
 * compilation unit while eliminating the previous hand-maintained
 * duplicate of the parser in each module.
 *
 * Ported from nginx-zstd-module's ngx_http_zstd_common.h (BSD-2-Clause,
 * Copyright (C) Alex Zhang and contributors), where this parser is
 * continuously fuzzed with an independent differential oracle. The
 * walker is parameterized by coding name, so the future dcb (RFC 9842)
 * lookup reuses it unchanged.
 *
 * Behavioural differences from the previous substring-scan parser, all
 * deliberate (see README):
 *
 *   - "*" (RFC 9110 §12.5.3 wildcard) now matches br;
 *   - a coding name inside a quoted parameter value (e.g.
 *     `gzip;x="a, br"`) no longer fabricates a phantom br token;
 *   - the weight parameter name is case-insensitive ("Q=0" now declines
 *     instead of being ignored);
 *   - malformed weights make the element non-matching instead of
 *     defaulting to accept;
 *   - a later duplicate explicit token wins (`br;q=0, br` now accepts).
 */

#ifndef NGX_HTTP_BROTLI_COMMON_H
#define NGX_HTTP_BROTLI_COMMON_H

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
 * The helpers below walk that grammar strictly bounded by ae->len: every
 * dereference is guarded against `end`, so they never rely on NUL
 * termination (the libFuzzer target depends on this).
 *
 * qvalues are parsed into integer milli-units (0..1000).
 */


/*
 * If `p` points at a DQUOTE, consume the whole quoted-string (RFC 9110
 * §5.6.4: DQUOTE *( qdtext / quoted-pair ) DQUOTE) and return the position
 * just past the closing DQUOTE; otherwise return `p` unchanged. A
 * quoted-string may legitimately contain ';' or ',', so both delimiter
 * scanners below route through this helper to avoid mistaking an embedded
 * delimiter for a parameter or element boundary. Strictly bounded by `end`,
 * never NUL-reliant. Always advances past at least the opening DQUOTE when
 * it fires, so the caller's surrounding loop cannot stall.
 */
static u_char *
ngx_http_brotli_skip_quoted(u_char *p, u_char *end)
{
    if (p >= end || *p != '"') {
        return p;
    }

    p++;    /* opening DQUOTE */

    while (p < end && *p != '"') {
        if (*p == '\\' && p + 1 < end) {
            p++;    /* skip the escaped octet of a quoted-pair */
        }
        p++;
    }

    if (p < end) {
        p++;    /* closing DQUOTE */
    }

    return p;
}


/*
 * Evaluate the optional parameters of a coding token whose name has just
 * been consumed. `p` points at the ';' that introduces the parameters.
 * Returns the weight in milli-units (0..1000) — 1000 when no "q" parameter
 * is present — or -1 if any parameter is malformed (including a repeated
 * "q", which RFC 9110 §12.4.2 permits at most once). Strictly length-bounded
 * by ae->len. Takes `p` by value: it does not advance the caller's cursor
 * (the caller re-scans to the next ',').
 */
static ngx_int_t
ngx_http_brotli_eval_qvalue(ngx_str_t *ae, u_char *p)
{
    u_char     *end = ae->data + ae->len;
    ngx_int_t   q = 1000;   /* no q parameter → q=1 */
    ngx_int_t   q_seen = 0; /* reject a second "q" parameter (RFC 9110) */

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
                if (q_seen) {
                    return -1;          /* repeated "q" parameter */
                }
                q_seen = 1;

                if (p >= end) {
                    return -1;          /* "q=" with no value */
                }

                if (*p == '0') {
                    /* ngx_int_t (not int) so the digit*scale product widens
                     * before the add. */
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
                /*
                 * non-q parameter: skip its value to the next top-level ';'
                 * (another parameter) or ',' (next element), stepping over a
                 * quoted-string so an embedded delimiter is not mistaken for
                 * the value's end.
                 */
                while (p < end && *p != ';' && *p != ',') {
                    if (*p == '"') {
                        p = ngx_http_brotli_skip_quoted(p, end);
                    } else {
                        p++;
                    }
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

        /*
         * After the OWS that may trail any parameter, only ';' (another
         * parameter), ',' (next element), or end may follow — anything
         * else is trailing junk (e.g. "br;q=1 garbage") and rejects the
         * element rather than silently accepting it.
         */
        if (p < end && *p != ';' && *p != ',') {
            return -1;
        }
    }

    return q;
}


/*
 * Generic weight lookup for one content coding in an Accept-Encoding
 * value. Returns the effective weight for `coding` in milli-units
 * (0..1000), or -1 when the header expresses no preference for it at
 * all. An explicit token always decides (even q=0, which then overrides
 * a permissive "*"); with no explicit token the "*" wildcard applies
 * only when `allow_wildcard` is set — RFC 9110 §12.5.3's "*" matches
 * any coding not explicitly listed, but a caller may legitimately
 * require an explicit opt-in (a future dcb lookup will: only a client
 * that actually holds the dictionary can decode a dictionary-compressed
 * response, so a blanket "*" must not turn it on).
 */
static ngx_int_t
ngx_http_brotli_coding_weight(ngx_str_t *ae, const char *coding,
    size_t coding_len, ngx_uint_t allow_wildcard)
{
    u_char     *p   = ae->data;
    u_char     *end = ae->data + ae->len;
    ngx_int_t   coding_q = -1;   /* explicit `coding` weight, -1 = absent */
    ngx_int_t   star_q = -1;     /* "*" wildcard weight,      -1 = absent */

    while (p < end) {

        u_char     *tok, *name_end;
        ngx_int_t   is_coding, is_star, q;

        /* Skip OWS and empty list elements (RFC 9110 allows stray
         * commas, e.g. ", ,br"). */
        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
            p++;
        }
        if (p >= end) {
            break;
        }

        /* The coding name runs until OWS, ';' (params), ',' (next
         * element), or a DQUOTE. A '"' can never be part of a valid coding
         * token; stopping here keeps a quoted-string that opens in
         * name position (e.g. `"a,br "`) from being split on a comma
         * inside the quotes — the quote-aware element-skip below then
         * swallows the whole quoted blob and the element declines. Without
         * this stop, the bytes after an in-quote comma are mis-read as a
         * fresh coding name and can fabricate a phantom "br" token. */
        tok = p;
        while (p < end
               && *p != ' ' && *p != '\t' && *p != ';' && *p != ','
               && *p != '"')
        {
            p++;
        }
        name_end = p;

        is_coding = ((size_t) (name_end - tok) == coding_len
                     && ngx_strncasecmp(tok, (u_char *) coding,
                                        coding_len) == 0);
        is_star = (name_end - tok == 1 && tok[0] == '*');

        /* Step over any OWS between the name and its ';' or ','. */
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        q = 1000;       /* no parameters → q=1 */
        if (p < end && *p == ';') {
            q = ngx_http_brotli_eval_qvalue(ae, p);
        }

        if (q >= 0) {
            if (is_coding) {
                coding_q = q;   /* a later duplicate explicit token wins */
            } else if (is_star) {
                star_q = q;
            }
        }
        /* q < 0 → malformed weight: leave this element non-matching. */

        /*
         * Skip the remainder of this element up to the next top-level comma,
         * stepping over any quoted-string so a ',' inside quotes is not
         * mistaken for an element boundary.
         */
        while (p < end && *p != ',') {
            if (*p == '"') {
                p = ngx_http_brotli_skip_quoted(p, end);
            } else {
                p++;
            }
        }
    }

    /*
     * An explicit token decides the result (even q=0, which then
     * overrides a permissive "*"). With no explicit token, the "*"
     * wildcard applies if present and permitted by the caller.
     */
    if (coding_q >= 0) {
        return coding_q;
    }
    if (allow_wildcard && star_q >= 0) {
        return star_q;
    }
    return -1;
}


/*
 * br acceptance predicate over one Accept-Encoding value: NGX_OK iff the
 * effective weight for "br" (explicit token, else "*" wildcard) is > 0.
 */
static ngx_int_t
ngx_http_brotli_accept_encoding(ngx_str_t *ae)
{
    ngx_int_t  q;

    q = ngx_http_brotli_coding_weight(ae, "br", sizeof("br") - 1, 1);

    return q > 0 ? NGX_OK : NGX_DECLINED;
}


/*
 * ngx_http_brotli_accepts()
 *
 * Side-effect-free acceptance predicate: NGX_OK iff this is a main request
 * whose client advertises acceptable br support. Does NOT touch
 * r->gzip_tested / r->gzip_ok — callers that only need the decision use
 * this. In particular the static module must use THIS before it knows
 * whether a .br file exists: latching gzip off first would suppress a
 * later gzip_static fallback for a client that accepts both br and gzip
 * when only a .gz file is on disk (it previously did exactly that).
 */
static ngx_int_t
ngx_http_brotli_accepts(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ae;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    ae = r->headers_in.accept_encoding;
    if (ae == NULL) {
        return NGX_DECLINED;
    }

    return ngx_http_brotli_accept_encoding(&ae->value);
}


/*
 * ngx_http_brotli_ok()
 *
 * As ngx_http_brotli_accepts(), but additionally latches r->gzip_tested /
 * r->gzip_ok = 0 on a positive result, so a later gzip filter/handler
 * declines and does not double-compress a response we are about to encode
 * as br. Callers must invoke this only at the point they COMMIT to a br
 * response (the filter module right before setting Content-Encoding; the
 * static module only after the .br file is known to exist).
 *
 * ngx_inline: not every including TU calls both predicates; an inline
 * definition is exempt from -Werror=unused-function.
 */
static ngx_inline ngx_int_t
ngx_http_brotli_ok(ngx_http_request_t *r)
{
    if (ngx_http_brotli_accepts(r) != NGX_OK) {
        return NGX_DECLINED;
    }

    r->gzip_tested = 1;
    r->gzip_ok = 0;

    return NGX_OK;
}


/*
 * ngx_http_brotli_vary_handled_externally()
 *
 * True when a module named "ngx_http_compression_vary_filter_module"
 * (HanadaLee's Vary-flattening filter) is loaded, statically or via
 * load_module. When its "compression_vary" directive is on, that
 * module emits Vary: Accept-Encoding keyed on r->gzip_vary alone,
 * regardless of clcf->gzip_vary — replacing the "gzip_vary" directive
 * (verified empirically against all four gzip_vary x compression_vary
 * quadrants; its author explicitly recommends "gzip_vary off" when
 * "compression_vary on" is used). With it loaded, "gzip_vary off" is
 * plausibly deliberate rather than a caching hazard.
 *
 * PRESENCE IS NOT PROOF, though: "compression_vary" itself defaults
 * to off, and this module cannot verify the effective value — the
 * conf struct is private to that module, and merge order between
 * unrelated modules follows their position in cycle->modules, so its
 * merged values may not even exist yet when ours merge. Callers
 * therefore must not silence the gzip_vary-off warning outright on
 * this check; they withhold the per-location lines and emit one
 * summary warning from postconfiguration that tells the operator
 * exactly what to verify.
 *
 * Called at merge-time: every load_module directive has been processed
 * by then (core conf parses before the http block), so
 * cf->cycle->modules is complete for both linkage styles.
 *
 * ngx_inline for the same reason as ngx_http_brotli_ok() above.
 */
static ngx_inline ngx_uint_t
ngx_http_brotli_vary_handled_externally(ngx_conf_t *cf)
{
    ngx_uint_t  i;

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (ngx_strcmp(cf->cycle->modules[i]->name,
                       "ngx_http_compression_vary_filter_module") == 0)
        {
            return 1;
        }
    }

    return 0;
}


#endif /* NGX_HTTP_BROTLI_COMMON_H */
