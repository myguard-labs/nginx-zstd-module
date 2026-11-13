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
ngx_http_brotli_eval_qvalue(ngx_str_t *ae, u_char **pp)
{
    u_char     *p = *pp;
    u_char     *end = ae->data + ae->len;
    ngx_int_t   q = 1000;   /* no q parameter → q=1 */
    ngx_int_t   q_seen = 0; /* reject a second "q" parameter (RFC 9110) */
    ngx_int_t   quoted_name = 0;    /* DQUOTE seen inside a parameter name */

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
            if (*p == '"') {
                quoted_name = 1;
            }
            p++;
        }
        nend = p;

        /*
         * RFC 9110 has no empty-parameter production, so "br;;q=1"
         * (and a trailing "br;") is malformed rather than "a skipped
         * parameter followed by q=1". Reject it instead of silently
         * resolving the element to q=1 (the siblings' parent #142
         * rule; this copy had drifted without it).
         */
        if (nend == nstart) {
            goto malformed;
        }

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
                    goto malformed;     /* repeated "q" parameter */
                }
                q_seen = 1;

                if (p >= end) {
                    goto malformed;     /* "q=" with no value */
                }

                if (*p == '0') {
                    p++;
                    q = 0;

                    /*
                     * Up to three decimal digits, each with its literal
                     * milli-unit scale (no loop counter to reason
                     * about). A fourth digit stays in place for the
                     * trailing-junk check below to reject.
                     */
                    if (p < end && *p == '.') {
                        p++;

                        if (p < end && *p >= '0' && *p <= '9') {
                            q += (*p++ - '0') * 100;
                        }
                        if (p < end && *p >= '0' && *p <= '9') {
                            q += (*p++ - '0') * 10;
                        }
                        if (p < end && *p >= '0' && *p <= '9') {
                            q += *p++ - '0';
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
                    goto malformed;     /* leading digit not 0 or 1 */
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
                    goto malformed;
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
                goto malformed;         /* "q" with no "=value" is malformed */
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
            goto malformed;
        }
    }

    goto done;

malformed:

    q = -1;

done:

    if (!quoted_name) {
        *pp = p;
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
/*
 * The _ex form also reports the two accumulated weights it computed
 * anyway (zstd sibling #315): *explicit_q is the latest explicit
 * `coding` token's weight and *star_q_out the latest "*" weight, each
 * -1 when that form is absent. The request walker below needs both to
 * compose duplicate field lines, and taking them from one pass keeps it
 * from parsing the same line a second time. The return value is exactly
 * the precedence rule applied to them, so ngx_http_brotli_coding_weight()
 * below stays byte-for-byte the function the fuzz oracle asserts.
 */
static ngx_int_t
ngx_http_brotli_coding_weight_ex(ngx_str_t *ae, const char *coding,
    size_t coding_len, ngx_uint_t allow_wildcard, ngx_int_t *explicit_q,
    ngx_int_t *star_q_out)
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

        /*
         * After the name and OWS only ';' (parameters), ',' (next
         * element), or end may follow. Anything else ("br x") is
         * trailing junk: the element matches nothing rather than
         * negotiating at the implied q=1 below.
         */
        if (p < end && *p != ';' && *p != ',') {
            is_coding = 0;
            is_star = 0;
        }

        q = 1000;       /* no parameters → q=1 */
        if (p < end && *p == ';') {
            q = ngx_http_brotli_eval_qvalue(ae, &p);
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

    *explicit_q = coding_q;
    *star_q_out = star_q;

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
 * Effective weight for `coding` in one field value, the per-form
 * weights discarded. This is the signature the fuzz differential and
 * the extracted parser link against.
 */
static ngx_int_t
ngx_http_brotli_coding_weight(ngx_str_t *ae, const char *coding,
    size_t coding_len, ngx_uint_t allow_wildcard)
{
    ngx_int_t  explicit_q, star_q;

    return ngx_http_brotli_coding_weight_ex(ae, coding, coding_len,
                                            allow_wildcard,
                                            &explicit_q, &star_q);
}


/*
 * Whole-request weight lookup: multiple Accept-Encoding lines are
 * semantically ONE comma-joined field (RFC 9110 section 5.3), so the
 * lines accumulate under the same precedence the single-value walker
 * applies within one line — the latest explicit token wins wherever it
 * appears, and "*" stays subordinate to an explicit token on ANY line.
 * Reading only the first line would refuse a client that advertised br
 * on the second, and would honour an allowance a later line revoked
 * with q=0 — divergence any comma-joining intermediary makes visible.
 *
 * The per-line probe runs once, through the parser's _ex form, which
 * reports an explicit token's verdict (including q=0) and the "*"
 * weight separately (zstd sibling #315; the earlier shape probed twice
 * and re-scanned every line that named no explicit token).
 *
 * nginx >= 1.23 chains same-name headers through ngx_table_elt_t.next;
 * older cores keep only the first line in headers_in.accept_encoding,
 * so there the raw headers list is walked instead.
 */
/*
 * One field line folded into the field-wide accumulators, and the
 * final precedence over them. The two collections in the request
 * walker below (the ->next chain on nginx >= 1.23, the raw header
 * list on older cores) may differ per build; the accumulation and
 * precedence MUST not — a private copy in each branch is how the two
 * shapes' negotiation drifts apart with only one compiled at a time.
 */
static ngx_inline void
ngx_http_brotli_fold_line_weight(ngx_str_t *value, const char *coding,
    size_t coding_len, ngx_uint_t allow_wildcard, ngx_int_t *coding_q,
    ngx_int_t *star_q)
{
    ngx_int_t  line_coding_q, line_star_q;

    (void) ngx_http_brotli_coding_weight_ex(value, coding, coding_len,
                                            allow_wildcard,
                                            &line_coding_q, &line_star_q);

    if (line_coding_q >= 0) {
        *coding_q = line_coding_q;  /* comma-joined in received order */
        return;
    }

    if (allow_wildcard && line_star_q >= 0) {
        *star_q = line_star_q;
    }
}


static ngx_inline ngx_int_t
ngx_http_brotli_field_weight(ngx_int_t coding_q, ngx_int_t star_q,
    ngx_uint_t allow_wildcard)
{
    if (coding_q >= 0) {
        return coding_q;
    }
    if (allow_wildcard && star_q >= 0) {
        return star_q;
    }
    return -1;
}


static ngx_int_t
ngx_http_brotli_request_coding_weight(ngx_http_request_t *r,
    const char *coding, size_t coding_len, ngx_uint_t allow_wildcard)
{
    ngx_int_t         coding_q, star_q;
#if nginx_version >= 1023000
    ngx_table_elt_t  *ae;
#else
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
#endif

    coding_q = -1;
    star_q = -1;

#if nginx_version >= 1023000

    for (ae = r->headers_in.accept_encoding; ae != NULL; ae = ae->next) {
        ngx_http_brotli_fold_line_weight(&ae->value, coding, coding_len,
                                         allow_wildcard,
                                         &coding_q, &star_q);
    }

#else

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0
            || h[i].key.len != sizeof("Accept-Encoding") - 1
            || ngx_strncasecmp(h[i].key.data, (u_char *) "Accept-Encoding",
                               sizeof("Accept-Encoding") - 1)
               != 0)
        {
            continue;
        }

        ngx_http_brotli_fold_line_weight(&h[i].value, coding, coding_len,
                                         allow_wildcard,
                                         &coding_q, &star_q);
    }

#endif

    return ngx_http_brotli_field_weight(coding_q, star_q, allow_wildcard);
}


/*
 * br acceptance predicate over one Accept-Encoding value: NGX_OK iff the
 * effective weight for "br" (explicit token, else "*" wildcard) is > 0.
 * Production callers negotiate whole-request through
 * ngx_http_brotli_request_coding_weight(); this single-value shape is
 * kept as the fuzz harness's entry point (fuzz/extract_parser.sh slices
 * it out by name). ngx_inline: no in-tree TU calls it any more, and an
 * inline definition is exempt from -Werror=unused-function.
 */
static ngx_inline ngx_int_t
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
 * whose client advertises acceptable br support across the whole
 * Accept-Encoding field. Does NOT touch r->gzip_tested / r->gzip_ok —
 * callers that only need the decision use this. In particular the static
 * module must use THIS before it knows whether a .br file exists:
 * latching gzip off first would suppress a later gzip_static fallback
 * for a client that accepts both br and gzip when only a .gz file is on
 * disk (it previously did exactly that).
 */
static ngx_int_t
ngx_http_brotli_accepts(ngx_http_request_t *r)
{
    if (r != r->main) {
        return NGX_DECLINED;
    }

    return ngx_http_brotli_request_coding_weight(r, "br", sizeof("br") - 1, 1)
           > 0 ? NGX_OK : NGX_DECLINED;
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
 * ngx_http_brotli_vary_accept_encoding()
 *
 * Emit "Vary: Accept-Encoding" BY CONSTRUCTION (parent nginx-zstd-module
 * #163) rather than merely requesting it through r->gzip_vary. A brotli
 * (or dcb, or Accept-Encoding-negotiated static) response is a
 * content-coding variant, but nginx only turns r->gzip_vary into a Vary
 * line when the core "gzip_vary" directive is on — and its default is
 * OFF, under which nginx clears the flag and emits nothing, so by default
 * a negotiated response shipped with no Vary and a shared cache could
 * hand the compressed body to a client that cannot decode it.
 *
 * When gzip_vary is on, defer to nginx (it dedups against an existing
 * line). When it is off, scan the response headers and push the literal
 * line only if one is not already present (another filter, or the origin,
 * may have set it), so the field is never doubled in either state.
 *
 * Shared by the filter and static modules — a header-static so each
 * translation unit gets its own copy, exactly like the helpers above.
 */
static ngx_inline ngx_int_t
ngx_http_brotli_vary_accept_encoding(ngx_http_request_t *r)
{
    ngx_uint_t                 i;
    ngx_table_elt_t           *v, *h;
    ngx_list_part_t           *part;
    ngx_http_core_loc_conf_t  *clcf;

    r->gzip_vary = 1;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf != NULL && clcf->gzip_vary) {
        /* nginx's header filter emits the line from r->gzip_vary */
        return NGX_OK;
    }

    for (part = &r->headers_out.headers.part, h = part->elts, i = 0;
         /* void */;
         i++)
    {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (h[i].key.len == sizeof("Vary") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Vary",
                               sizeof("Vary") - 1) == 0)
        {
            /*
             * "Accept-Encoding" must be matched among the value's
             * comma-separated tokens (zstd sibling #200 row n11): an
             * exact-value compare misses an origin's
             * "Vary: Accept-Encoding, Cookie" and doubles the token on
             * a second line. Trim OWS per token, compare
             * case-insensitively (the values are header names).
             */
            u_char* p = h[i].value.data;
            u_char* end = h[i].value.data + h[i].value.len;

            while (p < end) {
                u_char *tstart, *tend;

                while (p < end && (*p == ' ' || *p == '\t')) {
                    p++;
                }
                if (p >= end) {
                    break;
                }

                tstart = p;
                while (p < end && *p != ',') {
                    p++;
                }
                tend = p;

                while (tend > tstart
                       && (*(tend - 1) == ' ' || *(tend - 1) == '\t')) {
                    tend--;
                }

                if (tend - tstart == sizeof("Accept-Encoding") - 1
                    && ngx_strncasecmp(tstart, (u_char*) "Accept-Encoding",
                                       sizeof("Accept-Encoding") - 1) == 0) {
                    return NGX_OK;
                }

                if (p < end && *p == ',') {
                    p++;
                }
            }
        }
    }

    v = ngx_list_push(&r->headers_out.headers);
    if (v == NULL) {
        return NGX_ERROR;
    }
    v->hash = 1;
#if nginx_version >= 1023000
    v->next = NULL;
#endif
    ngx_str_set(&v->key, "Vary");
    ngx_str_set(&v->value, "Accept-Encoding");
    return NGX_OK;
}


#endif /* NGX_HTTP_BROTLI_COMMON_H */
