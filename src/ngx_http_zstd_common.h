/*
 * Copyright (C) Alex Zhang
 * Copyright (C) 2026 Thijs Eilander
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
 * If `p` points at a DQUOTE, consume the whole quoted-string (RFC 9110
 * §5.6.4: DQUOTE *( qdtext / quoted-pair ) DQUOTE) and return the position
 * just past the closing DQUOTE; otherwise return `p` unchanged. A
 * quoted-string may legitimately contain ';' or ',', so both delimiter
 * scanners below route through this helper to avoid mistaking an embedded
 * delimiter for a parameter or element boundary. Strictly bounded by `end`,
 * never NUL-reliant. Always advances past at least the opening DQUOTE when it
 * fires, so the caller's surrounding loop cannot stall.
 */
static u_char *
ngx_http_zstd_skip_quoted(u_char *p, const u_char *end)
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
 * Walk the up-to-three fractional digits of a "q=0.NNN" qvalue, starting
 * right after the '.'. Advances *p past each digit consumed and returns
 * the accumulated milli-units contribution (0..900, in multiples of 100,
 * 10 or 1 as digits are consumed) via the return value. Bounded on both
 * sides: the loop stops at `end`, and after three digits `scale` has hit
 * 0 so a fourth or later digit byte is left unconsumed for the caller's
 * trailing-junk check to reject. Pure digit-walk, no other qvalue state:
 * splitting it out of ngx_http_zstd_eval_qvalue() shrinks that function's
 * branching without changing what either side does.
 */
static ngx_int_t
ngx_http_zstd_parse_q_fraction(const u_char *end, u_char **p)
{
    /* ngx_int_t (not int) so the digit*scale product widens before the
     * add — avoids a theoretical int overflow CodeQL flags (the operands
     * are tiny in practice). */
    ngx_int_t  scale = 100;
    ngx_int_t  frac = 0;
    u_char    *q = *p;

    while (q < end && *q >= '0' && *q <= '9' && scale > 0) {
        frac += (*q - '0') * scale;
        scale /= 10;
        q++;
    }

    *p = q;
    return frac;
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
ngx_http_zstd_eval_qvalue(const ngx_str_t *ae, u_char *p)
{
    const u_char  *end = ae->data + ae->len;
    ngx_int_t      q = 1000;   /* no q parameter → q=1 */
    ngx_int_t      q_seen = 0; /* reject a second "q" parameter (RFC 9110) */

    while (p < end && *p == ';') {

        const u_char  *nstart, *nend;
        ngx_int_t      is_q;

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

        /*
         * RFC 9110 has no empty-parameter production, so "zstd;;q=1" is
         * malformed rather than "a skipped parameter followed by q=1".
         * Reject it instead of silently resolving the element to q=1.
         */
        if (nend == nstart) {
            return -1;
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
                    return -1;          /* repeated "q" parameter */
                }
                q_seen = 1;

                if (p >= end) {
                    return -1;          /* "q=" with no value */
                }

                if (*p == '0') {
                    p++;
                    q = 0;

                    if (p < end && *p == '.') {
                        p++;
                        q += ngx_http_zstd_parse_q_fraction(end, &p);
                    }

                } else if (*p == '1') {
                    p++;
                    q = 1000;

                    if (p < end && *p == '.') {
                        int  i = 0;

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
                        p = ngx_http_zstd_skip_quoted(p, end);
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
         * After the OWS that may trail any parameter (its q-specific
         * check above only catches junk BEFORE this OWS skip, e.g.
         * "q=1x"), only ';' (another parameter), ',' (next element), or
         * end may follow -- anything else is trailing junk the loop's own
         * "while (*p == ';')" condition would otherwise silently accept
         * as "no more parameters" instead of rejecting (e.g.
         * "zstd;q=1 garbage" previously parsed as zstd;q=1).
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
 * require an explicit opt-in (dcz does: only a dictionary-aware client
 * that actually holds the dictionary can decode a dcz response, so a
 * blanket "*" must not turn it on).
 *
 * This is the walker ngx_http_zstd_accept_encoding() has always been,
 * with the coding name parameterized; the zstd semantics are preserved
 * verbatim by the wrapper below (the fuzz differential oracle depends
 * on that).
 */
static ngx_int_t
ngx_http_zstd_coding_weight(const ngx_str_t *ae, const char *coding,
    size_t coding_len, ngx_uint_t allow_wildcard)
{
    u_char        *p   = ae->data;
    const u_char  *end = ae->data + ae->len;
    ngx_int_t      coding_q = -1; /* explicit `coding` weight, -1 = absent */
    ngx_int_t      star_q = -1;   /* "*" wildcard weight,      -1 = absent */

    while (p < end) {

        u_char        *tok;
        const u_char  *name_end;
        ngx_int_t      is_coding, is_star, q;

        /* Skip OWS and empty list elements (RFC 9110 allows stray
         * commas, e.g. ", ,zstd"). */
        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
            p++;
        }
        if (p >= end) {
            break;
        }

        /* The coding name runs until OWS, ';' (params), ',' (next
         * element), or a DQUOTE. A '"' can never be part of a valid coding
         * token; stopping here keeps a quoted-string that opens in
         * name position (e.g. `"a,zstd "`) from being split on a comma
         * inside the quotes — the quote-aware element-skip below then
         * swallows the whole quoted blob and the element declines. Without
         * this stop, the bytes after an in-quote comma are mis-read as a
         * fresh coding name and can fabricate a phantom "zstd" token. */
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
         * Only ';' (parameters), ',' (next element) or end of field may
         * follow a coding name. RFC 9110 12.5.3 makes `codings` a token,
         * so anything else means this element is not the coding it looked
         * like: `zstd"x` and `zstd "x` advertise nothing, and neither does
         * `zstd x`. nginx's own ngx_http_gzip_accept_encoding() applies
         * the same rule, so accepting these diverged from the sibling
         * filter and compressed for clients that never offered zstd.
         *
         * The check must sit AFTER the OWS skip: the name scan stops on
         * OWS as well as on '"', so testing the stopping byte alone
         * catches `zstd"x` and misses everything hiding behind a space.
         * The quote-aware element-skip below still swallows the rest of
         * the element, so the phantom-token guard is unchanged.
         */
        if (p < end && *p != ';' && *p != ',') {
            is_coding = 0;
            is_star = 0;
        }

        q = 1000;       /* no parameters → q=1 */
        if (p < end && *p == ';') {
            q = ngx_http_zstd_eval_qvalue(ae, p);
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
         * mistaken for an element boundary (which would otherwise let a
         * quoted comma fabricate a phantom coding token from the bytes that
         * follow it, e.g. `gzip;x="a, zstd";q=1`).
         */
        while (p < end && *p != ',') {
            if (*p == '"') {
                p = ngx_http_zstd_skip_quoted(p, end);
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
 * zstd acceptance predicate over one Accept-Encoding value — the
 * original entry point, now a thin wrapper. Semantics are unchanged:
 * NGX_OK iff the effective weight for "zstd" (explicit token, else "*"
 * wildcard) is > 0. The fuzz harness's independent reference oracle
 * asserts exactly this decision, so any behavioural drift here is a
 * fuzz failure, not just a review nit.
 */
static ngx_int_t
ngx_http_zstd_accept_encoding(const ngx_str_t *ae)
{
    ngx_int_t  q;

    q = ngx_http_zstd_coding_weight(ae, "zstd", sizeof("zstd") - 1, 1);

    return q > 0 ? NGX_OK : NGX_DECLINED;
}


/*
 * ngx_http_zstd_accepts()
 *
 * Side-effect-free acceptance predicate: NGX_OK iff this is a main request
 * whose client advertises acceptable zstd support (Accept-Encoding accepts
 * "zstd" with q > 0, via an explicit token or the "*" wildcard). Does NOT
 * touch r->gzip_tested / r->gzip_ok — callers that only need the decision
 * (e.g. the static module, which must not suppress a gzip_static fallback
 * before it even knows whether a .zst file exists) use this.
 */
static ngx_int_t
ngx_http_zstd_accepts(ngx_http_request_t *r)
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
    return ngx_http_zstd_accept_encoding(&ae->value);
}


/*
 * ngx_http_zstd_ok()
 *
 * As ngx_http_zstd_accepts(), but additionally latches r->gzip_tested /
 * r->gzip_ok = 0 on a positive result, so a later gzip filter/handler
 * declines and does not double-compress a response we are about to encode as
 * zstd. Only the on-the-fly filter module uses this: it calls
 * ngx_http_zstd_ok() at the point it commits to compressing
 * (Content-Encoding: zstd is set immediately after), so latching gzip off
 * here is always followed by an actual zstd encoding — the latch never
 * strands a response with neither coding. The static module must NOT use
 * this (see ngx_http_zstd_accepts()).
 *
 * ngx_inline: only the filter TU calls this; the static TU includes the header
 * but uses ngx_http_zstd_accepts() instead, so a plain `static` definition
 * trips -Werror=unused-function there. An inline definition is exempt.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_ok(ngx_http_request_t *r)
{
    if (ngx_http_zstd_accepts(r) != NGX_OK) {
        return NGX_DECLINED;
    }

    r->gzip_tested = 1;
    r->gzip_ok = 0;

    return NGX_OK;
}


/*
 * Push a response header with the given key and value. Handles the
 * nginx_version >= 1023000 guard that sets next=NULL to prevent linked-list
 * corruption on HTTP/1.1 responses. Both key and value are ngx_str_t.
 *
 * Returns NGX_OK on success, NGX_ERROR on allocation failure.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_push_header(ngx_http_request_t *r, const char *key,
    const char *value)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    ngx_str_set(&h->key, key);
    ngx_str_set(&h->value, value);

    return NGX_OK;
}


/*
 * ngx_http_zstd_vary_accept_encoding()
 *
 * Make "Vary: Accept-Encoding" safe BY CONSTRUCTION on any response
 * whose representation depends on Accept-Encoding, instead of leaving
 * it to the operator's "gzip_vary" directive.
 *
 * The hazard this closes: r->gzip_vary alone is only a REQUEST for the
 * header. ngx_http_header_filter_module honours it solely when
 * clcf->gzip_vary is on, and otherwise clears the flag outright
 * (ngx_http_header_filter_module.c: "if (r->gzip_vary) { if
 * (clcf->gzip_vary) ... else r->gzip_vary = 0; }"). So under the
 * default "gzip_vary off" the module negotiated on Accept-Encoding and
 * then shipped a response that did not say so — and a shared cache
 * stored the zstd representation under a key a client sending no
 * "Accept-Encoding: zstd" would hit, handing it a body it cannot
 * decode. That correctness property used to belong to a directive this
 * module does not own; now it does not.
 *
 * DUPLICATE-SAFE, which is the whole subtlety. We must not simply push
 * a header line unconditionally: when clcf->gzip_vary IS on, nginx
 * emits its own "Vary: Accept-Encoding" from r->gzip_vary and we would
 * produce two identical field lines. Caches union all Vary fields so
 * the result would still be semantically correct, but a doubled field
 * is sloppy and strict intermediaries have been known to object. The
 * two emitters are mutually exclusive by construction:
 *
 *   clcf->gzip_vary on  -> set r->gzip_vary, push nothing (nginx emits)
 *   clcf->gzip_vary off -> push our own line (nginx emits nothing,
 *                          having cleared r->gzip_vary)
 *
 * Exactly one "Vary: Accept-Encoding" line in both states, verified as
 * a proxy-cache matrix in CI. r->gzip_vary is set in BOTH branches,
 * because other modules read the flag — notably
 * ngx_http_compression_vary_filter_module, which keys on it alone and
 * flattens the Vary fields it finds, so our own line is folded rather
 * than doubled. That is precisely why emitting a real header is
 * compatible with that module where relying on its default-off
 * directive was not.
 *
 * Callers must invoke this at most once per response, and only on a
 * path that is genuinely Accept-Encoding-dependent. "zstd_static
 * always" deliberately does NOT call it: it ignores Accept-Encoding,
 * so its response is not a negotiated variant and must not claim to
 * vary on one.
 *
 * Returns NGX_OK, or NGX_ERROR when the header-list allocation fails.
 *
 * ngx_inline for the same reason as the helpers above: this header is
 * included by TUs that never call it (the fuzz harness), and a plain
 * `static` definition trips -Werror=unused-function there.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_vary_accept_encoding(ngx_http_request_t *r)
{
    ngx_uint_t                 i;
    ngx_table_elt_t           *h;
    ngx_list_part_t           *part;
    ngx_http_core_loc_conf_t  *clcf;

    r->gzip_vary = 1;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf != NULL && clcf->gzip_vary) {
        /* nginx's header filter emits the line from r->gzip_vary */
        return NGX_OK;
    }

    /*
     * Idempotence, and it is NOT theoretical: the filter and the static
     * handler are separate modules that both reach this helper on one
     * request. With "zstd_static on" + "zstd on" + "gzip_vary off", a
     * non-accepting client makes the static handler emit the field and
     * DECLINE, after which the filter emits it again on the identity
     * response it then also declines to encode -- two identical Vary
     * lines, breaking the exactly-one contract this function exists to
     * keep. (Observed on PR #163 before this guard: `curl -H
     * "Accept-Encoding: gzip"` returned two "Vary: Accept-Encoding"
     * fields.)
     *
     * A request-local flag would need a ctx that the static handler
     * does not own, so scan the response header list instead. It is
     * short at this point (the modules run before most header-emitting
     * filters) and this runs at most twice per response. Scanning also
     * makes the helper safe against a Vary: Accept-Encoding pushed by
     * any OTHER module, not just our own second call.
     *
     * The token compare is case-insensitive on both field name and
     * value, per RFC 9110: field names are case-insensitive, and the
     * field values here are header NAMES, which are too.
     */
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
             * Check if "Accept-Encoding" is among the comma-separated tokens
             * in the Vary value. Parse as comma-separated tokens, trim
             * whitespace, and compare case-insensitively.
             */
            u_char  *p = h[i].value.data;
            u_char  *end = h[i].value.data + h[i].value.len;

            while (p < end) {
                u_char  *token_start, *token_end;

                /* Skip leading whitespace */
                while (p < end && (*p == ' ' || *p == '\t')) {
                    p++;
                }

                if (p >= end) {
                    break;
                }

                token_start = p;

                /* Find end of token (comma or end of string) */
                while (p < end && *p != ',') {
                    p++;
                }

                token_end = p;

                /* Trim trailing whitespace from token */
                while (token_end > token_start
                       && (*(token_end - 1) == ' '
                           || *(token_end - 1) == '\t'))
                {
                    token_end--;
                }

                /* Check if this token is "Accept-Encoding" */
                if (token_end - token_start == sizeof("Accept-Encoding") - 1
                    && ngx_strncasecmp(token_start,
                                       (u_char *) "Accept-Encoding",
                                       sizeof("Accept-Encoding") - 1) == 0)
                {
                    return NGX_OK;
                }

                /* Skip past the comma */
                if (p < end && *p == ',') {
                    p++;
                }
            }
        }
    }

    return ngx_http_zstd_push_header(r, "Vary", "Accept-Encoding");
}


#endif /* NGX_HTTP_ZSTD_COMMON_H */
