/*
 * Copyright (C) Alex Zhang
 * Copyright (C) 2026 Thijs Eilander
 *
 * THE authoritative copy of the Accept-Encoding parser: the RFC 9110
 * qvalue grammar walk and the per-line, per-field and per-request
 * weight lookups for one content coding. No logging, no allocation,
 * no zstd -- the coding name is a parameter, so every consumer (the
 * filter module and the static module through ngx_http_zstd_common.h,
 * the fuzz target and the unit suite through ci/fuzz/extract_parser.sh,
 * the compression branch's negotiation) uses THIS file instead of
 * carrying a synchronized copy. The parser existed three times across
 * the two trees and the brotli fork, each copy fuzzed and unit-tested
 * on its own; a fix to it would have been ported three times and
 * proven three times.
 *
 * CONSUMER CONTRACT. Inside nginx, include after the nginx headers and
 * everything below resolves: ngx_str_t, ngx_table_elt_t (its ->next
 * link on nginx >= 1.23.0), ngx_http_request_t with the
 * headers_in.accept_encoding field the gzip and headers modules
 * declare, ngx_strncasecmp() and ngx_inline. Outside nginx, the fuzz
 * target and the unit suite do not include this file: they slice the
 * function bodies out of it with ci/fuzz/extract_parser.sh and supply
 * those few names from ci/fuzz/ngx_shim.h, so the code they exercise is
 * the shipped code and never a copy.
 *
 * Every function is ngx_http_zstd_common.h's, moved verbatim. The zstd
 * wrappers that fix the coding name -- ngx_http_zstd_accept_encoding(),
 * ngx_http_zstd_accepts(), ngx_http_zstd_ok() -- stay in that header;
 * they are the only place the string "zstd" appears on this path.
 */

#ifndef NGX_HTTP_ZSTD_ACCEPT_ENCODING_H
#define NGX_HTTP_ZSTD_ACCEPT_ENCODING_H


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
    /* ngx_int_t (not int) so each digit*weight product widens before the
     * add — avoids a theoretical int overflow CodeQL flags (the operands
     * are tiny in practice). */
    ngx_int_t  frac = 0;
    u_char    *q = *p;

    /*
     * RFC 9110's qvalue grammar permits at most three fractional digits
     * ("0" "." 0*3DIGIT), so the walk is fixed at three guarded steps
     * with literal weights 100/10/1 instead of a loop counting a
     * runtime `scale` down by dividing by 10 each iteration. Each step
     * is behaviour-identical to one loop iteration of the original: it
     * only fires if the previous step also fired (so a mismatch or
     * end-of-input at digit N leaves N-1..2 unconsumed, exactly as the
     * loop's own condition would stop it), and after the third digit
     * `q` is NOT advanced again -- a fourth or later digit byte is
     * deliberately left for the caller's trailing-junk check to reject,
     * the same contract the loop's `scale > 0` guard enforced.
     */
    if (q < end && *q >= '0' && *q <= '9') {
        frac += (*q - '0') * 100;
        q++;

        if (q < end && *q >= '0' && *q <= '9') {
            frac += (*q - '0') * 10;
            q++;

            if (q < end && *q >= '0' && *q <= '9') {
                frac += (*q - '0') * 1;
                q++;
            }
        }
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
 * by ae->len.
 *
 * Single-pass cursor contract: `*pp` points at the ';' on entry and is
 * advanced to the resume position on return, so the caller never rescans
 * the parameter bytes. On success that is the next top-level ',' or end
 * (the trailing-junk check below guarantees it); on -1 it is the byte the
 * walk stopped on, from which the caller's quote-aware skip to the next
 * ',' yields exactly what a rescan from the ';' would. The one input that
 * breaks that equivalence is a DQUOTE inside a parameter NAME: the name
 * scan steps over it, whereas a quote-aware rescan from the ';' would open
 * a quoted-string there. For that (malformed, token grammar forbids it)
 * case `*pp` is left at the ';' so the caller's skip reproduces the
 * historical result byte for byte -- a rescan only on that input, not on
 * every parameterized element.
 */
static ngx_int_t
ngx_http_zstd_eval_qvalue(const ngx_str_t *ae, u_char **pp)
{
    u_char        *p = *pp;
    const u_char  *end = ae->data + ae->len;
    ngx_int_t      q = 1000;   /* no q parameter → q=1 */
    ngx_int_t      q_seen = 0; /* reject a second "q" parameter (RFC 9110) */
    ngx_int_t      quoted_name = 0; /* DQUOTE seen inside a parameter name */

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
            if (*p == '"') {
                quoted_name = 1;
            }
            p++;
        }
        nend = p;

        /*
         * RFC 9110 has no empty-parameter production, so "zstd;;q=1" is
         * malformed rather than "a skipped parameter followed by q=1".
         * Reject it instead of silently resolving the element to q=1.
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
                        p = ngx_http_zstd_skip_quoted(p, end);
                    } else {
                        p++;
                    }
                }
            }

        } else {
            /* parameter present without a value */
            if (is_q) {
                goto malformed;     /* "q" with no "=value" is malformed */
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
 * require an explicit opt-in (dcz does: only a dictionary-aware client
 * that actually holds the dictionary can decode a dcz response, so a
 * blanket "*" must not turn it on).
 *
 * This is the walker ngx_http_zstd_accept_encoding() has always been,
 * with the coding name parameterized; the zstd semantics are preserved
 * verbatim by the wrapper below (the fuzz differential oracle depends
 * on that).
 *
 * The _ex form additionally reports the two accumulated weights it had to
 * compute anyway: *explicit_q is the latest explicit `coding` token's
 * weight and *star_q_out the latest "*" weight, each -1 when that form is
 * absent from the value. The chain walker needs both to compose duplicate
 * field lines, and taking them from one pass keeps it from parsing the
 * same line a second time just to learn which of the two produced the
 * answer. Both out-params are mandatory; the return value is exactly the
 * precedence rule applied to them, so ngx_http_zstd_coding_weight() below
 * stays byte-for-byte the function the fuzz differential oracle asserts.
 */
static ngx_int_t
ngx_http_zstd_coding_weight_ex(const ngx_str_t *ae, const char *coding,
    size_t coding_len, ngx_uint_t allow_wildcard, ngx_int_t *explicit_q,
    ngx_int_t *star_q_out)
{
    u_char        *p   = ae->data;
    const u_char  *end = ae->data + ae->len;
    ngx_int_t      coding_q = -1; /* explicit `coding` weight, -1 = absent */
    ngx_int_t      star_q = -1;   /* "*" wildcard weight,      -1 = absent */

#ifdef NGX_HTTP_ZSTD_TEST_COUNT_CODING_WEIGHT
    ngx_http_zstd_test_coding_weight_calls++;
#endif

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
            q = ngx_http_zstd_eval_qvalue(ae, &p);
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
         * follow it, e.g. `gzip;x="a, zstd";q=1`). After a well-formed
         * parameter list this is a no-op: ngx_http_zstd_eval_qvalue() has
         * already advanced `p` to that comma. It still does real work for
         * a malformed element (p sits on the offending byte) and for a
         * DQUOTE inside a parameter name (p is still on the ';').
         */
        while (p < end && *p != ',') {
            if (*p == '"') {
                p = ngx_http_zstd_skip_quoted(p, end);
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
 * Effective weight for `coding` in one Accept-Encoding field value, with
 * the per-form weights discarded. This is the signature the fuzz
 * differential and the extracted unit suite link against.
 */
static ngx_int_t
ngx_http_zstd_coding_weight(const ngx_str_t *ae, const char *coding,
    size_t coding_len, ngx_uint_t allow_wildcard)
{
    ngx_int_t  explicit_q, star_q;

    return ngx_http_zstd_coding_weight_ex(ae, coding, coding_len,
                                          allow_wildcard,
                                          &explicit_q, &star_q);
}


/*
 * Step to the next duplicate Accept-Encoding field line.
 *
 * nginx grew ngx_table_elt_t.next in 1.23.0 (the linked-list header
 * rework); that is the same version floor every other ->next use in this
 * module guards on -- see the `#if (nginx_version >= 1023000)` sites in
 * the filter and in ngx_http_zstd_push_header() below.
 *
 * On an older nginx the field does not exist. The request-level helper below
 * walks r->headers_in.headers there; this macro remains a single-field step
 * so the common chain walker is safe for callers with one field.
 */
#if (nginx_version >= 1023000)
#define NGX_HTTP_ZSTD_AE_NEXT(ae)  ((const ngx_table_elt_t *) (ae)->next)
#else
#define NGX_HTTP_ZSTD_AE_NEXT(ae)  ((const ngx_table_elt_t *) NULL)
#endif


/*
 * ngx_http_zstd_chain_coding_weight()
 *
 * Effective weight for `coding` across the WHOLE Accept-Encoding header
 * field, i.e. every duplicate field line nginx chained on ->next, not
 * just the first. Returns milli-units (0..1000), or -1 when the field
 * expresses no preference for `coding` at all. `ae` may be NULL (no
 * Accept-Encoding at all), which is -1.
 *
 * WHY THIS EXISTS. nginx does not reject a repeated Accept-Encoding
 * request header; it chains the extra field lines on ae->next. RFC 9110
 * section 5.3 makes a repeated list-valued field semantically identical to
 * the single field whose value is the lines joined in order with commas,
 * so
 *
 *     Accept-Encoding: gzip
 *     Accept-Encoding: zstd
 *
 * IS "gzip, zstd" and accepts zstd. Evaluating only ae->value read that
 * request as "gzip" and declined. The in-code justification used to be
 * parity with nginx's own gzip filter, but parity with a sibling module is
 * not the contract this module advertises: the README documents an
 * Accept-Encoding negotiation, and a client that split its codings across
 * two lines is entitled to the same answer it would have got from one.
 *
 * Duplicate coding values retain that received order: the latest explicit
 * token wins, just as it does within one field line. Thus `zstd;q=0` then
 * `zstd;q=1` accepts, while the reversed order declines. This keeps a
 * comma-joined set of lines equivalent to its single-field representation.
 *
 * The wildcard is accumulated the same way and stays subordinate to an
 * explicit token exactly as in the single-value parser: any explicit token
 * anywhere in the field decides, and "*" applies only when no line named
 * the coding explicitly. `allow_wildcard` has the same meaning as in
 * ngx_http_zstd_coding_weight() and is passed straight through.
 *
 * NOTE the two-level accumulation is deliberate and NOT a contradiction.
 * Within ONE field-line value, ngx_http_zstd_coding_weight() keeps its
 * existing last-wins behaviour for a repeated token, byte for byte — the
 * fuzz differential's independent reference oracle asserts exactly that
 * single-value decision, and changing it would be a behavioural drift the
 * fuzzer is entitled to fail on. This function composes those per-line
 * answers; it never reaches inside one.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_chain_coding_weight(const ngx_table_elt_t *ae,
    const char *coding, size_t coding_len, ngx_uint_t allow_wildcard)
{
    ngx_int_t  coding_q = -1;   /* latest explicit token, -1 = absent */
    ngx_int_t  star_q = -1;     /* latest "*" wildcard, -1 = absent */

    for (/* void */; ae != NULL; ae = NGX_HTTP_ZSTD_AE_NEXT(ae)) {

        ngx_int_t  line_coding_q, line_star_q;

        /*
         * One pass per line. The single-value parser accumulates the
         * explicit and the wildcard weight separately anyway, so the _ex
         * form hands both back and this walker composes them directly.
         * The earlier shape asked the parser twice per line — once with
         * the wildcard suppressed to isolate the explicit weight, then
         * again to learn the effective one — which re-scanned every line
         * that named no explicit token, i.e. the common case.
         *
         * ngx_http_zstd_coding_weight() is unchanged as a symbol: it is
         * the fuzzed, extracted-into-the-unit-suite function, and it is
         * now the wrapper that drops these two out-params.
         */
        (void) ngx_http_zstd_coding_weight_ex(&ae->value, coding, coding_len,
                                              allow_wildcard,
                                              &line_coding_q, &line_star_q);

        if (line_coding_q >= 0) {
            /* Duplicate field lines are comma-joined in received order. */
            coding_q = line_coding_q;
            continue;
        }

        if (allow_wildcard && line_star_q >= 0) {
            star_q = line_star_q;
        }
    }

    /*
     * Same precedence as the single-value parser: an explicit token
     * anywhere in the field decides (even q=0, which then overrides a
     * permissive "*"); with no explicit token the wildcard applies if
     * present and permitted by the caller.
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
 * Effective weight across the request's complete Accept-Encoding field.
 * nginx before 1.23.0 does not link duplicate table elements through ->next:
 * accept_encoding names the first one and every later occurrence remains in
 * headers_in.headers. RFC 9110 section 5.3 still requires all occurrences to
 * be treated as one comma-joined field.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_request_coding_weight(ngx_http_request_t *r, const char *coding,
    size_t coding_len, ngx_uint_t allow_wildcard)
{
#if (nginx_version >= 1023000)
    return ngx_http_zstd_chain_coding_weight(r->headers_in.accept_encoding,
                                              coding, coding_len,
                                              allow_wildcard);
#else
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *headers;
    ngx_int_t         coding_q, star_q, line_coding_q, line_star_q;

    coding_q = -1;
    star_q = -1;
    part = &r->headers_in.headers.part;
    headers = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            headers = part->elts;
            i = 0;
        }

        if (headers[i].key.len != sizeof("Accept-Encoding") - 1
            || ngx_strncasecmp(headers[i].key.data,
                                (u_char *) "Accept-Encoding",
                                sizeof("Accept-Encoding") - 1) != 0)
        {
            continue;
        }

        (void) ngx_http_zstd_coding_weight_ex(&headers[i].value, coding,
                                              coding_len, allow_wildcard,
                                              &line_coding_q, &line_star_q);
        if (line_coding_q >= 0) {
            coding_q = line_coding_q;
            continue;
        }

        if (allow_wildcard && line_star_q >= 0) {
            star_q = line_star_q;
        }
    }

    if (coding_q >= 0) {
        return coding_q;
    }
    if (allow_wildcard && star_q >= 0) {
        return star_q;
    }
    return -1;
#endif
}


#endif /* NGX_HTTP_ZSTD_ACCEPT_ENCODING_H */
