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
 * Step to the next duplicate Accept-Encoding field line.
 *
 * nginx grew ngx_table_elt_t.next in 1.23.0 (the linked-list header
 * rework); that is the same version floor every other ->next use in this
 * module guards on -- see the `#if (nginx_version >= 1023000)` sites in
 * the filter and in ngx_http_zstd_push_header() below.
 *
 * On an older nginx the field does not exist and duplicate Accept-Encoding
 * lines are not chained at all: r->headers_in.accept_encoding points at
 * the first occurrence and the rest are reachable only by walking
 * r->headers_in.headers. Rather than fork the walker, the macro degrades
 * to "there is no next line", which is exactly the pre-1.23 behaviour this
 * module has always had there -- the fix lands on every nginx that can
 * express the chain, and nothing regresses on the ones that cannot.
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
 * DUPLICATE-CODING RULE — an explicit q=0 anywhere is final ("sticky").
 *
 * When the same coding appears in more than one field line with different
 * weights (`zstd;q=0` on one line, `zstd;q=1` on another), the joined list
 * is self-contradictory and RFC 9110 blesses no winner, because a
 * conforming sender should never have produced it. We resolve it in the
 * fail-safe direction: the LOWEST explicit weight wins, so an explicit
 * "do not send me this" is honoured wherever it appears and can never be
 * upgraded back into an accept by a later line.
 *
 * That is not a new policy invented here — it is the policy this module
 * already documents. README's "Selection policy" says the module "honours
 * each coding's own q=0 as an absolute 'not acceptable'", and the dcz
 * section lists "dcz;q=0" as a hard gate miss. "Absolute" has to mean
 * absolute across the whole field, otherwise a client can refuse a coding
 * on one line and have the refusal quietly discarded by the next.
 *
 * The asymmetry is the whole argument: honouring a q=0 that appeared
 * anywhere can only ever make us send LESS zstd than a permissive reading
 * would. The opposite rule (last-wins) can turn an explicit refusal into an
 * accept, and the failure that produces — a body the client told us it
 * cannot decode — is the one that actually hurts a user. Between two
 * defensible readings of input that should not exist, we take the one whose
 * worst case is a missed compression opportunity.
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
static ngx_int_t
ngx_http_zstd_chain_coding_weight(const ngx_table_elt_t *ae,
    const char *coding, size_t coding_len, ngx_uint_t allow_wildcard)
{
    ngx_int_t  coding_q = -1;   /* explicit token, lowest seen, -1 = absent */
    ngx_int_t  star_q = -1;     /* "*" wildcard,   lowest seen, -1 = absent */

    for (/* void */; ae != NULL; ae = NGX_HTTP_ZSTD_AE_NEXT(ae)) {

        ngx_int_t  q;

        /*
         * Ask the single-value parser twice per line: once with the
         * wildcard suppressed, to learn this line's EXPLICIT weight only,
         * and once as the caller asked for, to learn the effective weight.
         * When the two differ the effective answer came from "*", so the
         * line contributed a wildcard weight and no explicit token.
         *
         * Doing it this way keeps ngx_http_zstd_coding_weight() untouched
         * — it is the fuzzed, extracted-into-the-unit-suite function, and
         * a second out-parameter would change the slice every one of those
         * layers links. The header field is at most a handful of short
         * lines, and this runs once per request on a path that is about to
         * compress a response body.
         */
        q = ngx_http_zstd_coding_weight(&ae->value, coding, coding_len, 0);

        if (q >= 0) {
            /* Explicit token on this line: lowest explicit weight wins. */
            if (coding_q < 0 || q < coding_q) {
                coding_q = q;
            }
            continue;
        }

        if (!allow_wildcard) {
            continue;
        }

        q = ngx_http_zstd_coding_weight(&ae->value, coding, coding_len, 1);

        if (q >= 0) {
            /* Only "*" could have produced an answer here. */
            if (star_q < 0 || q < star_q) {
                star_q = q;
            }
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
 * zstd acceptance predicate over one Accept-Encoding value — the
 * original entry point, now a thin wrapper. Semantics are unchanged:
 * NGX_OK iff the effective weight for "zstd" (explicit token, else "*"
 * wildcard) is > 0. The fuzz harness's independent reference oracle
 * asserts exactly this decision, so any behavioural drift here is a
 * fuzz failure, not just a review nit.
 *
 * SINGLE VALUE ONLY. This evaluates one Accept-Encoding field line. The
 * request path does NOT call it -- ngx_http_zstd_accepts() walks the whole
 * chained field via ngx_http_zstd_chain_coding_weight() -- but the fuzz
 * target (ci/fuzz/fuzz_accept_encoding.c) and the unit suite
 * (ci/tests/unit/test_accept_encoding.c) both link this exact body as the
 * single-value entry point, and its differential oracle is written against
 * it. ngx_inline because no module TU references it any more and a plain
 * `static` would trip -Werror=unused-function in both of them, the same
 * reason ngx_http_zstd_ok() below is inline.
 */
static ngx_inline ngx_int_t
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
     * is still a decline (the walk below returns -1).
     *
     * The whole chained field is evaluated, not just ae->value: duplicate
     * Accept-Encoding lines are one comma-joined list (RFC 9110 section
     * 5.3). See ngx_http_zstd_chain_coding_weight() for that and for the
     * duplicate-coding rule it applies.
     */
    return ngx_http_zstd_chain_coding_weight(ae, "zstd", sizeof("zstd") - 1, 1)
               > 0
               ? NGX_OK : NGX_DECLINED;
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
 * corruption on HTTP/1.1 responses. Both key and value are NUL-terminated
 * C string literals supplied by the caller.
 *
 * key/value are `const char *` PARAMETERS, not literals in this scope, so
 * ngx_str_set() must not be used here: that macro computes its length via
 * `sizeof(text) - 1`, which is only the string length when `text` is a
 * literal token at the macro's own call site. Applied to a `const char *`
 * parameter it instead yields sizeof(pointer) - 1 (7 on a 64-bit build) --
 * every pushed header key/value here was truncated/overrun to 7 bytes
 * regardless of the real string length, which silently broke every caller
 * of this helper. Use ngx_strlen() on the parameter instead.
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
    h->key.len = ngx_strlen(key);
    h->key.data = (u_char *) key;
    h->value.len = ngx_strlen(value);
    h->value.data = (u_char *) value;

    return NGX_OK;
}


static ngx_inline ngx_uint_t
ngx_http_zstd_vary_has_token(ngx_http_request_t *r, const char *token,
    size_t token_len)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

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

        if (h[i].hash == 0
            || h[i].key.len != sizeof("Vary") - 1
            || ngx_strncasecmp(h[i].key.data, (u_char *) "Vary",
                               sizeof("Vary") - 1) != 0)
        {
            continue;
        }

        {
            u_char  *end, *p, *start;

            p = h[i].value.data;
            end = p + h[i].value.len;

            while (p < end) {
                while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
                    p++;
                }

                start = p;
                while (p < end && *p != ',') {
                    p++;
                }

                while (p > start && (p[-1] == ' ' || p[-1] == '\t')) {
                    p--;
                }

                if ((size_t) (p - start) == token_len
                    && ngx_strncasecmp(start, (u_char *) token,
                                       token_len) == 0)
                {
                    return 1;
                }

                while (p < end && *p != ',') {
                    p++;
                }
            }
        }
    }

    return 0;
}


/*
 * Same walk as ngx_http_zstd_vary_has_token(), but checks for two tokens
 * in one pass over r->headers_out.headers instead of two. Used only by
 * ngx_http_zstd_vary_dcz(), whose two calls are adjacent and always want
 * both answers -- folding them avoids a second full header-list walk plus
 * a second per-Vary-line comma-token sub-scan.
 */
static ngx_inline void
ngx_http_zstd_vary_has_two_tokens(ngx_http_request_t *r,
    const char *token_a, size_t token_a_len,
    const char *token_b, size_t token_b_len,
    ngx_uint_t *has_a, ngx_uint_t *has_b)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    *has_a = 0;
    *has_b = 0;

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

        if (h[i].hash == 0
            || h[i].key.len != sizeof("Vary") - 1
            || ngx_strncasecmp(h[i].key.data, (u_char *) "Vary",
                               sizeof("Vary") - 1) != 0)
        {
            continue;
        }

        {
            u_char  *end, *p, *start;

            p = h[i].value.data;
            end = p + h[i].value.len;

            while (p < end) {
                while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
                    p++;
                }

                start = p;
                while (p < end && *p != ',') {
                    p++;
                }

                while (p > start && (p[-1] == ' ' || p[-1] == '\t')) {
                    p--;
                }

                if (!*has_a
                    && (size_t) (p - start) == token_a_len
                    && ngx_strncasecmp(start, (u_char *) token_a,
                                       token_a_len) == 0)
                {
                    *has_a = 1;
                }

                if (!*has_b
                    && (size_t) (p - start) == token_b_len
                    && ngx_strncasecmp(start, (u_char *) token_b,
                                       token_b_len) == 0)
                {
                    *has_b = 1;
                }

                if (*has_a && *has_b) {
                    return;
                }

                while (p < end && *p != ',') {
                    p++;
                }
            }
        }
    }
}


/*
 * Add the two request-header dimensions that can select a dcz response.
 * The static content handler and the response filter can both reach this
 * helper on one request. Detect tokens across every active Vary field, so
 * repeated calls and fields flattened or reordered by another filter remain
 * duplicate-free.
 *
 * The two tokens are looked up together in a single header-list walk
 * (ngx_http_zstd_vary_has_two_tokens()) rather than as two independent
 * calls to ngx_http_zstd_vary_has_token() -- the two lookups are always
 * wanted together here, so paying for the walk and the per-line
 * comma-token scan twice was redundant.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_vary_dcz(ngx_http_request_t *r)
{
    ngx_uint_t  has_available_dictionary, has_sec_fetch_site;

    ngx_http_zstd_vary_has_two_tokens(
        r, "Available-Dictionary", sizeof("Available-Dictionary") - 1,
        "Sec-Fetch-Site", sizeof("Sec-Fetch-Site") - 1,
        &has_available_dictionary, &has_sec_fetch_site);

    if (has_available_dictionary && has_sec_fetch_site) {
        return NGX_OK;
    }

    if (has_available_dictionary) {
        return ngx_http_zstd_push_header(r, "Vary", "Sec-Fetch-Site");
    }

    if (has_sec_fetch_site) {
        return ngx_http_zstd_push_header(r, "Vary", "Available-Dictionary");
    }

    return ngx_http_zstd_push_header(
        r, "Vary", "Available-Dictionary, Sec-Fetch-Site");
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
 * Repeated calls are safe because the response-header scan above makes
 * this helper idempotent. Call it only on a path that is genuinely
 * Accept-Encoding-dependent. "zstd_static always" normally does not call
 * it because that mode ignores Accept-Encoding; the explicit dictionary
 * bypass is the exception, since its routing predicate reads that field.
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
    ngx_http_core_loc_conf_t  *clcf;

    r->gzip_vary = 1;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf != NULL && clcf->gzip_vary) {
        /* nginx's header filter emits the line from r->gzip_vary */
        return NGX_OK;
    }

    if (ngx_http_zstd_vary_has_token(
            r, "Accept-Encoding", sizeof("Accept-Encoding") - 1))
    {
        return NGX_OK;
    }

    return ngx_http_zstd_push_header(r, "Vary", "Accept-Encoding");
}


#endif /* NGX_HTTP_ZSTD_COMMON_H */
