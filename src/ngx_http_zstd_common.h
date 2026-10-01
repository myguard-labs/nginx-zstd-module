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


#include "ngx_http_zstd_accept_encoding.h"


/*
 * zstd acceptance predicate over one Accept-Encoding value — the
 * original entry point, now a thin wrapper. Semantics are unchanged:
 * NGX_OK iff the effective weight for "zstd" (explicit token, else "*"
 * wildcard) is > 0. The fuzz harness's independent reference oracle
 * asserts exactly this decision, so any behavioural drift here is a
 * fuzz failure, not just a review nit.
 *
 * SINGLE VALUE ONLY. This evaluates one Accept-Encoding field line. The
 * request path does NOT call it -- ngx_http_zstd_accepts() evaluates the
 * complete request field via ngx_http_zstd_request_coding_weight() -- but
 * the fuzz target (ci/fuzz/fuzz_accept_encoding.c) and the unit suite
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
static ngx_inline ngx_int_t
ngx_http_zstd_accepts(ngx_http_request_t *r)
{
    if (r != r->main) {
        return NGX_DECLINED;
    }

    /*
     * A "*" wildcard (one byte) can make zstd acceptable, so the old
     * "shorter than 'zstd'" fast-reject is no longer valid; an empty value
     * is still a decline (the walk below returns -1).
     *
     * The whole field is evaluated: linked duplicate lines on nginx >= 1.23,
     * and the complete headers list on older supported nginx. RFC 9110
     * section 5.3 makes them one comma-joined list.
     */
    return ngx_http_zstd_request_coding_weight(r, "zstd", sizeof("zstd") - 1, 1)
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


/*
 * token_b/has_b and token_c/has_c are each either both NULL or both
 * non-NULL, independently of each other (so a 1-, 2- or 3-token walk is
 * one function).
 */
static ngx_inline void
ngx_http_zstd_vary_find_tokens(ngx_http_request_t *r,
    const char *token_a, size_t token_a_len,
    const char *token_b, size_t token_b_len,
    const char *token_c, size_t token_c_len,
    ngx_uint_t *has_a, ngx_uint_t *has_b, ngx_uint_t *has_c)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    *has_a = 0;
    if (has_b != NULL) {
        *has_b = 0;
    }
    if (has_c != NULL) {
        *has_c = 0;
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

        if (h[i].hash == 0
            || h[i].key.len != sizeof("Vary") - 1
            || ngx_strncasecmp(h[i].key.data, (u_char *) "Vary",
                               sizeof("Vary") - 1) != 0)
        {
            continue;
        }

        {
            u_char  *end, *p, *start, *tok_end;

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

                /*
                 * `p` is the untrimmed token end (the comma, or `end`);
                 * keep it so the tail advance below can reuse it instead
                 * of re-walking from the OWS-trimmed pointer to find the
                 * same comma again.
                 */
                tok_end = p;

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

                if (has_b != NULL && !*has_b
                    && (size_t) (p - start) == token_b_len
                    && ngx_strncasecmp(start, (u_char *) token_b,
                                       token_b_len) == 0)
                {
                    *has_b = 1;
                }

                if (has_c != NULL && !*has_c
                    && (size_t) (p - start) == token_c_len
                    && ngx_strncasecmp(start, (u_char *) token_c,
                                       token_c_len) == 0)
                {
                    *has_c = 1;
                }

                if (*has_a && (has_b == NULL || *has_b)
                             && (has_c == NULL || *has_c))
                {
                    return;
                }

                p = tok_end;
            }
        }
    }
}


static ngx_inline ngx_uint_t
ngx_http_zstd_vary_has_token(ngx_http_request_t *r, const char *token,
    size_t token_len)
{
    ngx_uint_t  found;

    ngx_http_zstd_vary_find_tokens(r, token, token_len, NULL, 0, NULL, 0,
                                   &found, NULL, NULL);

    return found;
}


/*
 * Add the two request-header dimensions that can select a dcz response.
 * The static content handler and the response filter can both reach this
 * helper on one request. Detect tokens across every active Vary field, so
 * repeated calls and fields flattened or reordered by another filter remain
 * duplicate-free.
 *
 * The two tokens are looked up together in a single header-list walk
 * (ngx_http_zstd_vary_find_tokens()) rather than as two independent
 * calls to ngx_http_zstd_vary_has_token() -- the two lookups are always
 * wanted together here, so paying for the walk and the per-line
 * comma-token scan twice was redundant.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_vary_dcz(ngx_http_request_t *r)
{
    ngx_uint_t  has_available_dictionary, has_sec_fetch_site;

    ngx_http_zstd_vary_find_tokens(
        r, "Available-Dictionary", sizeof("Available-Dictionary") - 1,
        "Sec-Fetch-Site", sizeof("Sec-Fetch-Site") - 1,
        NULL, 0,
        &has_available_dictionary, &has_sec_fetch_site, NULL);

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


/*
 * ngx_http_zstd_vary_ae_dcz()
 *
 * Fused replacement for the ngx_http_zstd_vary_accept_encoding() +
 * ngx_http_zstd_vary_dcz() pair at call sites that always want both.
 * The static module's dict_bypass path has that shape; the filter module's
 * intervening bypass return deliberately keeps the helpers separate.
 * Both original helpers walk r->headers_out.headers once via
 * ngx_http_zstd_vary_find_tokens() and comma-split every Vary
 * value they find; calling them back to back pays for that walk and
 * per-line token scan twice. This helper does it once, for all three
 * tokens ("Accept-Encoding", "Available-Dictionary", "Sec-Fetch-Site"),
 * then pushes exactly the header lines the two original calls would have
 * pushed -- same duplicate-safety, same push shapes, same
 * cache-correctness reasoning (RFC 9842 SS8.3 dictionary/origin binding,
 * the shared-cache poisoning argument in
 * ngx_http_zstd_vary_accept_encoding()'s comment above and in
 * ngx_http_zstd_vary_dcz()'s comment). See both for the full rationale;
 * this comment only covers what fusing changes.
 *
 * `want_dcz` gates the Available-Dictionary/Sec-Fetch-Site half exactly
 * as the callers' own "any dcz dictionaries configured?" guard does
 * today -- pass 0 from a location with no dcz_dicts configured so it
 * does not start emitting Vary tokens for a negotiation that location
 * never performs. Passing the guard in, rather than moving it here,
 * keeps that decision at the call site where the configuration lives.
 *
 * r->gzip_vary is set unconditionally, before any return, exactly as in
 * ngx_http_zstd_vary_accept_encoding() -- other modules (notably
 * ngx_http_compression_vary_filter_module) read the flag regardless of
 * whether this call ends up pushing a header line itself.
 *
 * Caller ordering requirement: run this AFTER any header line the
 * caller itself pushes onto r->headers_out.headers that should count as
 * "already present" to the walk (e.g. filter_module's zstd_bypass_vary
 * push) -- the walk only sees lines already in the list when it starts.
 *
 * Returns NGX_OK, or NGX_ERROR when a header-list allocation fails.
 *
 * ngx_inline for the same reason as the helpers above: this header is
 * included by TUs that never call it (the fuzz harness), and a plain
 * `static` definition trips -Werror=unused-function there.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_vary_ae_dcz(ngx_http_request_t *r, ngx_uint_t want_dcz)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_uint_t                 has_ae, has_available_dictionary,
                                has_sec_fetch_site;
    ngx_uint_t                 need_ae;

    r->gzip_vary = 1;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    need_ae = (clcf == NULL || !clcf->gzip_vary);

    if (!need_ae && !want_dcz) {
        return NGX_OK;
    }

    if (need_ae) {
        ngx_http_zstd_vary_find_tokens(
            r,
            "Accept-Encoding", sizeof("Accept-Encoding") - 1,
            want_dcz ? "Available-Dictionary" : NULL,
            want_dcz ? sizeof("Available-Dictionary") - 1 : 0,
            want_dcz ? "Sec-Fetch-Site" : NULL,
            want_dcz ? sizeof("Sec-Fetch-Site") - 1 : 0,
            &has_ae,
            want_dcz ? &has_available_dictionary : NULL,
            want_dcz ? &has_sec_fetch_site : NULL);

    } else {
        has_ae = 1;
        ngx_http_zstd_vary_find_tokens(
            r,
            "Available-Dictionary", sizeof("Available-Dictionary") - 1,
            "Sec-Fetch-Site", sizeof("Sec-Fetch-Site") - 1,
            NULL, 0,
            &has_available_dictionary, &has_sec_fetch_site, NULL);
    }

    if (need_ae && !has_ae) {
        if (ngx_http_zstd_push_header(r, "Vary", "Accept-Encoding")
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (!want_dcz) {
        return NGX_OK;
    }

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


#endif /* NGX_HTTP_ZSTD_COMMON_H */
