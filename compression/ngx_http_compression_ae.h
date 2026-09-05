/*
 * Accept-Encoding VALUE parsing per RFC 9110 §12.5.3 / §12.4.2 —
 * lifted from nginx-zstd-module's ngx_http_zstd_common.h, where the
 * walker was already token-parameterized and fuzz-hardened
 * (differential oracle; quoted-string, stray-comma, malformed-qvalue
 * cases). Only the name prefix changed. Strictly length-bounded,
 * never NUL-reliant.
 *
 * Scope: ngx_http_compression_coding_weight() below parses ONE field
 * line; the request-level combination of every AE line (RFC 9110 §5.3
 * comma-joining, parent #215/#275) lives in
 * ngx_http_compression_request_coding_weight() at the bottom, which
 * composes this parser per line without reaching inside one. The defer
 * story that used to hold this at first-line-only is resolved: an
 * expressed whole-field gzip refusal VETOES core gzip through its own
 * gzip_tested/gzip_ok flags, and the one remaining first-line
 * asymmetry (an allowance visible only on a later line) fails closed
 * to identity in core's own read — never a wrong compression.
 *
 * Weight semantics: an explicit token always decides (even q=0, which
 * then overrides a permissive "*"); with no explicit token the "*"
 * wildcard applies only when the caller allows it — base codings do,
 * dictionary codings (dcz/dcb) must not, since only a client that
 * actually holds the dictionary can decode them.
 */

#ifndef NGX_HTTP_COMPRESSION_AE_H
#define NGX_HTTP_COMPRESSION_AE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static u_char *
ngx_http_compression_skip_quoted(u_char *p, u_char *end)
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
 * the accumulated milli-units contribution. Fixed at three guarded steps
 * with literal weights 100/10/1 (parent #211/#213) instead of a loop
 * counting a runtime scale down: each step is behaviour-identical to one
 * loop iteration, and a fourth digit byte is deliberately left
 * unconsumed for the caller's trailing-junk check to reject — the same
 * contract the loop's `scale > 0` guard enforced.
 */
static ngx_inline ngx_int_t
ngx_http_compression_parse_q_fraction(u_char *end, u_char **p)
{
    /* ngx_int_t so each digit*weight product widens before the add */
    ngx_int_t   frac = 0;
    u_char     *q = *p;

    if (q < end && *q >= '0' && *q <= '9') {
        frac += (*q - '0') * 100;
        q++;

        if (q < end && *q >= '0' && *q <= '9') {
            frac += (*q - '0') * 10;
            q++;

            if (q < end && *q >= '0' && *q <= '9') {
                frac += *q - '0';
                q++;
            }
        }
    }

    *p = q;
    return frac;
}


static ngx_int_t
ngx_http_compression_eval_qvalue(ngx_str_t *ae, u_char *p)
{
    u_char     *end = ae->data + ae->len;
    ngx_int_t   q = 1000;   /* no q parameter → q=1 */
    ngx_int_t   q_seen = 0;

    while (p < end && *p == ';') {

        u_char     *nstart, *nend;
        ngx_int_t   is_q;

        p++;    /* skip ';' */

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        nstart = p;
        while (p < end
               && *p != '=' && *p != ';' && *p != ','
               && *p != ' ' && *p != '\t')
        {
            p++;
        }
        nend = p;

        /*
         * RFC 9110 has no empty-parameter production, so "zstd;;q=1"
         * is malformed rather than "a skipped parameter followed by
         * q=1". Reject it instead of silently resolving the element
         * to q=1. (Parent #142; core gzip refuses the gzip twin, so
         * accepting it here would split the defer decision.)
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
                        q += ngx_http_compression_parse_q_fraction(end, &p);
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

                if (p < end
                    && *p != ' ' && *p != '\t' && *p != ';' && *p != ',')
                {
                    return -1;          /* trailing junk (q=1x, q=0.0001) */
                }

            } else {
                while (p < end && *p != ';' && *p != ',') {
                    if (*p == '"') {
                        p = ngx_http_compression_skip_quoted(p, end);
                    } else {
                        p++;
                    }
                }
            }

        } else {
            if (is_q) {
                return -1;              /* "q" with no "=value" */
            }
        }

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        if (p < end && *p != ';' && *p != ',') {
            return -1;
        }
    }

    return q;
}


/*
 * Effective weight for `coding` in milli-units (0..1000), or -1 when
 * the header expresses no preference for it at all.
 *
 * The _ex form also reports the two accumulated weights it computed
 * anyway (parent #315): *explicit_q is the latest explicit `coding`
 * token's weight and *star_q_out the latest "*" weight, each -1 when
 * that form is absent. The chain walker below needs both to compose
 * duplicate field lines, and taking them from one pass keeps it from
 * parsing the same line a second time just to learn which of the two
 * produced the answer. The return value is exactly the precedence rule
 * applied to them. The parent keeps a single-value wrapper without the
 * out-params for its fuzz oracle; this module has no caller for one
 * (every negotiation goes through the field walkers below), so only
 * the _ex form exists here and the name stays aligned with the parent.
 */
static ngx_int_t
ngx_http_compression_coding_weight_ex(ngx_str_t *ae, ngx_str_t *coding,
    ngx_uint_t allow_wildcard, ngx_int_t *explicit_q, ngx_int_t *star_q_out)
{
    u_char     *p   = ae->data;
    u_char     *end = ae->data + ae->len;
    ngx_int_t   coding_q = -1;
    ngx_int_t   star_q = -1;

    while (p < end) {

        u_char     *tok, *name_end;
        ngx_int_t   is_coding, is_star, q;

        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
            p++;
        }
        if (p >= end) {
            break;
        }

        tok = p;
        while (p < end
               && *p != ' ' && *p != '\t' && *p != ';' && *p != ','
               && *p != '"')
        {
            p++;
        }
        name_end = p;

        is_coding = ((size_t) (name_end - tok) == coding->len
                     && ngx_strncasecmp(tok, coding->data,
                                        coding->len) == 0);
        is_star = (name_end - tok == 1 && tok[0] == '*');

        /* Step over any OWS between the name and its ';' or ','. */
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        /*
         * Only ';' (parameters), ',' (next element) or end of field
         * may follow a coding name. RFC 9110 12.5.3 makes `codings` a
         * token, so anything else means this element is not the
         * coding it looked like: `zstd"x` and `zstd "x` advertise
         * nothing, and neither does `zstd x`. (Parent #142.) Core
         * gzip's ngx_http_gzip_accept_encoding() applies the same
         * rule, so accepting these here splits the defer decision:
         * "gzip x, zstd" would defer to core gzip on the malformed
         * gzip element, core gzip declines it, and a client that
         * validly offered zstd gets identity.
         *
         * The check must sit AFTER the OWS skip: the name scan stops
         * on OWS as well as on '"', so testing the stopping byte
         * alone catches `zstd"x` and misses everything hiding behind
         * a space. The quote-aware element-skip below still swallows
         * the rest of the element.
         */
        if (p < end && *p != ';' && *p != ',') {
            is_coding = 0;
            is_star = 0;
        }

        q = 1000;
        if (p < end && *p == ';') {
            q = ngx_http_compression_eval_qvalue(ae, p);
        }

        if (q >= 0) {
            if (is_coding) {
                coding_q = q;
            } else if (is_star) {
                star_q = q;
            }
        }

        while (p < end && *p != ',') {
            if (*p == '"') {
                p = ngx_http_compression_skip_quoted(p, end);
            } else {
                p++;
            }
        }
    }

    *explicit_q = coding_q;
    *star_q_out = star_q;

    if (coding_q >= 0) {
        return coding_q;
    }
    if (allow_wildcard && star_q >= 0) {
        return star_q;
    }
    return -1;
}


/*
 * Vary: Accept-Encoding, emitted BY CONSTRUCTION on any response whose
 * representation was negotiated on Accept-Encoding — parent #163's
 * hardening, ported. The hazard it closes: r->gzip_vary alone is only
 * a REQUEST for the header. ngx_http_header_filter_module honours it
 * solely under "gzip_vary on" and CLEARS the flag otherwise, so the
 * default "gzip_vary off" used to ship a negotiated compressed body
 * with no Vary at all — and a shared cache would then hand the
 * zstd/brotli representation to a client that sent no matching
 * Accept-Encoding, i.e. an undecodable body. That correctness property
 * belonged to a directive this module does not own; now it does not.
 *
 * With the gzip module we still set r->gzip_vary (other modules read
 * the flag — e.g. a Vary-flattening filter that keys on it alone), then
 * defer to nginx when the directive is on and emit our own line when it
 * is off. The two emitters are mutually exclusive, so exactly one line
 * results in every build/directive combination. The dedup scan guards
 * the case where a preceding filter already pushed the field.
 *
 * Header-static like the parser above — since the filter/static MODULE
 * SPLIT each module carries its own copy, so neither .so links symbols
 * from the other (the static module links nothing at all).
 */
static ngx_inline ngx_int_t
ngx_http_compression_vary(ngx_http_request_t *r)
{
    ngx_uint_t        i;
    ngx_table_elt_t  *v, *h;
    ngx_list_part_t  *part;
#if (NGX_HTTP_GZIP)
    ngx_http_core_loc_conf_t  *clcf;

    r->gzip_vary = 1;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf != NULL && clcf->gzip_vary) {
        /* nginx's header filter emits the line from r->gzip_vary */
        return NGX_OK;
    }
#endif

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
             * comma-separated tokens (parent #200 row n11): an
             * exact-value compare misses an origin's
             * "Vary: Accept-Encoding, Cookie" and doubles the token
             * on a second line. Trim OWS per token, compare
             * case-insensitively (the values are header names).
             */
            u_char  *p = h[i].value.data;
            u_char  *end = h[i].value.data + h[i].value.len;

            while (p < end) {
                u_char  *tstart, *tend;

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
                       && (*(tend - 1) == ' ' || *(tend - 1) == '\t'))
                {
                    tend--;
                }

                if (tend - tstart == sizeof("Accept-Encoding") - 1
                    && ngx_strncasecmp(tstart,
                                       (u_char *) "Accept-Encoding",
                                       sizeof("Accept-Encoding") - 1) == 0)
                {
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
    v->next = NULL;
    ngx_str_set(&v->key, "Vary");
    ngx_str_set(&v->value, "Accept-Encoding");
    return NGX_OK;
}


/* the request's FIRST Accept-Encoding header: parsed field with the
 * gzip module, list walk without. Presence/Vary decisions only — the
 * negotiation itself reads the WHOLE field via
 * ngx_http_compression_request_coding_weight() below (parent #215/#275:
 * RFC 9110 §5.3 makes repeated field lines one comma-joined field) */
static ngx_inline ngx_table_elt_t *
ngx_http_compression_ae_header(ngx_http_request_t *r)
{
#if (NGX_HTTP_GZIP)
    return r->headers_in.accept_encoding;
#else
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

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

        if (h[i].key.len == sizeof("Accept-Encoding") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Accept-Encoding",
                               sizeof("Accept-Encoding") - 1) == 0)
        {
            return &h[i];
        }
    }

    return NULL;
#endif
}


/*
 * Effective weight for `coding` across the WHOLE Accept-Encoding field
 * — every repeated field line, not just the first (parent #215/#275).
 * RFC 9110 §5.3 makes a repeated list-valued field identical to the
 * single field whose value is the lines joined in order with commas, so
 * "Accept-Encoding: gzip" + "Accept-Encoding: zstd" IS "gzip, zstd".
 *
 * Composition, not a second parser: the single-value parser above is
 * asked once per line through its _ex form, which hands back the
 * line's EXPLICIT weight and its "*" weight separately (parent #315;
 * the earlier shape asked twice, wildcard-suppressed then as-asked, and
 * so re-scanned every line that named no explicit token, the common
 * case). The latest explicit token wins across lines exactly as it
 * does within one line, and the wildcard stays subordinate to any
 * explicit token anywhere in the field. The single-value parser's
 * lineage is untouched, and this function never reaches inside one
 * line.
 */
/*
 * One field line folded into the field-wide accumulators, and the
 * final precedence over them. The two collections below (the ->next
 * chain with gzip, the raw header list without) may differ per build
 * shape; the accumulation and precedence MUST not — a private copy in
 * each walker is how the build shapes' negotiation drifts apart with
 * CI exercising only one of them per job.
 */
static ngx_inline void
ngx_http_compression_fold_line_weight(ngx_str_t *value, ngx_str_t *coding,
    ngx_uint_t allow_wildcard, ngx_int_t *coding_q, ngx_int_t *star_q)
{
    ngx_int_t  line_coding_q, line_star_q;

    (void) ngx_http_compression_coding_weight_ex(value, coding,
                                                 allow_wildcard,
                                                 &line_coding_q,
                                                 &line_star_q);

    if (line_coding_q >= 0) {
        *coding_q = line_coding_q;  /* comma-joined in received order */
        return;
    }

    if (allow_wildcard && line_star_q >= 0) {
        *star_q = line_star_q;
    }
}


static ngx_inline ngx_int_t
ngx_http_compression_field_weight(ngx_int_t coding_q, ngx_int_t star_q,
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


static ngx_inline ngx_int_t
ngx_http_compression_chain_coding_weight(const ngx_table_elt_t *ae,
    ngx_str_t *coding, ngx_uint_t allow_wildcard)
{
    ngx_int_t  coding_q, star_q;

    coding_q = -1;      /* latest explicit token, -1 = absent */
    star_q = -1;        /* latest "*" wildcard, -1 = absent */

    for ( /* void */ ; ae != NULL;
          ae = (const ngx_table_elt_t *) ae->next)
    {
        ngx_http_compression_fold_line_weight((ngx_str_t *) &ae->value,
                                              coding, allow_wildcard,
                                              &coding_q, &star_q);
    }

    return ngx_http_compression_field_weight(coding_q, star_q,
                                             allow_wildcard);
}


/*
 * The request-level entry point. With the gzip module,
 * headers_in.accept_encoding heads the ->next chain nginx (>= 1.23,
 * this module's floor) builds for repeated known headers. WITHOUT the
 * gzip module that field does not exist and nothing chains the lines,
 * so the list is walked directly — the same accumulation, a different
 * collection (the parent's #275 legacy shape, needed here for a
 * different reason: unprocessed headers, not old nginx).
 */
static ngx_inline ngx_int_t
ngx_http_compression_request_coding_weight(ngx_http_request_t *r,
    ngx_str_t *coding, ngx_uint_t allow_wildcard)
{
#if (NGX_HTTP_GZIP)
    return ngx_http_compression_chain_coding_weight(
               r->headers_in.accept_encoding, coding, allow_wildcard);
#else
    ngx_uint_t        i;
    ngx_int_t         coding_q, star_q;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    coding_q = -1;
    star_q = -1;

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

        if (h[i].key.len != sizeof("Accept-Encoding") - 1
            || ngx_strncasecmp(h[i].key.data, (u_char *) "Accept-Encoding",
                               sizeof("Accept-Encoding") - 1) != 0)
        {
            continue;
        }

        ngx_http_compression_fold_line_weight(&h[i].value, coding,
                                              allow_wildcard,
                                              &coding_q, &star_q);
    }

    return ngx_http_compression_field_weight(coding_q, star_q,
                                             allow_wildcard);
#endif
}


#endif /* NGX_HTTP_COMPRESSION_AE_H */
