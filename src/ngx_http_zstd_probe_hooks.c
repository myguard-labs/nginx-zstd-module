/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_http_zstd_probe_hooks.c -- nginx-module-testkit zoneless probe glue
 * for the zstd filter module (CI only).
 *
 * See ngx_http_zstd_probe_hooks.h. Everything here is compiled out unless
 * NGX_TEST_HARNESS is defined.
 *
 * http-zstd has no shm zone, so state that would normally live in shared
 * memory (see ngx_test_probe.h's fault_set comment) lives in process
 * globals instead. That is correct here for a different reason than the
 * generic "single worker in every prober conf" note: the counters below
 * are bumped by the SAME worker that later serves /__probe only when the
 * test topology pins one worker (worker_processes 1, or a single kept-alive
 * connection) -- exactly the constraint ngx_test_probe.h's
 * fault_set_global documents for its own counter. We inherit it rather
 * than re-deriving it.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifdef NGX_TEST_HARNESS

#include "ngx_test_probe.h"
#include "ngx_http_zstd_probe_hooks.h"
#include "ngx_http_zstd_common.h"

/*
 * Mirrors just the fields of ngx_http_zstd_ctx_t this file needs to read at
 * probe-render time (free chain head and out_buf). Defined locally rather
 * than pulled from the filter's own (non-exported, file-static) typedef:
 * the filter module passes us the live pointer via
 * ngx_http_zstd_probe_note_ctx(), typed as the opaque
 * `struct ngx_http_zstd_ctx_s *` from the header, and this file only ever
 * reads through it to render JSON -- it never assumes the two structs are
 * layout-compatible.
 *
 * Actually: since ngx_http_zstd_ctx_t is a plain typedef (not a tag'd
 * struct) local to the filter TU, we take the fields we need as explicit
 * parameters from the call site instead of trying to peek through an
 * opaque pointer. See the note_ctx() call site in the filter for the
 * field values passed.
 */

/* Running per-process counters, bumped inline at each call site. */
static ngx_uint_t  ngx_http_zstd_probe_chain_links;
static ngx_uint_t  ngx_http_zstd_probe_bufs_allocated;

/* Snapshot of the most recently observed request's ctx state, taken by
 * ngx_http_zstd_probe_note_ctx(). Observational only -- see the
 * single-worker caveat above the includes. -1 (via the "have" flag) until
 * the first request populates it. */
static ngx_uint_t  ngx_http_zstd_probe_free_links;
static ngx_uint_t  ngx_http_zstd_probe_out_buf_present;
static size_t      ngx_http_zstd_probe_out_buf_size;
static ngx_uint_t  ngx_http_zstd_probe_have_ctx;

/*
 * Fault-injection state. The armed value is the raw `nth` the testkit
 * parsed, still carrying its outcome encoding (see
 * NGX_HTTP_ZSTD_PROBE_FAULT_ZERO_BASE in the header); -1 means disarmed,
 * which is what fault_set_global stores for any negative value.
 *
 * PROCESS GLOBALS, DELIBERATELY. These are armed by the request that hits
 * /__probe and tripped by a LATER request that runs the filter, so the two
 * must land in the same worker. Every prober conf for this module runs a
 * single worker (worker_processes 1) precisely so that holds -- the same
 * constraint ngx_test_probe.h documents for its own fault_set_global
 * counter, inherited here rather than re-derived. There is no shm zone in
 * this module to put them in even if we wanted one (verified: zero
 * ngx_shared_memory_add / shm_zone in src/), which is why the zoneless
 * hook family is registered at all.
 */
static ngx_int_t  ngx_http_zstd_probe_fault_codec_nth     = -1;
static ngx_int_t  ngx_http_zstd_probe_fault_codec_end_nth = -1;

/*
 * Per-site event counters, counting ZSTD_compressStream2 calls seen since
 * process start. Same single-worker rationale as the armed values above.
 * These advance on EVERY call, armed or not, so that an arm issued
 * mid-stream still counts from a well-defined origin rather than from
 * whenever the arm happened to land.
 */
static ngx_uint_t  ngx_http_zstd_probe_codec_calls;
static ngx_uint_t  ngx_http_zstd_probe_codec_end_calls;

static ngx_int_t ngx_http_zstd_probe_handler(ngx_http_request_t *r);


void
ngx_http_zstd_probe_note_chain_link(void)
{
    ngx_http_zstd_probe_chain_links++;
}


void
ngx_http_zstd_probe_note_buf_alloc(void)
{
    ngx_http_zstd_probe_bufs_allocated++;
}


/*
 * Called by the filter with the request's live ctx (see the header for
 * why we do not dereference a typedef this file does not own). The filter
 * passes the free-chain length it has already walked and the out_buf
 * size/presence, so this file stays independent of ngx_http_zstd_ctx_t's
 * private layout.
 */
void
ngx_http_zstd_probe_note_ctx_state(ngx_uint_t free_links,
    ngx_uint_t out_buf_present, size_t out_buf_size)
{
    ngx_http_zstd_probe_free_links = free_links;
    ngx_http_zstd_probe_out_buf_present = out_buf_present;
    ngx_http_zstd_probe_out_buf_size = out_buf_size;
    ngx_http_zstd_probe_have_ctx = 1;
}


/*
 * Codec fault decision. See the header for the outcome encoding and for
 * why the outcome rides inside `nth` instead of a second query key.
 *
 * Advances the site's event counter, then answers whether THIS call is
 * the armed nth. One-shot by construction: matching is `==`, so a site
 * armed at nth=1 trips on exactly one call and every later call in the
 * process is unarmed again -- a test does not have to disarm to keep the
 * rest of its traffic clean.
 *
 * Unarmed cost: one increment and one compare against -1 that predicts
 * perfectly, before any of the decode arithmetic runs.
 */
ngx_http_zstd_probe_codec_outcome_e
ngx_http_zstd_probe_codec_fault(ngx_uint_t is_end)
{
    ngx_int_t   armed;
    ngx_uint_t  seq;

    if (is_end) {
        armed = ngx_http_zstd_probe_fault_codec_end_nth;
        seq = ++ngx_http_zstd_probe_codec_end_calls;

    } else {
        armed = ngx_http_zstd_probe_fault_codec_nth;
        seq = ++ngx_http_zstd_probe_codec_calls;
    }

    if (armed < 0) {
        /* The overwhelmingly common case: nothing armed for this site. */
        return NGX_HTTP_ZSTD_PROBE_CODEC_NONE;
    }

    if (armed >= NGX_HTTP_ZSTD_PROBE_FAULT_ZERO_BASE) {

        if ((ngx_uint_t) (armed - NGX_HTTP_ZSTD_PROBE_FAULT_ZERO_BASE) != seq) {
            return NGX_HTTP_ZSTD_PROBE_CODEC_NONE;
        }

        return NGX_HTTP_ZSTD_PROBE_CODEC_ZERO;
    }

    if ((ngx_uint_t) armed != seq) {
        return NGX_HTTP_ZSTD_PROBE_CODEC_NONE;
    }

    return NGX_HTTP_ZSTD_PROBE_CODEC_ERROR;
}


/*
 * module_render hook: append this module's zone-independent counters to
 * the top-level "module" object. ngx_test_probe_render_module() has
 * already written the opening `,"module":{` before calling this hook, so
 * (unlike the zone-addressed zone_render) there is NO leading comma here;
 * must NOT close the brace either. Bounded against `last`.
 */
static u_char *
ngx_http_zstd_probe_module_render(u_char *buf, u_char *last)
{
    buf = ngx_slprintf(buf, last,
                        "\"chain_links_allocated\":%ui"
                        ",\"buffers_allocated\":%ui",
                        ngx_http_zstd_probe_chain_links,
                        ngx_http_zstd_probe_bufs_allocated);

    if (ngx_http_zstd_probe_have_ctx) {
        buf = ngx_slprintf(buf, last,
                            ",\"free_chain_links\":%ui"
                            ",\"out_buf\":{\"present\":%d,\"size\":%uz}",
                            ngx_http_zstd_probe_free_links,
                            (int) ngx_http_zstd_probe_out_buf_present,
                            ngx_http_zstd_probe_out_buf_size);
    } else {
        buf = ngx_slprintf(buf, last,
                            ",\"free_chain_links\":null"
                            ",\"out_buf\":null");
    }

    return buf;
}


/*
 * fault_set_global hook: zstd wires no SLAB/PALLOC/TEMPFILE/ACCEPT
 * injection points -- decline those. CODEC/CODEC_END are stored raw,
 * outcome encoding and all; ngx_http_zstd_probe_codec_fault() decodes
 * them at the single ZSTD_compressStream2 call site in the filter.
 *
 * The stored value is not range-checked here on purpose: the testkit's
 * parser has already bounded it to +/- 4 digits, and an nth that names an
 * event this process never reaches is a test that arms nothing, not an
 * error to report. Anything negative disarms.
 */
static ngx_int_t
ngx_http_zstd_probe_fault_set_global(ngx_test_probe_fault_e fault,
    ngx_int_t nth)
{
    switch (fault) {

    case NGX_TEST_PROBE_FAULT_CODEC:
        ngx_http_zstd_probe_fault_codec_nth = nth;
        return NGX_OK;

    case NGX_TEST_PROBE_FAULT_CODEC_END:
        ngx_http_zstd_probe_fault_codec_end_nth = nth;
        return NGX_OK;

    case NGX_TEST_PROBE_FAULT_SLAB:
    case NGX_TEST_PROBE_FAULT_PALLOC:
    case NGX_TEST_PROBE_FAULT_TEMPFILE:
    case NGX_TEST_PROBE_FAULT_ACCEPT:
    default:
        /* Not implemented by this module: refuse, same as no hook at all. */
        return NGX_DECLINED;
    }
}


/*
 * THIS STRUCT IS INITIALISED POSITIONALLY. Never append a member here --
 * ngx_test_probe_module_hooks_t is exactly two function pointers today and
 * this repo builds under -Wextra -Werror, which turns an appended member
 * into -Wmissing-field-initializers, a build failure, in every consumer
 * that initialises it positionally (this one included). If a future testkit
 * version needs more from a zoneless module, that is a THIRD struct with
 * its own registration call, never a member added to this one or to
 * ngx_test_probe_hooks_t (see ngx_test_probe.h's own comment on the same
 * rule for the zone-addressed struct).
 */
static const ngx_test_probe_module_hooks_t  ngx_http_zstd_probe_hooks = {
    ngx_http_zstd_probe_module_render,
    ngx_http_zstd_probe_fault_set_global,
};


/*
 * Directive handler for "zstd_probe": takes no arguments, installs this
 * location's content handler. Exposed (not static) so the filter module's
 * own ngx_command_t table can reference it directly -- this file adds no
 * second ngx_module_t/ngx_http_module_t of its own. filter/config builds
 * this TU as an extra source of the SAME dynamic module
 * (ngx_http_zstd_filter_module), not a separate one; see the traps note in
 * plan-testkit-integration.md about ngx_addon_dir and single-module builds.
 */
char *
ngx_http_zstd_probe_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_zstd_probe_handler;

    return NGX_CONF_OK;
}


/*
 * Content handler: render the probe snapshot as JSON and return 200 OK.
 * No shm zone to pass (this module has none) -- NULL routes
 * ngx_test_probe_arm() and ngx_test_probe_json() through the
 * zone-independent path.
 */
static ngx_int_t
ngx_http_zstd_probe_handler(ngx_http_request_t *r)
{
    size_t        size;
    u_char       *buf, *last;
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    /*
     * Arm-then-render: the response must reflect fault state AFTER
     * arming. No zone, so this always falls through to
     * fault_set_global -- see ngx_test_probe_arm()'s dispatch-order
     * comment.
     */
    (void) ngx_test_probe_arm(NULL, &r->args);

    /*
     * NGX_TEST_PROBE_JSON_MAX covers the harness's generic document.
     * This module has no zone name to add, but module_render appends
     * two counters plus a nested out_buf object plus the
     * `,"module":{}` wrapper -- comfortably under 256 bytes, and we
     * oversize per the header's "when in doubt, oversize" guidance
     * rather than count bytes exactly. An undersized buffer truncates
     * and fails EVERY case, not just one -- see plan-testkit-
     * integration.md Traps.
     */
    size = NGX_TEST_PROBE_JSON_MAX + 256;

    buf = ngx_pnalloc(r->pool, size);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = ngx_test_probe_json(buf, buf + size, NULL);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = last - buf;
    ngx_str_set(&r->headers_out.content_type, "application/json");

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = buf;
    b->last = last;
    b->memory = 1;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


ngx_int_t
ngx_http_zstd_probe_init(ngx_conf_t *cf)
{
    ngx_test_probe_register_module(&ngx_http_zstd_probe_hooks);

    return NGX_OK;
}

#endif /* NGX_TEST_HARNESS */
