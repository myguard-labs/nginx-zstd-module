/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_http_zstd_probe_hooks.h -- nginx-module-testkit zoneless probe glue
 * for the zstd filter module (CI only).
 *
 * http-zstd has zero shm zones (verified: no ngx_shared_memory_add /
 * shm_zone in src/), so the zone-addressed hook family
 * (ngx_test_probe_hooks_t / ngx_test_probe_register()) does not apply. This
 * file wires the zone-INDEPENDENT hooks instead
 * (ngx_test_probe_module_hooks_t / ngx_test_probe_register_module()),
 * rendering into the top-level "module" object.
 *
 * Entirely compiled out unless NGX_TEST_HARNESS is defined -- see
 * filter/config for the two build switches this requires
 * (TEST_HARNESS=1 for the sources, -DNGX_TEST_HARNESS for the macro; both
 * are required, see plan-testkit-integration.md § Ground truth).
 */

#ifndef NGX_HTTP_ZSTD_PROBE_HOOKS_H_INCLUDED_
#define NGX_HTTP_ZSTD_PROBE_HOOKS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifdef NGX_TEST_HARNESS

/*
 * Register the zoneless testkit hooks. Call once from
 * ngx_http_zstd_filter_init() (postconfiguration) -- see the call site
 * there. Unconditional: called even when every location has "zstd off",
 * because the probe endpoint must stay reachable regardless of filter
 * enablement.
 */
ngx_int_t ngx_http_zstd_probe_init(ngx_conf_t *cf);

/*
 * Handler for the "zstd_probe" directive (NGX_CONF_NOARGS), added to the
 * filter module's own ngx_command_t table -- this file registers no
 * ngx_module_t of its own. Installs this location's content handler.
 */
char *ngx_http_zstd_probe_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * Per-request instrumentation call sites. Both are cheap process-global
 * counter bumps guarded entirely by NGX_TEST_HARNESS, so they cost nothing
 * in a packaged build (the calls themselves compile out via the macro guard
 * at each call site, not just the bodies here).
 *
 * ngx_http_zstd_probe_note_chain_link() -- called once per ngx_chain_link_t
 * allocated in the body filter's incoming-chain append loop.
 *
 * ngx_http_zstd_probe_note_buf_alloc() -- called once per fresh output
 * buffer created in ngx_http_zstd_filter_get_buf() (the ctx->bufs < ...
 * branch, i.e. NOT the free-list reuse branch).
 *
 * ngx_http_zstd_probe_note_ctx() -- called with the request's ctx so the
 * probe can snapshot free-list length and out_buf state. Safe to call
 * repeatedly (e.g. once per body filter invocation); last write wins. The
 * pointer is observational only and is never dereferenced outside the
 * request that owns it -- see the .c file for the single-worker caveat this
 * inherits from fault_set_global's per-worker-global contract.
 */
void ngx_http_zstd_probe_note_chain_link(void);
void ngx_http_zstd_probe_note_buf_alloc(void);

/*
 * Snapshot the request's free-chain length and out_buf state. The filter
 * passes already-derived values (not the ctx pointer itself) so this file
 * stays independent of ngx_http_zstd_ctx_t's private layout, which is a
 * file-static typedef in the filter TU.
 */
void ngx_http_zstd_probe_note_ctx_state(ngx_uint_t free_links,
    ngx_uint_t out_buf_present, size_t out_buf_size);

#endif /* NGX_TEST_HARNESS */

#endif /* NGX_HTTP_ZSTD_PROBE_HOOKS_H_INCLUDED_ */
