/*
 * CI-only stub module. Registers under the exact name
 * "ngx_http_compression_vary_filter_module" so the CI witness can assert
 * that the per-location gzip_vary-off warnings collapse into a summary
 * warning when a module by that name is loaded
 * (ngx_http_zstd_vary_handled_externally() in ngx_http_zstd_common.h
 * matches on the module name alone) and still fire per location when it
 * is absent. No directives, no handlers, no behaviour.
 *
 * Never ship or install this: it claims the name of HanadaLee's real
 * ngx_http_compression_vary_filter_module, and loading both would fail
 * with a duplicate module error.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_http_module_t  ngx_http_compression_vary_filter_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL,                                   /* merge location configuration */
};


static ngx_command_t  ngx_http_compression_vary_filter_commands[] = {
    ngx_null_command
};


ngx_module_t  ngx_http_compression_vary_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_compression_vary_filter_module_ctx,  /* module context */
    ngx_http_compression_vary_filter_commands,     /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};
