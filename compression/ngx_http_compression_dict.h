/*
 * nginx-compression — the shared dictionary store (phase 1, RFC #109).
 *
 * THE DATA MODEL THE RFC CALLS LOAD-BEARING, made concrete: the only
 * persistent state per dictionary is {path, raw bytes, sha256}. Every
 * algorithm-specific structure — zstd's refPrefix window, brotli's
 * quality-baked prepared dictionary — is per-request scratch built
 * from these bytes through the backend's attach_dictionary() hook, so
 * ONE store entry feeds every coding: one copy per file instead of one
 * per module, and at most one hash pass per file per cycle.
 *
 * Store rules (review round 1 of the RFC, verbatim where possible):
 *
 *  - The STORE is cycle-global and deduplicates BY PATH: the same file
 *    named at http{} and again in a location loads once. Everything
 *    lives in the cycle's config pool — a rejected reload takes its
 *    store down with it (the #103 lesson), and worker processes share
 *    the bytes via fork COW.
 *  - Each configuration level carries a LIST of pointers into the
 *    store. A level that declares its own compression_dict_file list
 *    replaces the inherited one wholesale (standard array-directive
 *    semantics; the RFC's alias-merge rule).
 *  - An optional second argument supplies the SHA-256 (64 hex chars).
 *    By DEFAULT it is VERIFIED against the bytes read (parent #198):
 *    a mismatch fails the load — or, with "optional", warns and
 *    re-keys on the computed truth. Under
 *    "compression_dict_trust_hashes on" (parent #220) the literal is
 *    trusted VERBATIM instead — the deploy-system fast path that
 *    takes config-load hashing to zero for that line. Either way the
 *    literal's syntax is validated before the file is even opened
 *    (the parent repo's ordering pin).
 *  - "A supplied hash never satisfies a directive that didn't supply
 *    one": when an unsupplied directive references a path whose store
 *    entry knows only an UNVERIFIED (trusted-verbatim) hash, the hash
 *    IS computed for that directive — and since the computation was
 *    already paid for, it doubles as a free cross-check: a mismatch
 *    is a config error (catching exactly the stale-supplied-hash
 *    hazard verbatim trust cannot see), a match marks the entry
 *    verified. Under the verify default every supplied entry is
 *    verified at first load, so this audit only has work to do under
 *    trust_hashes — where it remains the safety net.
 *  - Two DIFFERENT paths with the same hash are a config error:
 *    RFC 9842 negotiation keys on the hash, so duplicates would be
 *    ambiguous (parent behavior, kept).
 *
 * PHASE 1a SCOPE: the store loads, validates, dedups, and exposes the
 * per-location lists; nothing reads them yet. Dictionary codings stay
 * unelectable until phase 1b wires Available-Dictionary negotiation
 * and the wire-prologue emitters (the election gates on
 * wire_prologue != NULL). Because nothing non-negotiated can ever be
 * served from this store, there is no equivalent of the parent's
 * zstd_dict_file_unsafe acknowledgement — that gate guards a
 * non-RFC-9842 mode this module simply does not have.
 */

#ifndef NGX_HTTP_COMPRESSION_DICT_H
#define NGX_HTTP_COMPRESSION_DICT_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_COMPRESSION_SHA256_LEN      32
#define NGX_HTTP_COMPRESSION_SHA256_HEX_LEN  64


typedef struct {
    ngx_str_t    path;         /* resolved against the prefix */
    ngx_str_t    bytes;        /* raw contents, cycle config pool */
    u_char       sha256[NGX_HTTP_COMPRESSION_SHA256_LEN];
    ngx_str_t    sha256_hex;   /* lowercase; negotiation + compare key */
    unsigned     supplied:1;   /* hash arrived via config, verbatim */
    unsigned     verified:1;   /* a computed pass confirmed the hash */
    unsigned     optional:1;   /* any line for this path said
                                * "optional": load failures demote to
                                * warnings (sticky across lines) */
} ngx_http_compression_dict_t;


typedef struct {
    /*
     * of ngx_http_compression_dict_t * — the entry OBJECTS are
     * allocated individually and the array holds only pointers,
     * because per-location lists alias the entries and
     * ngx_array_push() RELOCATES element storage on growth: a
     * value-array here handed out pointers that went stale the
     * moment a fifth dictionary loaded (caught by the six-dict
     * duplicate test, which forces the growth).
     */
    ngx_array_t   store;

    /*
     * SHA-256 computations over dictionary files in THIS configuration
     * ($compression_dicts_hashed). Cycle-owned on purpose — the same
     * reasoning as the parent's dcz counter (#103): a rejected reload
     * takes its count down with its pool. The observable witness for
     * both store-level dedup (N references, one compute) and the
     * supplied-hash fast path (zero computes).
     */
    ngx_uint_t    dicts_hashed;

    /*
     * One EVP digest context reused across every hash this config load
     * computes (parent #262): lazily created on the first computed hash,
     * freed with cf->pool when parsing ends. void* so this header pulls
     * in no OpenSSL types; NULL (creation failed, or no libcrypto) makes
     * every hash take the portable path — same total-function contract
     * as before. Only the directive handler touches it, and only during
     * parse; a reload's fresh main conf starts over.
     */
    void          *sha256_evp_ctx;
    ngx_flag_t    sha256_evp_ctx_attempted;

    /*
     * Preformatted decimal of dicts_hashed (parent #154), rendered once
     * in init_main_conf() — the count is final after config parsing (all
     * hashing happens in the compression_dict_file directive handler,
     * before init_main_conf runs) and never changes for the worker's
     * life. The $compression_dicts_hashed handler returns this instead of
     * ngx_sprintf'ing into a fresh per-request buffer on every lookup.
     */
    ngx_str_t     dicts_hashed_str;

    /*
     * compression_dict_strict_path (parent #165): opt-in, off by
     * default. When on, dictionary files open with O_NOFOLLOW and a
     * target writable by group or other is rejected — a symlink or a
     * loosely-permissioned dictionary must not let a lower-privileged
     * local writer swap bytes into every worker on the next reload.
     * MAIN_CONF only: the store is cycle-global, so the policy is a
     * property of the whole load, declared once in http{}. Independent
     * of it, a non-regular target (FIFO/socket/dir/device) is rejected
     * unconditionally, and every open is O_NONBLOCK so a FIFO cannot
     * hang the config-parsing master.
     */
    ngx_flag_t    dict_strict_path;

    /*
     * Set by ngx_http_compression_dict_file() the first time it LOADS
     * a dictionary while dict_strict_path still reads as anything
     * other than the explicit "on" (1) at that moment in the parse —
     * i.e. every load that ran BEFORE a LATER
     * "compression_dict_strict_path on;" line could apply to it.
     * ngx_conf_parse() runs top-to-bottom, and directives are
     * conventionally order-independent, so the operator gets no cue
     * that this one must come first; silently treating such a load as
     * "strict passed" would fail OPEN (the O_NOFOLLOW open and the
     * writable-target check both already happened without it). Rather
     * than defer the strict checks to init_main_conf() — which would
     * mean re-opening every dictionary by path a second time,
     * reintroducing exactly the TOCTOU window the fstat-after-open
     * checks exist to close — init_main_conf() rejects the ordering
     * outright when the flag's final value is "on": see the check
     * there. (Parent's dcz_dict_loaded_before_strict_on, same shape.)
     */
    ngx_flag_t    dict_loaded_before_strict_on;
    ngx_str_t     dict_loaded_before_strict_on_file;

    /*
     * compression_dict_trust_hashes (parent #198 + #220): default off
     * VERIFIES a supplied hash literal against the bytes read — a
     * mismatch fails the load (or warns and re-keys under
     * "optional"), protecting a pipeline whose config generation and
     * file placement are decoupled. "on" restores the trusted-verbatim
     * fast path: the literal IS the negotiation key and the load-time
     * SHA-256 is skipped, which at hundreds of dictionaries is
     * essentially all of the config-load CPU (parent measured 737
     * lines: nginx -t 5.1s -> 0.9s, user CPU 4.3s -> 0.03s). Lines
     * without a literal are hashed under either policy — the per-line
     * escape hatch under trust — and the unsupplied-reference audit
     * below stays live under trust as the safety net.
     */
    ngx_flag_t    dict_trust_hashes;

    /*
     * Ordering record, same trap and remedy as the strict_path pair
     * above: a literal VERIFIED (hashed) because trust did not yet
     * read "on" at that point in the parse is correct but silently
     * paid the pass the directive exists to skip; init_main_conf
     * rejects the ordering when the final value is "on".
     */
    ngx_flag_t    dict_verified_before_trust_on;
    ngx_str_t     dict_verified_before_trust_on_file;

    /*
     * "Could this cycle ever compress a response" latch (parent #182),
     * set at directive PARSE time by ngx_http_compression_set_enable_slot()
     * whenever a "compression on;" is parsed ANYWHERE — main, srv, loc, or
     * an NGX_HTTP_LIF_CONF conf synthesized for a rewrite-phase "if" block.
     * Parse time, not a merged-location walk: an "if" block's conf is not
     * reliably reachable from the ordinary merge tree, and a false negative
     * would silently drop compression for a live location. When it stays
     * clear, postconfiguration skips installing the header/body filter
     * hooks entirely — no per-response NULL-ctx pass on a build that
     * carries the module but never enables it.
     */
    ngx_flag_t    any_enabled;

    /*
     * "Some compression_level configured a negative zstd level" latch
     * (parent #284): negative levels first exist in libzstd 1.4.0, a
     * COMPILE-time gate — but a dynamically loaded libzstd older than
     * the build headers would take those configured levels into API
     * territory it does not have. Latched at compression_level parse
     * time (only the zstd scale admits negatives); init_module feeds
     * it to the parent's runtime version policy, which warns on any
     * skew and refuses startup only when a configured feature crosses
     * its floor.
     */
    ngx_flag_t    any_negative_zstd_level;
} ngx_http_compression_main_conf_t;


/* compression_dict_file <path> [sha256hex] — the directive handler */
char *ngx_http_compression_dict_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* registers $compression_dicts_hashed; call from preconfiguration */
ngx_int_t ngx_http_compression_dict_add_variables(ngx_conf_t *cf);


#endif /* NGX_HTTP_COMPRESSION_DICT_H */
