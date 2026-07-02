[![Build & Test](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/build-test.yml/badge.svg)](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/build-test.yml)
[![CodeQL](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/codeql.yml/badge.svg)](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/codeql.yml)
[![Security Scanners](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/security-scanners.yml/badge.svg)](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/security-scanners.yml)
[![Fuzzing](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/fuzzing.yml/badge.svg)](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/fuzzing.yml)
[![Valgrind Memcheck](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/valgrind.yml/badge.svg)](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/valgrind.yml)

📖 **Background reading:** 
- [zstd nginx module: what it does, bugs fixed](https://deb.myguard.nl/2026/05/zstd-nginx-module-what-it-does-bugs-fixed/)
- [nginx zstd vs brotli vs zlib-ng — a compression comparison](https://deb.myguard.nl/2026/05/nginx-zstd-vs-brotli-vs-zlib-ng-compression/)

# zstd-nginx-module

An nginx module for [Zstandard (zstd)](https://facebook.github.io/zstd/) compression. Zstandard typically achieves better compression ratios than gzip at comparable or faster speeds, making it a good choice for reducing transmitted response sizes.

This is a hardened fork: every build is exercised against **nginx mainline and [Angie](https://angie.software/)**, the full test suite runs under **ASAN/UBSAN**, the `Accept-Encoding` parser is **continuously fuzzed**, and **CodeQL** plus flawfinder/semgrep/clang-tidy run on every change (see the badges above and [Testing & CI](#testing--ci)).

# Table of Contents

* [Status](#status)
* [Synopsis](#synopsis)
* [Set and forget](#set-and-forget)
* [Installation](#installation)
* [Directives](#directives)
  * [ngx_http_zstd_filter_module](#ngx_http_zstd_filter_module)
    * [zstd](#zstd)
    * [zstd_comp_level](#zstd_comp_level)
    * [zstd_min_length](#zstd_min_length)
    * [zstd_max_length](#zstd_max_length)
    * [zstd_types](#zstd_types)
    * [zstd_buffers](#zstd_buffers)
    * [zstd_target_cblock_size](#zstd_target_cblock_size)
    * [zstd_window_log](#zstd_window_log)
    * [zstd_long](#zstd_long)
    * [zstd_max_cctx_memory](#zstd_max_cctx_memory)
    * [zstd_bypass](#zstd_bypass)
    * [zstd_bypass_vary](#zstd_bypass_vary)
    * [zstd_dict_file](#zstd_dict_file)
  * [ngx_http_zstd_static_module](#ngx_http_zstd_static_module)
    * [zstd_static](#zstd_static)
* [Variables](#variables)
  * [$zstd_ratio](#zstd_ratio)
  * [$zstd_bytes_in](#zstd_bytes_in)
  * [$zstd_bytes_out](#zstd_bytes_out)
* [Compatibility](#compatibility)
* [Testing & CI](#testing--ci)
* [Benchmarks](#benchmarks)
* [Operations](#operations)
* [Security](#security)
* [Author](#author)
* [License](#license)

# Status

Production-oriented. The module originates from the upstream
[tokers/zstd-nginx-module](https://github.com/tokers/zstd-nginx-module) and
has since had an extensive audit pass: a regression test for every known
historical bug class, ASAN/UBSAN runtime checks, and continuous fuzzing of
the request-parsing path (see [Testing & CI](#testing--ci)). Bug reports and
pull requests are welcome.

# Synopsis

```nginx
http {
    # Compress text responses for clients that support zstd.
    # Defaults: level 3, web-content MIME types, and a 1024-byte minimum.
    zstd             on;

    # Required: emit Vary: Accept-Encoding so proxies/CDNs cache correctly.
    gzip_vary        on;

    server {
        listen 80;
        server_name example.com;

        # Dynamic compression via filter module
        location /api/ {
            proxy_pass http://backend;
        }

        # Serve pre-compressed .zst files for static assets
        location /static/ {
            zstd_static on;
            root /var/www;
        }
    }
}
```

For pre-compressed static files, generate them alongside the originals:

```bash
# Compress all JS and CSS files in the static directory
find /var/www/static -name "*.js" -o -name "*.css" | \
    xargs -I{} zstd -3 -k {}
# This creates file.js.zst next to file.js, etc.
```

# Set and forget

If you just want sane production compression without reading every
directive, paste this into the `http {}` block of `nginx.conf` and move
on. It is tuned for typical web traffic (HTML/JSON/JS/CSS/SVG) and
relies on the module's built-in defaults for everything not shown.

```nginx
http {
    # --- zstd: set and forget ---
    zstd              on;    # level 3, 1 KiB minimum, common web types

    # Required so proxies/CDNs cache compressed and identity variants
    # separately. The module warns at startup if this is missing.
    gzip_vary         on;

    # Pre-compressed static assets (optional but free if you ship .zst)
    # zstd_static     on;
}
```

Why these values, and why nothing else is needed:

* **`zstd_comp_level 3`** — the built-in default; for real web content this beats `gzip -6`
  on ratio at comparable or better speed (see [Benchmarks](#benchmarks)).
  Levels ≥ 9 cost CPU steeply for marginal gain; only raise it for
  infrequently-generated, cached responses.
* **`zstd_min_length 1024`** — the built-in default; below about 1 KiB the
  zstd frame overhead and CPU cost usually outweigh the saving.
* **`zstd_types` is intentionally not set.** Its built-in list covers HTML,
  plain text, CSS, JavaScript, JSON, XML/feed formats, SVG, and common
  structured JSON variants (see [`zstd_types`](#zstd_types)).
* **`zstd_buffers` is intentionally not set.** The default is now
  `2 × ZSTD_CStreamOutSize()` — libzstd's own recommended streaming
  output unit (~128 KB each). This lets every compress call flush a
  full internal block without fragmentation. Only override it if you
  run thousands of concurrent connections on a memory-constrained box
  and need to trade some throughput for a lower per-request memory
  floor (see [`zstd_buffers`](#zstd_buffers)).
* **`zstd_long`, `zstd_window_log`, `zstd_dict_file`,
  `zstd_target_cblock_size` are intentionally not set.** They are
  specialist levers (very large repetitive bodies, hard per-request
  memory caps, shared dictionaries). The defaults are correct for
  general traffic; reach for these only with a measured reason.

That is the entire recommended baseline. Everything past this point in
the README is reference detail and tuning for specific workloads — you
do not need it to run the module well.

# Installation

Build nginx with the module using `--add-dynamic-module`:

```bash
./configure --add-dynamic-module=/path/to/zstd-nginx-module
make && make install
```

Then load the modules in `nginx.conf`:

```nginx
load_module modules/ngx_http_zstd_filter_module.so;
load_module modules/ngx_http_zstd_static_module.so;
```

**Notes:**

* Both `ngx_http_zstd_filter_module` and `ngx_http_zstd_static_module` are compiled together.
* If you are using a custom zstd installation, set `ZSTD_INC` (path to `zstd.h`) and `ZSTD_LIB` (path to the library) before running `configure`. If unset, the system-installed zstd is used.
* Dynamic modules (`.so`) require dynamic linking against `libzstd.so`. The build scripts auto-detect and prefer this. Ensure the zstd shared library is installed and available at runtime (`libzstd-dev` on Debian/Ubuntu, `libzstd-devel` on RHEL/Fedora).
* When `ZSTD_LIB` is set to a non-standard path, the build embeds an RPATH pointing to that directory in the module `.so`. This means the module will load `libzstd.so` from that exact path at runtime. If the library is later moved (e.g. by a package upgrade), the module will fail to load. Use the system package and leave `ZSTD_LIB` unset to avoid this.

# Compatibility

| Component | Minimum | Recommended | CI-verified |
|---|---|---|---|
| **nginx** | 1.9.11 (first `--add-dynamic-module` release) | latest mainline / stable | **1.31.0 mainline** |
| **Angie** | 1.x | latest | **1.11.5** |
| **libzstd** | **1.4.0** | **≥ 1.5.6** | 1.5.x (full suite) + **1.4.x** fallback-paths build |
| **OS** | Linux/BSD/RHEL-family | — | Ubuntu (GitHub runners) |

Notes on the libzstd floor — these are enforced in code, not assumed:

* **< 1.4.0**: the streaming API the module uses (`ZSTD_compressStream2`)
  is unavailable; this is the hard minimum. Negative `zstd_comp_level`
  values are also unsupported and are clamped to `1` with a warning
  (guarded by `#if ZSTD_VERSION_NUMBER >= 10400`).
* **< 1.5.6**: `zstd_target_cblock_size` has no effect — the directive
  is accepted but silently ignored (apply path gated by
  `#if ZSTD_VERSION_NUMBER >= 10506`, with a config-load warning).
  Everything else works. This fallback path is exercised in CI by a
  dedicated "Build (libzstd 1.4.x — fallback paths)" job that links the
  module against a privately built libzstd 1.4.x and runs the
  decode-and-compare smoke test.
* **≥ 1.5.6**: every directive is fully functional.
* **`zstd_max_cctx_memory`** additionally requires the module to be
  built with `-DZSTD_STATIC_LINKING_ONLY` so libzstd's experimental
  memory-estimator API is available. The project's production and CI
  builds enable that flag; without it, the directive is rejected at
  config load with a clear, actionable error rather than silently
  no-op'd.

"CI-verified" means every push builds and runs the full test suite
against that exact version (see [Testing & CI](#testing--ci)). Other
versions within the stated ranges are expected to work but are not
continuously exercised.

# Directives

## ngx_http_zstd_filter_module

This filter module compresses responses on the fly using zstd. It runs after the upstream or file handler generates the response, and before nginx sends it to the client. Compression is applied only when the client signals support via `Accept-Encoding: zstd`. 2xx responses are eligible for compression — except the bodyless `204 No Content` and `205 Reset Content` — as well as `403` and `404` (which often carry compressible error bodies). All other non-2xx statuses are passed through uncompressed.

> **Required:** Enable `gzip_vary on;` alongside this module. When compression is applied, the module sets `r->gzip_vary = 1`, which causes nginx to emit a `Vary: Accept-Encoding` response header — but only when `gzip_vary` is enabled. Without it, proxies and CDNs may cache and serve compressed responses to clients that do not support zstd.

> **ETag behaviour:** When a response is compressed, nginx automatically weakens the `ETag` value (converting `"abc"` to `W/"abc"` if it was strong). This is correct per HTTP semantics — a compressed representation is a different entity variant — but it means strong ETag validation (`If-Match`) will not match across compressed and uncompressed responses. CDN edge nodes that cache both variants will see different ETags for each.

> **Coexisting with `gzip` and `brotli`:** It is safe to enable `zstd`, the [`brotli`](https://github.com/google/ngx_brotli) filter, and the built-in [`gzip`](https://nginx.org/en/docs/http/ngx_http_gzip_module.html) filter on the same location with overlapping `*_types`. A response is only ever compressed once: nginx body filters run in a fixed chain, and the first encoder whose `Accept-Encoding` test passes wins, setting `Content-Encoding` so the later encoders skip the already-encoded body. Relative to the built-in `gzip`, `zstd` is always ordered to run **before** it (both in static and dynamic builds), so a client advertising `Accept-Encoding: gzip, zstd` receives `zstd`; clients that do not advertise `zstd` fall through to `gzip`. Always pair this with `gzip_vary on;` so each encoded variant is cached separately by proxies and CDNs.
>
> **`zstd` vs `brotli` ordering (dynamic builds):** the fixed `before brotli` guarantee holds for **static** builds, where `filter/config` explicitly places `zstd` ahead of `ngx_http_brotli_filter_module` in the module array. For **dynamic** modules, `ngx_brotli` and this module share the same filter anchor and neither constrains itself relative to the other, so the body-filter chain is built in **reverse `load_module` order** — whichever is loaded **last** runs first and wins. To make `zstd` win a `br, zstd` negotiation, load it last:
>
> ```nginx
> load_module modules/ngx_http_brotli_filter_module.so;
> load_module modules/ngx_http_zstd_filter_module.so;   # loaded last → runs first → wins
> ```
>
> Swap the two lines to prefer `brotli`. If you require a fixed winner regardless of operator load order, prefer a static build (or pick one of the two filters per location).
>
> **Selection policy — server preference, not client qvalue ranking.** When several encoders are enabled and the client lists more than one as acceptable, the winner is decided by **server-side filter order** (zstd runs first), **not** by the client's relative `q` weights. So `Accept-Encoding: zstd;q=0.5, gzip;q=0.9` still yields `zstd`, even though the client ranked `gzip` higher. This is a deliberate server-preference policy. RFC 9110 §12.5.3 describes preferring the acceptable coding with the highest non-zero qvalue, which a single per-coding filter cannot implement (it cannot see the other codings' weights); honouring it would require a shared negotiation step ahead of the body filters. The module still honours each coding's own `q=0` as an absolute "not acceptable" — only the *relative* ranking between acceptable codings is server-decided.

---

### zstd

**Syntax:** `zstd on | off;`
**Default:** `zstd off;`
**Context:** `http, server, location, if in location`

Enables or disables on-the-fly zstd compression for responses.

**Example:**

```nginx
http {
    zstd       on;          # enable everywhere
    gzip_vary  on;          # required: see the note above

    server {
        location /downloads/ {
            zstd off;       # already-compressed archives: skip
        }
    }
}
```

---

### zstd_comp_level

**Syntax:** `zstd_comp_level level;`
**Default:** `zstd_comp_level 3;`
**Context:** `http, server, location`

Sets the zstd compression level. Accepted values depend on the installed zstd library version:

| Range | Meaning |
|---|---|
| `1` to `ZSTD_maxCLevel()` (22) | Standard levels — higher = better ratio, slower |
| `0` | Library default (`ZSTD_CLEVEL_DEFAULT`, currently level 3) |
| `ZSTD_minCLevel()` (-131072) to `-1` | Fast/negative levels — lower ratio, minimal CPU cost (requires zstd ≥ 1.4.0) |

**Choosing a level:**

* `1` — Fastest compression; suitable for high-throughput APIs or when latency is critical.
* `3` (default) — Good all-around balance of ratio and speed; the zstd library's own default.
* `6`–`9` — Better ratios with moderate CPU cost; suitable for large, infrequently-changed responses.
* Negative levels (`-1` to `-5`) — Ultra-fast, for cases where you want some compression with nearly zero overhead.

For most web-serving workloads, levels `1`–`3` are recommended. Avoid high levels (> 9) in production unless responses are generated infrequently and cached.

**Example:**

```nginx
http {
    zstd             on;
    zstd_comp_level  3;          # balanced default for live traffic

    server {
        location /api/ {
            zstd_comp_level 1;   # latency-sensitive: fastest level
        }

        location /reports/ {
            zstd_comp_level 12;  # large, cached, infrequently generated
        }
    }
}
```

> **Performance note:** when a response has a known exact
> `Content-Length` (the common proxied/static case), the module passes
> that size to zstd up front (`ZSTD_CCtx_setPledgedSrcSize`). zstd then
> sizes its internals to the input and writes a more compact frame
> header, giving a small speed/ratio improvement at no cost. This is
> automatic, per request, and requires no configuration. Chunked /
> unknown-length responses are unaffected (they stream as before).

---

### zstd_min_length

**Syntax:** `zstd_min_length length;`
**Default:** `zstd_min_length 1024;`
**Context:** `http, server, location`

Sets the minimum response size (in bytes) required for compression to apply. The size is taken from the `Content-Length` response header; responses without `Content-Length` are always eligible.

> **Note:** The built-in default is `1024` bytes. Smaller responses often lose
> their savings to zstd frame overhead while still consuming compression CPU.

**Example:**

```nginx
zstd_min_length 1024;  # skip compression for responses smaller than 1 KiB
```

---

### zstd_max_length

**Syntax:** `zstd_max_length length;`
**Default:** `—` (no limit)
**Context:** `http, server, location`

Sets the maximum response size that will be compressed. The limit is enforced in two places:

* **Before compression starts**, when the response advertises a `Content-Length` larger than the limit: the response is passed through uncompressed (no CPU spent).
* **During compression**, for chunked/streaming responses with *no* `Content-Length`: the running input total is tracked, and if it exceeds the limit the request is **aborted** (logged as `zstd: input exceeded zstd_max_length ...`). Compression has already begun and the client is mid-stream, so the only safe action is to terminate the response — protecting the worker from an unbounded or runaway upstream is preferred over completing one oversized response.

> **Behaviour on chunked responses:** the no-`Content-Length` case cannot be served uncompressed-instead (the `Content-Encoding: zstd` stream is already in flight), so exceeding the limit there ends the request rather than transparently passing through. Size the limit with headroom for the largest response you legitimately compress on that location. If you routinely serve very large streaming bodies (proxied video, big downloads), prefer simply not enabling `zstd` on those locations.

By default there is no upper limit. You may want to set one if very large responses (e.g. multi-megabyte file downloads) should bypass compression to avoid holding the worker process busy.

**Example:**

```nginx
zstd_max_length 10m;  # don't compress responses larger than 10 MB
```

---

### zstd_types

**Syntax:** `zstd_types mime-type ...;`
**Default:**

```nginx
zstd_types text/html text/plain text/css text/csv application/json
           application/x-ndjson application/json-seq application/javascript
           text/xml application/xml
           application/xml+rss text/javascript image/svg+xml
           application/atom+xml application/ld+json
           application/manifest+json application/problem+json
           application/rss+xml application/vnd.api+json
           application/xhtml+xml application/wasm text/wgsl;
```
**Context:** `http, server, location`

When omitted, the default covers common textual web representations. If set
explicitly, it follows nginx's usual type-directive behaviour: `text/html` is
included along with the listed MIME types. Use `*` to match all MIME types.

> **Note:** Only compressible content types (text, structured data, SVG, etc.) benefit from compression. Binary formats such as images (JPEG, PNG, WebP), audio, and video are already compressed and should be excluded.

**Example for a typical web application:**

```nginx
zstd_types
    text/plain
    text/css
    text/csv
    text/xml
    text/javascript
    application/json
    application/x-ndjson
    application/json-seq
    application/javascript
    application/xml
    application/xml+rss
    application/atom+xml
    application/ld+json
    application/manifest+json
    application/problem+json
    application/rss+xml
    application/vnd.api+json
    application/xhtml+xml
    application/wasm
    text/wgsl
    image/svg+xml;
```

---

### zstd_buffers

**Syntax:** `zstd_buffers number size;`
**Default:** `zstd_buffers 2 <ZSTD_CStreamOutSize()>;` (the size is libzstd's recommended streaming output unit, ~128 KB)
**Context:** `http, server, location`

Configures the number and size of output buffers used during compression. The total buffer space is `number × size`.

The default buffer **size** is `ZSTD_CStreamOutSize()` — the value libzstd documents as the minimum at which `ZSTD_compressStream2()` can flush a complete internal block in a single call. With any smaller buffer, zstd is forced to fragment a block across calls, costing extra compression round-trips and output-chain allocations per response. Earlier versions used a heuristic (`32 4k`, then `4 32k`) that approximated this; the module now asks libzstd for the exact value so it stays correct if the library changes it.

The default **count** is `2`: one buffer being filled by the compressor while the other is in flight down the output chain. This sets the per-request filter-memory floor at roughly `2 × ZSTD_CStreamOutSize()` (~256 KB), up from the previous ~128 KB — the deliberate cost of never forcing zstd to flush mid-block. If that trade is wrong for your workload (many concurrent connections, memory-constrained), set `zstd_buffers` explicitly to a smaller value; configurations that set it are unaffected by this default.

Increasing these values allows larger chunks to be accumulated before writing, potentially improving throughput at the cost of higher per-request memory usage.

**Example:**

```nginx
http {
    zstd on;

    # The built-in default (applied when the directive is omitted):
    # 2 buffers sized to ZSTD_CStreamOutSize() (~128 KB each on
    # libzstd 1.5.x), i.e. ~256 KB/request. The line below is that
    # default written explicitly — leaving zstd_buffers unset is
    # equivalent and recommended:
    zstd_buffers 2 128k;

    server {
        # Memory-constrained box with very high concurrency:
        # trade some throughput for a lower per-request floor.
        location /high-fanout/ {
            zstd_buffers 4 16k;   # 64 KB/request instead of ~256 KB
        }
    }
}
```

> The default **size** is whatever `ZSTD_CStreamOutSize()` returns for
> the linked libzstd (~128 KB on 1.5.x); `2 128k` above is the
> human-readable equivalent for that version. Prefer leaving the
> directive unset so the size always tracks the library — only write it
> explicitly when you are deliberately overriding it.

---

### zstd_target_cblock_size

**Syntax:** `zstd_target_cblock_size size;`
**Default:** `—` (disabled, uses ZSTD library defaults)
**Context:** `http, server, location`
**Requires:** libzstd ≥ v1.5.6

Sets the target compressed block size for zstd frames. Controlling block size improves incremental response parsing, particularly in browsers where CSS/JavaScript in the response head must be available as soon as possible.

> **Rationale:** When the zstd encoder produces large compressed blocks, the entire block must be decompressed before any content within it becomes available to the client. Smaller blocks allow incremental decompression and earlier access to critical resources. For example, CSS in `<head>` can be parsed sooner if it lands in an early, smaller block.

> **Compatibility:** This directive requires libzstd v1.5.6 or later. On older versions, the directive is silently ignored. If not set (value 0 or unset), zstd uses its internal defaults, typically yielding blocks of 128–256 KB depending on the compression level and content.

**Example:**

```nginx
http {
    # Smaller blocks = faster incremental parsing, slightly lower compression ratio
    zstd_target_cblock_size 65536;  # 64 KB blocks
}
```

**Effect:** Lower values increase the number of blocks and may reduce compression ratio slightly, but improve streaming/incremental decompression. Common values:

| Value | Use Case |
|---|---|
| Not set | Default behavior; good all-around balance |
| `16384` (16 KB) | Very aggressive incremental parsing; reduces ratio notably |
| `65536` (64 KB) | Moderate; CSS/JS in head typically available faster |
| `262144` (256 KB) | Conservative; minimal ratio impact |

---

### zstd_window_log

**Syntax:** `zstd_window_log exponent;`
**Default:** `—` (disabled; zstd uses its level-derived default)
**Context:** `http, server, location`

Caps the zstd compression **window** at `2^exponent` bytes. zstd's
per-request working memory is dominated by the window size (roughly the
window plus match-table overhead), so without a cap a high compression
level on large response bodies lets each concurrent request inflate the
worker's resident memory unpredictably. Bounding `window_log` gives a
hard, predictable per-request memory ceiling.

Typical values are `20`–`24` (1–16 MB). Lower values reduce memory and
the compression ratio on inputs larger than the window; on responses
smaller than the window there is no ratio impact. Unset (or `0`) keeps
zstd's default window for the configured level.

> **Note:** This bounds compressor memory, not the amount of response
> body buffered by nginx (that is governed by `zstd_buffers`). For a hard
> limit on how much input is ever fed to the compressor regardless of
> `Content-Length`, see also `zstd_max_length`.

**Example:**

```nginx
http {
    zstd on;
    zstd_comp_level   9;
    zstd_window_log   21;   # cap the window at 2 MB per request
}
```

---

### zstd_long

**Syntax:** `zstd_long on | off;`
**Default:** `zstd_long off;`
**Context:** `http, server, location`

Enables zstd **long-distance matching** (`ZSTD_c_enableLongDistanceMatching`). zstd keeps a secondary long-range hash table that finds repeated sequences far beyond the regular match window, which can meaningfully improve the compression ratio on large, internally repetitive bodies — concatenated JSON, HTML with repeated boilerplate, log dumps, sitemaps.

Off by default: the win only appears on inputs large enough to exceed the match window, and it costs a modest, bounded amount of extra per-request memory for the long-range table. Small responses should not pay that allocation, so enable it only on locations that serve large repetitive payloads.

Interacts with [`zstd_window_log`](#zstd_window_log): an explicit `zstd_window_log` still takes precedence over the window zstd would otherwise derive when long mode is on, so the per-request memory ceiling remains under your control.

**Example:**

```nginx
location /api/bulk-export {
    zstd on;
    zstd_comp_level  12;
    zstd_long        on;    # large, highly repetitive JSON
    zstd_window_log  24;    # keep the memory ceiling explicit
}
```

---

### zstd_max_cctx_memory

**Syntax:** `zstd_max_cctx_memory size;`
**Default:** `—` (disabled, no budget enforced)
**Context:** `http, server, location`
**Requires:** module built with `-DZSTD_STATIC_LINKING_ONLY` against libzstd ≥ 1.4.0 (the project's production and CI builds do; see [Compatibility](#compatibility)).

Asserts at **config load** that the combined zstd parameters configured
for the location (`zstd_comp_level`, `zstd_window_log`, `zstd_long`,
`zstd_target_cblock_size`) do not need more than `size` bytes of
per-request compressor working memory. If they would, nginx refuses to
start with a clear, actionable error pointing at the smallest set of
parameters to lower.

The budget is checked against libzstd's own
`ZSTD_estimateCStreamSize_usingCCtxParams()`, so the number is
authoritative — it accounts for the level's *strategy tables*
(chain/hash/search), the window, and LDM, not just the window. This
matters because **lowering `zstd_window_log` alone does not bound
memory for high levels**: level 22 at windowLog 20 still allocates
~640 MB, because the table size is driven by the level/strategy, not
the window.

```nginx
http {
    zstd                  on;
    zstd_comp_level       19;       # would otherwise eat ~90 MB / request
    zstd_max_cctx_memory  256m;     # accepted: level 19 fits in 256 MB
}

server {
    location /risky/ {
        zstd_comp_level       22;
        zstd_max_cctx_memory  64m;  # REFUSED at config load:
        # "the configured zstd parameters need ~833 MB of per-request
        # compressor memory, which exceeds zstd_max_cctx_memory 64m;
        # lower zstd_comp_level (currently 22), lower zstd_window_log,
        # disable zstd_long, or raise the budget"
    }
}
```

**Why a config-load assert and not a runtime cap.** The directive does
**not** silently tune anything. A too-tight budget is a hard error so
operators see the misconfiguration up front, instead of discovering it
as a worker-RSS surprise under concurrency. Without
`-DZSTD_STATIC_LINKING_ONLY` the estimator API is unavailable; in that
case the directive is rejected at config load with the same kind of
clear message, never silently no-op'd.

> **Note:** This bounds **per-request** memory at one CCtx. The total
> worker memory ceiling at the request limit is roughly
> `worker_connections × zstd_max_cctx_memory` in the worst case
> (every connection actively compressing).

---

### zstd_bypass

**Syntax:** `zstd_bypass string ...;`
**Default:** `—`
**Context:** `http, server, location`

Disables on-the-fly compression for the current request when at least
one of the given string parameters evaluates to a non-empty value that
is not `"0"`. Each parameter is typically a variable (often driven by a
`map`), so the decision is made per request rather than statically.

```nginx
map $request_uri $no_zstd {
    default              0;
    ~^/wp-admin/         1;   # authenticated admin: reflects input + nonces
    ~^/wp-json/          1;   # REST: responses mix tokens with user data
}

server {
    zstd on;
    zstd_bypass $no_zstd;            # skip those paths
    zstd_bypass $http_x_no_compression;  # honour a client opt-out header
}
```

> **Security note — BREACH:** `zstd_bypass` is the intended lever for
> mitigating [BREACH](https://en.wikipedia.org/wiki/BREACH)-style
> attacks, which exploit the *size* of a compressed HTTP body that
> contains **both** a secret (CSRF token, session data) **and**
> attacker-influenced reflected input. Use it to serve identity on the
> specific endpoints where that combination occurs.
>
> Be honest about what this does and does not do: **no HTTP compressor
> can be made BREACH-safe while still compressing** — the attack is
> inherent to compression ratio as a side channel. `zstd_bypass` only
> lets you *exclude* the at-risk responses. The effective, primary
> BREACH defenses live in the application: per-request CSRF token
> masking, separating secrets from reflected input, and
> referer/origin checks. Treat `zstd_bypass` as a containment tool, not
> a fix. (CRIME and POODLE are unrelated TLS-layer attacks and are not
> addressed — or addressable — here; configure `ssl_protocols`
> appropriately instead.)

> **Why this module does not pad responses (the "anti-BREACH length
> padding" question).** A frequently requested "fix" is to add random
> padding to the compressed body so its length no longer reveals the
> compression ratio. This module deliberately does **not** do that, and
> will not, for concrete reasons:
>
> 1. **Random padding does not remove the signal — it adds noise the
>    attacker averages out.** BREACH is a guess-and-measure oracle: the
>    attacker replays the same request thousands of times, changing one
>    guessed byte at a time. A correct guess compresses ~1 byte smaller.
>    Random padding of variance σ adds zero-mean noise to each
>    measurement; averaging N samples shrinks the noise by √N while the
>    1-byte signal stays put. The attacker simply requests more times.
>    Published BREACH follow-up work (e.g. *Rupture*) automates exactly
>    this statistical recovery against padded/noised responses. Padding
>    raises the request count, not the difficulty class — it buys the
>    *appearance* of a fix while the secret still leaks.
> 2. **Padding that *would* defeat it is not "padding" anymore.** The
>    only length transform that actually closes the oracle is forcing
>    every response to a fixed size (or coarse power-of-two buckets)
>    *independent of content* — which throws away most of the
>    compression you enabled zstd for, on every response, to defend the
>    small subset that mixes a secret with reflected input. That is a
>    strictly worse trade than `zstd_bypass` on those endpoints (full
>    ratio everywhere else, identity exactly where it is unsafe).
> 3. **It moves a security boundary into the wrong layer.** Whether a
>    response safely mixes secrets and attacker input is an
>    application-semantics decision (is this field a CSRF token? is that
>    substring reflected query input?). A compression filter cannot see
>    that distinction; a per-response byte transform here cannot make an
>    application-layer information-flow problem safe, and shipping one
>    would invite operators to *believe* it had.
>
> So the module gives you the one lever that is honest and effective —
> `zstd_bypass`, to serve identity on the specific at-risk endpoints —
> and points you at the real fixes (CSRF token masking, separating
> secrets from reflected input, origin/referer checks). A built-in
> padding knob would trade real bandwidth for false confidence, so it is
> intentionally absent. See [`SECURITY.md`](SECURITY.md) for the
> in-scope / out-of-scope statement.

> **Cache safety with request-driven bypass.** When a `zstd_bypass`
> predicate depends on a **request header or cookie** (e.g.
> `zstd_bypass $http_x_no_compression`), the compressed-vs-identity
> decision now varies on that header. A shared cache (proxy / CDN) that
> does not key on it can store the identity response and serve it to a
> normal client, or store the compressed response and serve it to a
> bypass client. Either declare that variance with
> [`zstd_bypass_vary`](#zstd_bypass_vary) **or** mark such responses
> `Cache-Control: private` / `no-store`. Bypass predicates that depend
> only on `$request_uri`/`$uri` (already part of the cache key) do not
> need this.

---

### zstd_bypass_vary

**Syntax:** `zstd_bypass_vary field-name;`
**Default:** `—`
**Context:** `http, server, location`

Appends `field-name` to the response `Vary` header on every response from
the location (both the compressed and the bypassed-identity variant), so a
shared cache keys on the request header that drives a header/cookie-based
[`zstd_bypass`](#zstd_bypass). Use it whenever a bypass predicate reads a
request header or cookie:

```nginx
server {
    zstd on;
    zstd_bypass      $http_x_no_compression;  # client opt-out header
    zstd_bypass_vary X-No-Compression;        # so caches key on it
}
```

The module emits this as an additional `Vary` header line; caches union all
`Vary` fields, so it coexists with the `Vary: Accept-Encoding` produced by
`gzip_vary on;`. It does not itself decide anything — it only makes the
existing bypass behaviour cacheable without poisoning.

---

### zstd_dict_file

**Syntax:** `zstd_dict_file /path/to/dict;`
**Default:** `—`
**Context:** `http`

Loads a pre-trained zstd dictionary for use during compression. Dictionaries can significantly improve compression ratios for small, structurally similar responses (e.g. JSON API responses).

> **Requires explicit opt-in.** This directive emits an ordinary `Content-Encoding: zstd` response that was compressed with an external dictionary. That is **not** HTTP dictionary negotiation — [RFC 9842](https://www.rfc-editor.org/rfc/rfc9842) (Sept 2025) defines the `dcz` content coding and `Available-Dictionary` for that, which this module does not yet implement. A generic client that only advertises `Accept-Encoding: zstd` **cannot decode** the result, and a shared cache keys it as an ordinary zstd variant. nginx therefore refuses to start with `zstd_dict_file` set unless you also set `zstd_dict_file_unsafe on;`, acknowledging that you control both ends and will key any shared cache accordingly.

> **Warning:** The `Content-Encoding: zstd` token in HTTP does not include any mechanism for the client to discover or negotiate which dictionary the server is using. Only use this directive if you control both ends of the connection and can guarantee that both the server and client use the same dictionary (for example, by advertising it via a custom HTTP header). See [tokers/zstd-nginx-module#2](https://github.com/tokers/zstd-nginx-module/issues/2) for background.

> **Parameter precedence with a dictionary.** A `ZSTD_CDict` bakes in the compression parameters it was built with, and libzstd's `ZSTD_CCtx_refCDict()` lets those supersede the per-request CCtx parameters. To keep `zstd_window_log` an effective cap with a dictionary loaded, the CDict is built with `ZSTD_createCDict_advanced()` seeding `windowLog` from `zstd_window_log` (on the static-linked builds this module ships), so the baked window matches the CCtx window and `zstd_max_cctx_memory`'s estimate — computed from the same `windowLog` — stays accurate. The CDict is built per distinct (`zstd_comp_level`, `zstd_window_log`) combination, so changing either in a child `location` rebuilds it rather than silently reusing the parent's. `zstd_long` applies via the CCtx (it is not a `ZSTD_compressionParameters` field, so `refCDict` does not override it). On a non-static-linked build the advanced builder is unavailable and the CDict falls back to a level-only digest; there `zstd_window_log` is not honored while a dictionary is loaded.

**Example:**

```nginx
http {
    # Loaded once per cycle; must be readable by the nginx user.
    # Train it with: zstd --train samples/*.json -o /etc/nginx/api.dict
    zstd_dict_file        /etc/nginx/api.dict;
    zstd_dict_file_unsafe on;   # required: acknowledges non-RFC-9842 mode

    zstd            on;
    zstd_types      application/json;

    server {
        location /api/ {
            # Tell a cooperating client which dictionary was used,
            # since HTTP cannot negotiate it (see warning above).
            add_header X-Zstd-Dict "api.dict-v1" always;
        }
    }
}
```

---

## ngx_http_zstd_static_module

This module serves pre-compressed `.zst` files in place of the originals, without running compression at request time. It is the zstd equivalent of nginx's `gzip_static` module.

---

### zstd_static

**Syntax:** `zstd_static on | off | always;`
**Default:** `zstd_static off;`
**Context:** `http, server, location`

Controls how pre-compressed `.zst` files are served.

| Value | Behaviour |
|---|---|
| `off` | Disabled. Always serve the original file. |
| `on` | Check whether the client supports zstd (`Accept-Encoding: zstd`). If yes and a `.zst` file exists, serve it. Otherwise fall back to the original. Also emits `Vary: Accept-Encoding` (via `gzip_vary`). |
| `always` | Always serve the `.zst` file if it exists, regardless of `Accept-Encoding`. Use this when you know all clients support zstd (e.g. internal services). |

When set to `on`, the module sets `r->gzip_vary = 1`, which causes nginx to add a `Vary: Accept-Encoding` response header (controlled by [`gzip_vary`](https://nginx.org/en/docs/http/ngx_http_gzip_module.html#gzip_vary)). Enable `gzip_vary on;` alongside `zstd_static on;` to ensure correct caching by proxies and CDNs.

> **Warning (`always` mode):** When `zstd_static always` is set, `.zst` files are served to every client regardless of whether they advertise `Accept-Encoding: zstd`. No `Vary` header is emitted and no `Content-Encoding` negotiation occurs. Any client that does not support zstd will receive a compressed body it cannot decode. Only use `always` on locations where every client is guaranteed to support zstd — for example, internal service-to-service calls where you control both ends.

> **Magic-number validation.** Before serving a `.zst`, the module reads the first 4 bytes of the file (one `pread(2)` at offset 0) and verifies they are the zstd frame magic (`ZSTD_MAGICNUMBER` `0xFD2FB528`) or a skippable-frame magic (`ZSTD_MAGIC_SKIPPABLE_*`). On mismatch — a truncated download, mistaken rename (`cp foo.txt foo.zst`), or any other non-zstd content — the handler logs `zstd static: "..." is not a zstd frame (leading bytes 0x...)` and **declines**; nginx then falls back to serving the uncompressed original, or returns 404 if no original is present. Without this, the client would receive a body labelled `Content-Encoding: zstd` that it cannot decode. The check is Linux/BSD-only (uses `pread(2)`) and is skipped under `NGX_WIN32`.

**Example:**

```nginx
gzip_vary on;

location /static/ {
    zstd_static on;
    root /var/www;
}
```

Pre-compress files with a matching level to your workload:

```bash
zstd -3 -k /var/www/static/app.js   # creates app.js.zst alongside app.js
```

---

# Variables

## $zstd_ratio

The compression ratio achieved for the current response, expressed as the ratio of original size to compressed size (e.g. `3.42` means the compressed output is about 29% of the original). Only set when the filter module compressed the response.

Useful in access logs:

```nginx
log_format main '$remote_addr - $request - ratio: $zstd_ratio';
```

---

## $zstd_bytes_in

The number of uncompressed (input) bytes the filter consumed for the
current response. Only set once the filter has finished compressing the
response (log phase); not found otherwise. See
[`$zstd_bytes_out`](#zstd_bytes_out) below for a combined `log_format`
example.

## $zstd_bytes_out

The number of compressed (output) bytes the filter produced for the
current response. Same availability as `$zstd_bytes_in`.

Together these expose the **absolute** transfer saving, where
`$zstd_ratio` only gives the ratio. By construction
`$zstd_bytes_in / $zstd_bytes_out` equals `$zstd_ratio`:

```nginx
log_format zstd '$request in=$zstd_bytes_in out=$zstd_bytes_out '
                'ratio=$zstd_ratio';
```

---

# Testing & CI

Five workflows guard every change (badges at the top); their cadence
differs so PR feedback stays fast:

| Workflow | Cadence | What it does |
|---|---|---|
| **Build & Test** | every push & PR | Compiles the module against **nginx 1.31.0 mainline** and **Angie 1.11.5** with strict `-Werror` flags, then runs the full test suite: 46 `Test::Nginx::Socket` filter tests, 21 static-module tests, and end-to-end Python smoke tests (truncation, `Vary`, boundary sizes, repeated/concurrent requests, terminal-frame, the proxy-unbuffered and compression-matrix regressions, per-request CCtx isolation, reload-under-load, `zstd_long`/LDM, `$zstd_ratio`). A separate matrix entry rebuilds against **libzstd 1.4.x** (from source) to exercise the `< 1.5.6` and `≥ 1.4.0` fallback paths, and a parallel job rebuilds with **ASAN+UBSAN** and re-runs the smoke tests plus a `zstd_dict_file` config-reload leak check. A 10-minute mixed-load soak under ASAN+UBSAN runs on the weekly schedule. |
| **CodeQL** | every push & PR + weekly | GitHub's `security-extended` C/C++ analysis against a real module build. |
| **Security Scanners** | every push & PR + weekly | flawfinder, clang-tidy (`cert-*`, `bugprone-*`), and semgrep, with results uploaded as SARIF to the Security tab. |
| **Fuzzing** | nightly + PRs touching the parser | A libFuzzer harness for the `ngx_http_zstd_accept_encoding()` / `ngx_http_zstd_eval_qvalue()` RFC 9110 `Accept-Encoding`/q-value parser. The fuzz target is sliced from the shipped header at build time, so there is no copy drift. See [`fuzz/README.md`](fuzz/README.md). |
| **Valgrind Memcheck** | monthly + manual dispatch | A full Memcheck soak with `--track-origins=yes`, catching uninitialised-value reads and leaks that ASAN cannot. Monthly because a valgrind soak is ~20–50× slower than native. |

The test suite includes a dedicated regression test for every known
historical bug class:

* infinite-loop / CPU-spin DoS on zero-length and sub-stream-size bodies;
* the `proxy_buffering off` chunked-stream truncation ("bug B" —
  zero-size buffer forwarded to the writer), plus a ~504-cell
  compression-correctness matrix that decodes and byte-compares every
  transport × payload × encoding combination;
* per-request `ZSTD_CCtx` isolation (one request's compressor state
  bleeding into another) and reload-under-load response correctness;
* `$zstd_ratio` integer overflow on large bodies;
* filter ordering vs `sub_filter`; negative compression levels;
  `zstd_types` parsing; `zstd_max_length` enforcement (known and
  chunked length); `zstd_window_log`; `zstd_long`/LDM; `zstd_bypass`;
  the pledged-source-size path;
* `zstd_max_cctx_memory` rejects parameters that exceed the budget
  (config-load assertion);
* `zstd_static` declines `.zst` files whose magic number is not a real
  zstd frame (defence-in-depth against truncated / mis-renamed files);
* the multi-occurrence `Accept-Encoding` parser path (a header like
  `notzstd, zstd` must still negotiate zstd — covered by Perl tests
  *and* by continuous libFuzzer with ASAN/UBSAN over a NUL-free
  exact-size buffer);
* the `zstd_dict_file` feature, long-URI `.zst` path handling, and the
  `ZSTD_CDict` config-reload leak.

Run the suites locally:

```bash
# Perl suites (needs Test::Nginx::Socket and a built nginx)
TEST_NGINX_BINARY=/path/to/nginx prove t/00-filter.t t/01-static.t

# End-to-end smoke tests
python3 tools/test_encoding.py --nginx-binary /path/to/nginx

# Build and run the fuzzer (needs clang)
bash fuzz/build.sh && ./fuzz/fuzz_accept_encoding -max_total_time=60 fuzz/corpus/
```

# Benchmarks

Reproduce with `python3 tools/benchmark.py` (drives the `zstd`/`gzip`
CLIs linked against the same libzstd/zlib, so ratio is machine-stable;
throughput scales with CPU). Figures below: **libzstd 1.5.5**, single
core, `--repeat 3`, best wall-time.

| Payload | Codec | Ratio | MB/s |
|---|---|---:|---:|
| HTML, 58 KB (test fixture) | gzip-6 | 15.5 | 29 |
| | zstd-3 | 16.1 | 12 |
| | zstd-19 | 17.1 | 0.8 |
| JSON API, 256 KB | gzip-6 | 12.5 | 72 |
| | zstd-1 | 43.8 | 52 |
| | zstd-3 | 33.6 | 43 |
| JS, 512 KB | gzip-6 | 12.7 | 108 |
| | zstd-1 | 63.6 | 87 |
| | zstd-3 | 40.8 | 78 |
| Random 256 KB (incompressible) | gzip-6 | 1.00 | 31 |
| | zstd-3 | 1.00 | 36 |

Honest reading of these numbers:

* On **small** payloads (the 58 KB HTML fixture), low-level zstd is
  roughly on par with `gzip -6` and a touch slower — gzip is well tuned
  for small text. zstd's advantage grows with payload size.
* On **larger, structured** payloads zstd at a *low* level beats gzip
  decisively on both ratio and speed (e.g. ~44× vs ~12× on JSON,
  faster too). For typical web traffic, `zstd_comp_level 1`–`3` is the
  sweet spot.
* The synthetic JSON/JS generators are deliberately repetitive, so
  ratios there are inflated and *higher zstd levels show a lower ratio*
  — an artefact of trivially-redundant input, **not** representative of
  real assets. The HTML fixture (real-world content) shows the expected
  monotonic "higher level → better ratio, slower".
* High levels (≥ 9) cost CPU steeply for marginal gain on web content —
  reserve them for infrequently-generated, cached responses.

**How recent module changes affect these numbers.** The table above is
driven by the `zstd`/`gzip` CLIs against the same libzstd, so it
measures the *codec* — it is deliberately independent of nginx and does
**not** move when the module's internals change. The compression
**ratio** for a given level is therefore unchanged by any recent work.
What changed is the module's per-response *overhead* inside nginx:

* **Output buffers now default to `2 × ZSTD_CStreamOutSize()`**
  (previously a `4 × 32 KB` heuristic, and originally `32 × 4 KB`).
  Each `ZSTD_compressStream2()` call can now flush a complete internal
  block in one go instead of fragmenting it across calls, removing
  redundant compress round-trips and output-chain allocations per
  response. This shows up as lower CPU-per-response and less allocator
  churn under load — not as a different ratio or a different CLI MB/s
  figure. The trade is a higher per-request memory floor (~256 KB);
  see [`zstd_buffers`](#zstd_buffers).
* **`$zstd_ratio` now computes with a single division** instead of two
  — a log-path micro-cost, no effect on the response itself.
* **`zstd_long` (off by default)** can materially improve ratio on
  large, internally repetitive bodies that exceed the match window —
  but only when explicitly enabled, and the gain is workload-specific,
  so it is not reflected in the synthetic table above. Measure on your
  own assets before enabling.

In short: the codec figures here are stable by design; the recent
changes make the module *cheaper to run at the same ratio*, and add an
opt-in ratio lever (`zstd_long`) for specific workloads.

# Operations

**Reloads (`nginx -s reload`).** Compression state is per request: a
`ZSTD_CCtx` is created/reset per request and freed via an nginx pool
cleanup. A graceful reload spins up new workers and drains old ones
normally — in-flight responses on old workers finish on their existing
context; new requests use new workers. There is no shared compression
state to corrupt across a reload. The `zstd_dict_file` `ZSTD_CDict` is
loaded once per cycle and freed on the old cycle's cleanup; a
reload-leak regression for exactly this runs under ASAN in CI
(`tools/test_reload_leak.sh`).

**`zstd_dict_file`.** Loaded at config load in the `http` context, into
a `ZSTD_CDict` shared read-only by all workers (dictionary size capped
at 10 MB). The dictionary must be readable by the nginx user at config
load and reload. Changing it requires a reload. **Both ends must agree
on the dictionary**: HTTP has no dictionary negotiation, so only use
this where you control client and server (see the directive's warning).

**Rollback.** The module adds no persistent state, on-disk format, or
schema — it only transforms response bodies in memory. Rolling back is
purely "load the previous `.so` / previous nginx binary and reload":

1. Keep the previously-known-good module `.so` (or full nginx binary).
2. To disable instantly without a binary change: set `zstd off;` (and
   `zstd_static off;`) and `nginx -s reload` — responses immediately
   serve identity; no client/cache corruption (compressed and
   identity variants differ only by `Content-Encoding`, and
   `gzip_vary on` keeps caches correct).
3. To revert the binary: restore the prior `.so`/binary, `nginx -t`,
   then `nginx -s reload`.

No data migration, no irreversible step. A bad deploy is a one-line
config change or a binary swap away from rolled back.

**Pre-deploy soak.** `tools/soak.sh <nginx> <seconds> <concurrency>`
drives sustained mixed load (tiny/medium/large/compressible payloads,
zstd and non-zstd clients, the bypass path, a chunked upstream) and
fails on any sanitizer report, leak, crash, `[alert]`/`[emerg]`, or
corrupted response. Run it against an ASAN/UBSAN build (optionally
`USE_VALGRIND=1`) before shipping a change. CI runs a 10-minute soak
under ASAN+UBSAN on the weekly schedule (`Soak ASAN+UBSAN` job).

# Security

Compression of HTTP responses has a security dimension. See
[`SECURITY.md`](SECURITY.md) for the vulnerability-disclosure process
and the explicit in-scope / out-of-scope boundary (notably: BREACH
containment is `zstd_bypass`, not a fix; CRIME/POODLE are TLS-layer and
out of scope). The request parser is continuously fuzzed and the module
is built and load-tested under ASAN/UBSAN.

# Author

Alex Zhang (张超) \<zchao1995@gmail.com\>, UPYUN Inc.

Hardening, test suite, fuzzing and CI by Thijs Eilander and the
[deb.myguard.nl](https://deb.myguard.nl/) maintainers.

# License

Licensed under the [BSD 2-Clause License](LICENSE).
