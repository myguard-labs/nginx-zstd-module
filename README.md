[![Build & Test](https://github.com/eilandert/zstd-nginx-module/actions/workflows/build-test.yml/badge.svg)](https://github.com/eilandert/zstd-nginx-module/actions/workflows/build-test.yml)
[![CodeQL](https://github.com/eilandert/zstd-nginx-module/actions/workflows/codeql.yml/badge.svg)](https://github.com/eilandert/zstd-nginx-module/actions/workflows/codeql.yml)
[![Security Scanners](https://github.com/eilandert/zstd-nginx-module/actions/workflows/security-scanners.yml/badge.svg)](https://github.com/eilandert/zstd-nginx-module/actions/workflows/security-scanners.yml)
[![Fuzzing](https://github.com/eilandert/zstd-nginx-module/actions/workflows/fuzzing.yml/badge.svg)](https://github.com/eilandert/zstd-nginx-module/actions/workflows/fuzzing.yml)

📖 **Background reading:** [nginx zstd vs brotli vs zlib-ng — a compression comparison](https://deb.myguard.nl/2026/05/nginx-zstd-vs-brotli-vs-zlib-ng-compression/)

# zstd-nginx-module

An nginx module for [Zstandard (zstd)](https://facebook.github.io/zstd/) compression. Zstandard typically achieves better compression ratios than gzip at comparable or faster speeds, making it a good choice for reducing transmitted response sizes.

This is a hardened fork: every build is exercised against **nginx mainline and [Angie](https://angie.software/)**, the full test suite runs under **ASAN/UBSAN**, the `Accept-Encoding` parser is **continuously fuzzed**, and **CodeQL** plus flawfinder/semgrep/clang-tidy run on every change (see the badges above and [Testing & CI](#testing--ci)).

# Table of Contents

* [Status](#status)
* [Synopsis](#synopsis)
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
    * [zstd_dict_file](#zstd_dict_file)
  * [ngx_http_zstd_static_module](#ngx_http_zstd_static_module)
    * [zstd_static](#zstd_static)
* [Variables](#variables)
  * [$zstd_ratio](#zstd_ratio)
  * [$zstd_bytes_in](#zstd_bytes_in)
  * [$zstd_bytes_out](#zstd_bytes_out)
* [Testing & CI](#testing--ci)
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
    # Only responses >= 1000 bytes are compressed (smaller ones see no benefit).
    zstd             on;
    zstd_comp_level  3;
    zstd_min_length  1000;
    zstd_types       text/plain text/css application/json
                     application/javascript text/xml application/xml
                     application/xml+rss text/javascript image/svg+xml;

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

# Directives

## ngx_http_zstd_filter_module

This filter module compresses responses on the fly using zstd. It runs after the upstream or file handler generates the response, and before nginx sends it to the client. Compression is applied only when the client signals support via `Accept-Encoding: zstd`. All 2xx responses are eligible for compression, as well as 403 and 404 (which often carry compressible error bodies).

> **Required:** Enable `gzip_vary on;` alongside this module. When compression is applied, the module sets `r->gzip_vary = 1`, which causes nginx to emit a `Vary: Accept-Encoding` response header — but only when `gzip_vary` is enabled. Without it, proxies and CDNs may cache and serve compressed responses to clients that do not support zstd.

> **ETag behaviour:** When a response is compressed, nginx automatically weakens the `ETag` value (converting `"abc"` to `W/"abc"` if it was strong). This is correct per HTTP semantics — a compressed representation is a different entity variant — but it means strong ETag validation (`If-Match`) will not match across compressed and uncompressed responses. CDN edge nodes that cache both variants will see different ETags for each.

> **Coexisting with `gzip` and `brotli`:** It is safe to enable `zstd`, the [`brotli`](https://github.com/google/ngx_brotli) filter, and the built-in [`gzip`](https://nginx.org/en/docs/http/ngx_http_gzip_module.html) filter on the same location with overlapping `*_types`. A response is only ever compressed once: nginx body filters run in a fixed chain, and the first encoder whose `Accept-Encoding` test passes wins, setting `Content-Encoding` so the later encoders skip the already-encoded body. This module is ordered to run **before** `brotli` and `gzip`, so a client that advertises `Accept-Encoding: br, gzip, zstd` receives `zstd`. Clients that do not advertise `zstd` fall through to `brotli`, then `gzip`. Always pair this with `gzip_vary on;` so each encoded variant is cached separately by proxies and CDNs.

---

### zstd

**Syntax:** `zstd on | off;`
**Default:** `zstd off;`
**Context:** `http, server, location, if in location`

Enables or disables on-the-fly zstd compression for responses.

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

---

### zstd_min_length

**Syntax:** `zstd_min_length length;`
**Default:** `zstd_min_length 20;`
**Context:** `http, server, location`

Sets the minimum response size (in bytes) required for compression to apply. The size is taken from the `Content-Length` response header; responses without `Content-Length` are always eligible.

> **Note:** The built-in default of `20` bytes is intentionally low (matching nginx's `gzip_min_length` default) but is rarely the right value in practice. Compressing responses smaller than ~200 bytes typically produces output that is *larger* than the input, wasting CPU with no benefit. A value of `1000` is a more practical starting point for most deployments.

**Example:**

```nginx
zstd_min_length 1000;  # skip compression for responses smaller than 1KB
```

---

### zstd_max_length

**Syntax:** `zstd_max_length length;`
**Default:** `—` (no limit)
**Context:** `http, server, location`

Sets the maximum response size that will be compressed. Responses larger than this value are passed through uncompressed. The size is taken from the `Content-Length` response header.

> **Important:** `zstd_max_length` is **not enforced** for streaming or chunked responses that do not include a `Content-Length` header. Such responses are always compressed regardless of their final size. If you need to limit CPU exposure for large streaming responses (e.g. proxied video or large file downloads), ensure upstream always sets `Content-Length`, or avoid enabling zstd on those locations.

By default there is no upper limit. You may want to set one if very large responses (e.g. multi-megabyte file downloads) should bypass compression to avoid holding the worker process busy.

**Example:**

```nginx
zstd_max_length 10m;  # don't compress responses larger than 10 MB
```

---

### zstd_types

**Syntax:** `zstd_types mime-type ...;`
**Default:** `zstd_types text/html;`
**Context:** `http, server, location`

Compresses responses with the listed MIME types in addition to `text/html`. Use `*` to match all MIME types.

> **Note:** Only compressible content types (text, structured data, SVG, etc.) benefit from compression. Binary formats such as images (JPEG, PNG, WebP), audio, and video are already compressed and should be excluded.

**Example for a typical web application:**

```nginx
zstd_types
    text/plain
    text/css
    text/xml
    text/javascript
    application/json
    application/javascript
    application/xml
    application/xml+rss
    application/atom+xml
    image/svg+xml;
```

---

### zstd_buffers

**Syntax:** `zstd_buffers number size;`
**Default:** `zstd_buffers 32 4k;` (on 4 KB pages) or `zstd_buffers 16 8k;` (on 8 KB pages)
**Context:** `http, server, location`

Configures the number and size of output buffers used during compression. The total buffer space is `number × size`. The defaults give a fixed 128 KB of buffer space regardless of platform page size, which is appropriate for most workloads.

Increasing these values allows larger chunks to be accumulated before writing, potentially improving throughput at the cost of higher per-request memory usage.

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

### zstd_dict_file

**Syntax:** `zstd_dict_file /path/to/dict;`
**Default:** `—`
**Context:** `http`

Loads a pre-trained zstd dictionary for use during compression. Dictionaries can significantly improve compression ratios for small, structurally similar responses (e.g. JSON API responses).

> **Warning:** The `Content-Encoding: zstd` token in HTTP does not include any mechanism for the client to discover or negotiate which dictionary the server is using. Only use this directive if you control both ends of the connection and can guarantee that both the server and client use the same dictionary (for example, by advertising it via a custom HTTP header). See [tokers/zstd-nginx-module#2](https://github.com/tokers/zstd-nginx-module/issues/2) for background.

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
response (log phase); not found otherwise.

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

Every push and pull request runs four workflows (badges at the top):

| Workflow | What it does |
|---|---|
| **Build & Test** | Compiles the module against **nginx 1.31.0 mainline** and **Angie 1.11.5** with strict `-Werror` flags, then runs the full test suite: 37 `Test::Nginx::Socket` filter tests, 20 static-module tests, and end-to-end Python smoke tests (truncation, `Vary`, boundary sizes, repeated/concurrent requests, terminal-frame, `$zstd_ratio`). A parallel job rebuilds with **ASAN+UBSAN** and re-runs the smoke tests plus a `zstd_dict_file` config-reload leak check. |
| **CodeQL** | GitHub's `security-extended` C/C++ analysis against a real module build. |
| **Security Scanners** | flawfinder, clang-tidy (`cert-*`, `bugprone-*`), and semgrep, with results uploaded as SARIF to the Security tab. |
| **Fuzzing** | A libFuzzer harness for `ngx_http_zstd_accept_encoding()` — the RFC 7231 `Accept-Encoding`/q-value parser. The fuzz target is sliced from the shipped header at build time, so there is no copy drift. Runs nightly and on PRs that touch the parser. See [`fuzz/README.md`](fuzz/README.md). |

The test suite includes a dedicated regression test for every known
historical bug class (infinite-loop/CPU-spin DoS, `$zstd_ratio` integer
overflow, filter ordering vs `sub_filter`, negative compression levels,
`zstd_types` parsing, `max_length` enforcement, the `zstd_dict_file`
feature, long-URI `.zst` path handling, and the `ZSTD_CDict` reload leak).

Run the suites locally:

```bash
# Perl suites (needs Test::Nginx::Socket and a built nginx)
TEST_NGINX_BINARY=/path/to/nginx prove t/00-filter.t t/01-static.t

# End-to-end smoke tests
python3 tools/test_encoding.py --nginx-binary /path/to/nginx

# Build and run the fuzzer (needs clang)
bash fuzz/build.sh && ./fuzz/fuzz_accept_encoding -max_total_time=60 fuzz/corpus/
```

# Author

Alex Zhang (张超) \<zchao1995@gmail.com\>, UPYUN Inc.

Hardening, test suite, fuzzing and CI by the [deb.myguard.nl](https://deb.myguard.nl/) maintainers.

# License

Licensed under the [BSD 2-Clause License](LICENSE).
