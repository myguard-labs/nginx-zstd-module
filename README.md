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
    * [zstd_bypass](#zstd_bypass)
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

# Set and forget

If you just want sane production compression without reading every
directive, paste this into the `http {}` block of `nginx.conf` and move
on. It is tuned for typical web traffic (HTML/JSON/JS/CSS/SVG) and
relies on the module's built-in defaults for everything not shown.

```nginx
http {
    # --- zstd: set and forget ---
    zstd              on;
    zstd_comp_level   3;     # sweet spot: strong ratio, cheap CPU
    zstd_min_length   256;   # don't bother compressing tiny responses
    zstd_types        text/plain text/css application/json
                      application/javascript text/xml application/xml
                      application/xml+rss text/javascript image/svg+xml;

    # Required so proxies/CDNs cache compressed and identity variants
    # separately. The module warns at startup if this is missing.
    gzip_vary         on;

    # Pre-compressed static assets (optional but free if you ship .zst)
    # zstd_static     on;
}
```

Why these values, and why nothing else is needed:

* **`zstd_comp_level 3`** — for real web content this beats `gzip -6`
  on ratio at comparable or better speed (see [Benchmarks](#benchmarks)).
  Levels ≥ 9 cost CPU steeply for marginal gain; only raise it for
  infrequently-generated, cached responses.
* **`zstd_min_length 256`** — below a few hundred bytes the zstd frame
  overhead outweighs any saving. 256 is a safe floor; the built-in
  default is 20 if you omit it.
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
| **libzstd** | **1.4.0** | **≥ 1.5.6** | 1.5.x |
| **OS** | Linux/BSD/RHEL-family | — | Ubuntu (GitHub runners) |

Notes on the libzstd floor — these are enforced in code, not assumed:

* **< 1.4.0**: the streaming API the module uses (`ZSTD_compressStream2`)
  is unavailable; this is the hard minimum. Negative `zstd_comp_level`
  values are also unsupported and are clamped to `1` with a warning
  (guarded by `#if ZSTD_VERSION_NUMBER >= 10400`).
* **< 1.5.6**: `zstd_target_cblock_size` has no effect — the directive
  is accepted but silently ignored (`#ifdef ZSTD_c_targetCBlockSize`).
  Everything else works.
* **≥ 1.5.6**: every directive is fully functional.

"CI-verified" means every push builds and runs the full test suite
against that exact version (see [Testing & CI](#testing--ci)). Other
versions within the stated ranges are expected to work but are not
continuously exercised.

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

> **Note:** length-padding "anti-BREACH" schemes are intentionally
> **not** provided: small pads are defeated statistically and large
> ones waste bandwidth, giving false confidence.

---

### zstd_dict_file

**Syntax:** `zstd_dict_file /path/to/dict;`
**Default:** `—`
**Context:** `http`

Loads a pre-trained zstd dictionary for use during compression. Dictionaries can significantly improve compression ratios for small, structurally similar responses (e.g. JSON API responses).

> **Warning:** The `Content-Encoding: zstd` token in HTTP does not include any mechanism for the client to discover or negotiate which dictionary the server is using. Only use this directive if you control both ends of the connection and can guarantee that both the server and client use the same dictionary (for example, by advertising it via a custom HTTP header). See [tokers/zstd-nginx-module#2](https://github.com/tokers/zstd-nginx-module/issues/2) for background.

**Example:**

```nginx
http {
    # Loaded once per cycle; must be readable by the nginx user.
    # Train it with: zstd --train samples/*.json -o /etc/nginx/api.dict
    zstd_dict_file  /etc/nginx/api.dict;

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
