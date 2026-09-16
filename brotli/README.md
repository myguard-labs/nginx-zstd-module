# ngx_brotli

Brotli is a generic-purpose lossless compression algorithm that compresses data
using a combination of a modern variant of the LZ77 algorithm, Huffman coding
and 2nd order context modeling, with a compression ratio comparable to the best
currently available general-purpose compression methods. It is similar in speed
with deflate but offers more dense compression.

ngx_brotli is a set of two nginx modules:

- ngx_brotli filter module - used to compress responses on-the-fly,
- ngx_brotli static module - used to serve pre-compressed files.

## About this fork

This is a maintained, hardened fork of
[google/ngx_brotli](https://github.com/google/ngx_brotli), following the
same approach as
[nginx-zstd-module](https://github.com/myguard-labs/nginx-zstd-module):
reproducible builds, a continuously fuzzed request-parsing path, and CI
against current nginx. Differences from upstream:

- **Build:** system-first brotli detection via `pkg-config libbrotlienc`
  with the bundled submodule as fallback (restores pre-`63ca02a`
  packaging behaviour, by Mikel Olasagasti); the bundled submodule is
  pinned to the released brotli v1.2.0 tag instead of floating; sh-sourced
  files are pinned to LF so Windows checkouts build under WSL.
- **Accept-Encoding parsing** is a shared, length-bounded RFC 9110
  walker (ported from nginx-zstd-module, where it is continuously fuzzed
  with an independent differential oracle), replacing two hand-maintained
  copies of a substring scan. Five deliberate behaviour changes, all
  toward the RFC: the `*` wildcard now matches `br`; a coding name inside
  a quoted parameter value (e.g. `gzip;x="a, br"`) no longer fabricates a
  phantom `br` token; `;Q=0` refusals are honored (the weight name is
  case-insensitive); malformed weights make an element non-matching
  instead of defaulting to accept; and a later duplicate explicit token
  wins (`br;q=0, br` now accepts).
- **`brotli_static` gzip fallback fix:** the old code latched gzip off
  before knowing whether a `.br` file exists, so a client accepting
  `br, gzip` with only a `.gz` file on disk got identity instead of the
  `gzip_static` response. The latch now fires only once the `.br` file is
  confirmed.

- **Hardening additions:** `brotli_max_length` (a declared-length gate
  plus a running input cap in the body filter, so a chunked or
  misdeclaring upstream cannot feed the encoder unbounded input);
  `brotli_bypass` / `brotli_bypass_vary` per-request bypass predicates
  (the operator lever for BREACH-style exposures, with the cache key the
  bypass decision varies on declared explicitly);
  `BROTLI_PARAM_SIZE_HINT` set from the declared content length; a
  config-load warning when `brotli`/`brotli_static` is enabled in a
  location whose effective `gzip_vary` is off (matching the zstd
  siblings — without `Vary: Accept-Encoding` a shared cache can serve
  the compressed variant to a client that cannot decode it;
  `brotli_static always` is exempt since it does not vary; when
  [ngx_http_compression_vary_filter_module](https://github.com/HanadaLee/ngx_http_compression_vary_filter_module)
  is loaded — it emits the header from `r->gzip_vary` in place of the
  `gzip_vary` directive wherever `compression_vary on` applies — the
  per-location warnings collapse into one summary warning per module
  asking you to verify `compression_vary on` covers those locations,
  since that directive itself defaults to off and its effective value
  cannot be read from another module).
- **Tests:** a Test::Nginx regression suite (`t/`) covering the
  negotiation matrix, bypass, caps, and the static-module fallback
  regression, run in CI alongside the roundtrip smoke tool and the fuzz
  harness.

- **RFC 9842 `dcb` shared-dictionary compression** via the repeatable
  `brotli_dcb_dict_file` directive (`http`/`server`/`location`). Each
  occurrence loads one dictionary — typically a previous version of the
  resource — and registers its SHA-256 as the negotiation key. An
  optional second argument supplies that SHA-256 as 64 hex characters —
  `brotli_dcb_dict_file /path/main-AAA.js <sha256hex>;` — and is
  trusted verbatim, skipping the load-time hashing pass entirely; deploy
  tooling that generates the directive list has usually just computed
  the hashes anyway (see [`examples/`](examples/)). Only supply hashes
  for content-hashed immutable assets: a *stale* supplied hash keeps
  matching, and the resulting responses may fail to decode or silently
  decode to wrong content (a same-size stale dictionary yields wrong
  bytes — the dcb stream carries no content checksum), fanned out by
  any shared cache to every client advertising the stale hash; a
  self-computed hash of a changed file simply stops matching (safe
  fallback to plain `br`). A request
  whose `Available-Dictionary` matches a loaded dictionary and whose
  `Accept-Encoding` lists `dcb` explicitly (the `*` wildcard deliberately
  does not match) gets the response compressed against that dictionary
  as `Content-Encoding: dcb`: the 36-byte header (`FF 44 43 42` + the
  dictionary SHA-256) followed by a brotli stream using it as a raw
  shared dictionary. Chrome 130+ negotiates this automatically for
  same-origin resources; requests with `Sec-Fetch-Site` other than
  `same-origin`/`none` fall back to plain `br`, as does every other gate
  miss. `Vary: Available-Dictionary` is emitted on every variant
  (including the identity fallback) whenever dictionaries are
  configured. Advertise the dictionary with one header on the resource
  itself — `add_header Use-As-Dictionary 'match="/app/main-*.js"';` —
  and register the previous build's file at deploy time; a
  ready-to-adapt config and deploy script live in
  [`examples/`](examples/), and
  [nginx-zstd-module's `zstd_dcz_dict_file` docs](https://github.com/myguard-labs/nginx-zstd-module#zstd_dcz_dict_file)
  cover the full deployment pattern (locale layouts, dedupe, rotation) —
  the two directives are deliberate twins, and serving both `dcb` and
  `dcz` from the same locations works (clients pick one). Requires
  brotli ≥ 1.1 (the shared-dictionary encoder API — the pinned
  submodule and any current distro libbrotli qualify); building against
  an older library rejects the directive at config load. Dictionary
  hashing uses libcrypto's EVP SHA-256 when detected at build time —
  roughly an order of magnitude faster, which at hundreds of registered
  dictionaries turns seconds of `nginx -t`/reload time into a blip
  (`NGX_BROTLI_NO_LIBCRYPTO=1` in the configure environment opts out) —
  with a portable implementation built in as the fallback. Empty,
  oversized (>10 MB) and duplicate-hash dictionaries are config-load
  errors (supplied hashes are compared as declared; with computed
  hashes "duplicate" means identical content). Verify end-to-end: strip the first 36 bytes of a response and
  `brotli -d -D <dict>` — byte-exact against origin.
  **Troubleshooting:** if `Vary: Available-Dictionary` appears but dcb
  never negotiates for hashes you know are right, run
  `nginx -T | grep dcb_dict_file` and check the loaded entries are your
  dictionary *files* — a deploy-generated list of directives must be
  pulled in with `include`, not passed to `brotli_dcb_dict_file` itself
  (which would loyally load the list file as a one-entry dictionary
  that matches nothing).


## Table of Contents

- [Status](#status)
- [Installation](#installation)
- [Configuration directives](#configuration-directives)
  - [`brotli_static`](#brotli_static)
  - [`brotli`](#brotli)
  - [`brotli_types`](#brotli_types)
  - [`brotli_buffers`](#brotli_buffers)
  - [`brotli_comp_level`](#brotli_comp_level)
  - [`brotli_window`](#brotli_window)
  - [`brotli_min_length`](#brotli_min_length)
- [Variables](#variables)
  - [`$brotli_ratio`](#brotli_ratio)
- [Sample configuration](#sample-configuration)
- [Contributing](#contributing)
- [License](#license)

## Status

Both Brotli library and nginx module are under active development.

## Installation

### Statically compiled

Checkout the latest `ngx_brotli` and build the dependencies:

```
git clone --recurse-submodules -j8 https://github.com/google/ngx_brotli
cd ngx_brotli/deps/brotli
mkdir out && cd out
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_FLAGS="-Ofast -m64 -march=native -mtune=native -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" -DCMAKE_CXX_FLAGS="-Ofast -m64 -march=native -mtune=native -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" -DCMAKE_INSTALL_PREFIX=./installed ..
cmake --build . --config Release --target brotlienc
cd ../../../..
```


    $ cd nginx-1.x.x
    $ export CFLAGS="-m64 -march=native -mtune=native -Ofast -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections"
    $ export LDFLAGS="-m64 -Wl,-s -Wl,-Bsymbolic -Wl,--gc-sections"
    $ ./configure --add-module=/path/to/ngx_brotli
    $ make && make install
  
This will compile the module directly into Nginx.


### Dynamically loaded

    $ cd nginx-1.x.x
    $ ./configure --with-compat --add-dynamic-module=/path/to/ngx_brotli
    $ make modules

You will need to use **exactly** the same `./configure` arguments as your Nginx configuration and append `--with-compat --add-dynamic-module=/path/to/ngx_brotli` to the end, otherwise you will get a "module is not binary compatible" error on startup. You can run `nginx -V` to get the configuration arguments for your Nginx installation.

`make modules` will result in `ngx_http_brotli_filter_module.so` and `ngx_http_brotli_static_module.so` in the `objs` directory. Copy these to `/usr/lib/nginx/modules/` then add the `load_module` directives to `nginx.conf` (above the http block):
```nginx
load_module modules/ngx_http_brotli_filter_module.so;
load_module modules/ngx_http_brotli_static_module.so;
```


### Windows (MSVC)

nginx's win32 build (MSYS shell + `cl`) works as a static `--add-module`
build. Build the bundled brotli first, into the `deps/brotli/out`
directory the module's config expects, with the **static CRT** to match
nginx's `cl` defaults — CMake's default `/MD` runtime produces
LIBCMT/MSVCRT conflicts at the final link:

```
cd ngx_brotli/deps/brotli
cmake -B out -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=OFF -DBROTLI_DISABLE_TESTS=ON \
      -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded
cmake --build out
```

Then configure nginx with a **relative** `--add-module` path (`cl`
cannot open MSYS-style `/c/...` absolute paths). Two upstream bugs are
fixed in this fork's config for MSVC to work at all: the compiler
branch guarded on `NGX_MSVC_VER`, a variable modern nginx no longer
defines, so `cl` received the gcc-only `-Wno-deprecated-declarations`
(fatal `D8021`); and the link flags were gcc-spelled `-L`/`-l`, which
`cl` drops with a `D9002` warning, leaving every `BrotliEncoder*`
symbol unresolved — the config now names the `.lib` files outright.

`brotli_static` links no brotli library at all (it only serves
pre-compressed `.br` files), so it is unaffected by any of the encoder
link mechanics.

A complete, SHA-pinned build script that assembles a static Windows
`nginx.exe` with this module (and optionally the zstd pair and
headers-more) lives in nginx-zstd-module's
[`tools/build-windows.sh`](https://github.com/myguard-labs/nginx-zstd-module/blob/master/tools/build-windows.sh),
including the VS-prompt/MSYS2 launch steps above and native-perl
detection for the OpenSSL build.


## Configuration directives

### `brotli_static`

- **syntax**: `brotli_static on|off|always`
- **default**: `off`
- **context**: `http`, `server`, `location`

Enables or disables checking of the existence of pre-compressed files with`.br`
extension. With the `always` value, pre-compressed file is used in all cases,
without checking if the client supports it.

### `brotli`

- **syntax**: `brotli on|off`
- **default**: `off`
- **context**: `http`, `server`, `location`, `if`

Enables or disables on-the-fly compression of responses.

### `brotli_types`

- **syntax**: `brotli_types <mime_type> [..]`
- **default**: `text/html`
- **context**: `http`, `server`, `location`

Enables on-the-fly compression of responses for the specified MIME types
in addition to `text/html`. The special value `*` matches any MIME type.
Responses with the `text/html` MIME type are always compressed.

### `brotli_buffers`

- **syntax**: `brotli_buffers <number> <size>`
- **default**: `32 4k|16 8k`
- **context**: `http`, `server`, `location`

**Deprecated**, ignored.

### `brotli_comp_level`

- **syntax**: `brotli_comp_level <level>`
- **default**: `6`
- **context**: `http`, `server`, `location`

Sets on-the-fly compression Brotli quality (compression) `level`.
Acceptable values are in the range from `0` to `11`.

### `brotli_window`

- **syntax**: `brotli_window <size>`
- **default**: `512k`
- **context**: `http`, `server`, `location`

Sets Brotli window `size`. Acceptable values are `1k`, `2k`, `4k`, `8k`, `16k`,
`32k`, `64k`, `128k`, `256k`, `512k`, `1m`, `2m`, `4m`, `8m` and `16m`.

### `brotli_min_length`

- **syntax**: `brotli_min_length <length>`
- **default**: `20`
- **context**: `http`, `server`, `location`

Sets the minimum `length` of a response that will be compressed.
The length is determined only from the `Content-Length` response header field.

## Variables

### `$brotli_ratio`

Achieved compression ratio, computed as the ratio between the original
and compressed response sizes.

## Sample configuration

```
brotli on;
brotli_comp_level 6;
brotli_static on;
brotli_types application/atom+xml application/javascript application/json application/vnd.api+json application/rss+xml
             application/vnd.ms-fontobject application/x-font-opentype application/x-font-truetype
             application/x-font-ttf application/x-javascript application/xhtml+xml application/xml
             font/eot font/opentype font/otf font/truetype image/svg+xml image/vnd.microsoft.icon
             image/x-icon image/x-win-bitmap text/css text/javascript text/plain text/xml;
```

## Contributing

See [Contributing](CONTRIBUTING.md).

## License

    Copyright (C) 2002-2015 Igor Sysoev
    Copyright (C) 2011-2015 Nginx, Inc.
    Copyright (C) 2015 Google Inc.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
    OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
    OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
    SUCH DAMAGE.
