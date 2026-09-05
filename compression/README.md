# nginx-compression — phase-0 prototype

Throwaway backend-interface prototype for the unified compression
module (RFC: [myguard-labs/nginx-zstd-module#109]). One filter module,
N backends behind one vtable (`ngx_http_compression.h`), election by
`compression_order`, gzip by defer/veto — never implemented.

Lives under `compression/` on the RFC's living review branch;
deliberately NOT wired into this repo's CI or its root `config` — the
zstd modules build exactly as before. Later phases land on the same
branch (phase 1 begins with the ngx_brotli history graft + the shared
dictionary store).

**The deliverable is the interface and [WRINKLES.md](WRINKLES.md)**,
not this code. Directives implemented: `compression on|off`,
`compression_order <codings...>` (tokens: `zstd`, `br`, `gzip`;
unknown or duplicate = config error; the list is the enable set),
`compression_min_length`, `compression_types`.

The addon builds TWO modules (the gzip/gzip_static split, kept
because this pair replaces modules that ship split and because the
static module must stay dependency-free):
`ngx_http_compression_filter_module` (the dynamic filter — links the
codec libraries and, when found, libcrypto for dictionary hashing)
and `ngx_http_compression_static_module` (sidecar serving — links
**nothing**; a static-only deployment such as a CDN edge or internal
artifact host loads a .so whose ldd shows only libc, with no
compression libraries installed at all). Dynamic builds emit two
.so files and take one `load_module` line each; either loads without
the other.

Build (nginx >= 1.23.0):

```bash
./configure --add-module=/path/to/nginx-zstd-module/compression
```

`compression/auto/detect` discovers the libraries with the parent
repo's hardened patterns — dynamic link first, then pkg-config
(`libzstd` needs `libzstd-dev` / `zstd-devel`; brotli needs
`libbrotli-dev` / `brotli-devel`, in RHEL's CRB repo). A missing
library is a **shape, not an error**: the build proceeds without that
backend, its coding tokens fail at config load with a pointer at the
build line, and static sidecar serving keeps working for every coding
(the `.zst` probe reads format constants, not library APIs — even the
zero-library build still subsumes gzip_static). Explicit paths via
`ZSTD_INC`/`ZSTD_LIB` and `BROTLI_INC`/`BROTLI_LIB` (MSVC: cmake's
`zstd_static.lib` and `brotlienc.lib`/`brotlicommon.lib`, POSIX path
spellings normalized via cygpath — see `tools/build-windows.sh` for
the zstd half of the Windows recipe); explicit paths that fail are a
configure error, not a fallback. `NGX_HTTP_COMPRESSION_NO_ZSTD=1` /
`NGX_HTTP_COMPRESSION_NO_BROTLI=1` opt out of a present library.

CI (`.github/workflows/compression.yml`) runs the eight Test::Nginx
suites plus both proxy-backed tools, the gzip-less no-compat build,
the three reduced backend shapes through the real opt-outs, the
genuine not-found detection path on a brotli-less runner, and strict
clang-tidy analyzer checks with proper nginx include paths.

Works with and without the core gzip module: gzip-less builds do their
own Accept-Encoding lookup, push their own `Vary: Accept-Encoding`,
and reject the `gzip` order token at config load. With gzip present,
Vary is delegated via `r->gzip_vary` — which the core emits only under
`gzip_vary on`, so the module warns at config load when that is off.

**Phase 1a** adds the shared dictionary store (see
`ngx_http_compression_dict.h` for the full rules):
`compression_dict_file <path> [sha256hex]` at http/server/location
(lists replace wholesale on inheritance; the bytes live once in a
cycle-global store regardless of how many levels reference them), the
RFC's provenance rules enforced at config load, and
`$compression_dicts_hashed` as the observable witness for the dedup
and the hash-policy in force. A supplied `sha256hex` is **verified**
against the bytes read by default (parent #198: a mismatch fails the
load, naming both values); `compression_dict_trust_hashes on;` (http
only, default off, parent #220) restores the trusted-verbatim fast
path — the literal is the negotiation key and the load-time SHA-256
is skipped for that line, the config-load cost at scale — for
deployments whose pipeline derives each literal from the exact file
it ships. It must precede every literal-carrying `compression_dict_file`
(a later declaration is a config-load error), lines without a literal
are hashed under either policy, and the "supplied never satisfies
unsupplied" audit stays live under trust as the safety net. The branch also carries the full
ngx_brotli hardened-fork history under `brotli/` (subtree merge; the
fork point is the merge's second parent).

The `optional` keyword on `compression_dict_file <path> [sha256]
[optional]` demotes deploy-race load failures to warnings instead of
refusing to start (an intentional deviation from the RFC's fail-fatal
rule, at the operator's insistence): missing/empty/unreadable
dictionaries are skipped — clients holding them degrade to the base
coding — while a stale or conflicting supplied hash is re-keyed to
the file's computed truth so clients holding the real file still
negotiate. Malformed hex stays fatal either way. Deploy tooling
should emit `optional` on generated lines; hand-written critical
entries stay strict by omitting it.

Two more dict-side policies:
`compression_dict_strict_path on;` (`http` only, default off, parent #165/#199)
opts every dictionary load into a stricter trust model — the path is resolved
one component at a time with `openat(O_NOFOLLOW)`, so a symlink
anywhere in it (a `current -> releases/N` deploy layout included,
which is why the default stays off) is refused rather than followed,
`.`/`..` components are rejected, and the file AND every directory
on the way to it must be owned by the loading principal or root and
not be group/other-writable (parent #316: no sticky-bit exemption, so
a dictionary under `/tmp` is refused — an ancestor a local user can
write into lets that user rename a file of their choosing into the
leaf's place). It must precede every `compression_dict_file` it
applies to; declaring it
after one is a config-load error rather than a silently unvetted
load. And `compression_dict_assume_secure_transport on;`
(`http`/`server`/`location`, default off, parent #158) is the
TLS-terminating-proxy acknowledgement: dictionary codings are only
negotiated on a secure context, and when nginx itself sees cleartext
because a proxy in front terminates TLS, this directive asserts —
as an operator statement, never inferred from client-settable
headers — that the hop the client spoke was secure.

**Phase 2** adds unified static sidecar serving: `compression_static
off|on|always` and `compression_static_order` (tokens `zstd`/`br`/
`gzip`; the list is the enable set AND the probe order; default
`br zstd gzip` — static prefers br because its CPU was spent at build
time). One content-phase handler probes `file.zst`/`.br`/`.gz` in
order and serves the first acceptable hit; no compression library is
called, which makes gzip fully first-class here — a gzip-less build
serves `.gz` sidecars byte-exact. The parent zstd_static's
magic + declared-window probe rides along intact (an oversized-window
`.zst` declines to the NEXT coding in the order, not just identity),
`always` serves the first existing sidecar with no Vary, and a static
miss falls through to the dynamic filter with no latches touched.

**Phase 1b** makes the dictionary codings real: RFC 9842
Available-Dictionary negotiation against the store (RFC 8941 byte
sequence, strict shape), per-backend wire-prologue emitters (dcz's
40-byte skippable frame with a checksummed stream; dcb's 36 raw
bytes), election of `dcz`/`dcb` at their base coding's position on an
explicit Accept-Encoding token only (`*` never elects them), graceful
degrade to the base coding on any negotiation miss, and a hoisted
`Vary: Available-Dictionary` on every eligible response wherever
dictionaries are configured — identity fallbacks included.

**Phase 3** (productization) begins with the per-coding tuning
directives, keyed by coding so a new backend needs no new commands:
`compression_level <coding> <n>` (zstd `-131072..22`, `0` = library
default, default `3`; br quality `0..11`, default `6`) and
`compression_window <coding> <size>` (a power-of-two size stored as
its log2: zstd `1k..128m` acting as a per-request memory ceiling,
unset by default; br `1k..16m`, default `512k`). Bounds and defaults
are declared by the backend in the vtable and validated at config
load. The `gzip` token is rejected with a pointer at
`gzip_comp_level` (defer means the core module's own tuning applies),
and `dcz`/`dcb` are rejected with a pointer at their base coding — a
dictionary variant shares the base coding's parameters (brotli bakes
quality into the prepared dictionary; there is nothing separate to
tune).

Phase 3 also brings output-buffer recycling (the core gzip filter's
busy/free pattern): shipped buffers are reclaimed once downstream
drains them, and `compression_buffers <num> [size]` caps how many a
request may hold in flight (default `32`, size defaulting to the
backend's recommended step size — an explicit size overrides it, and
the dict-prologue clamp applies either way). At the cap, production
pauses until the client drains — the backstop that keeps a slow
client behind a fast upstream from pinning unbounded output memory.
The num-times-size product is bounded at config load (the parent's #167):
totals above a hard per-request cap are refused, and
`compression_buffers_unsafe on` is the explicit acknowledgement that
accepts a larger total anyway — for the operator who has done the
arithmetic against their worker memory and wants the cap lifted, with
the refusal message naming the product it computed.
The backend roster is also build-conditional
(`NGX_HTTP_COMPRESSION_HAVE_ZSTD`/`_BROTLI`): a build without one or
both libraries compiles, elects what remains, rejects absent codings
with a pointer at the build, and still serves every static sidecar —
static serving reads format constants, not library APIs.

`compression_static_dict_bypass on` resolves the sidecar-vs-dictionary
collision found in production: the static module serves a
precompressed sidecar before the filter can negotiate dcz/dcb, so a
browser holding the dictionary would get the full sidecar instead of
the delta. With the bypass on, the static handler stands aside for
requests that both carry `Available-Dictionary` and explicitly accept
a dictionary coding (both modes, `always` included). Opt-in per
location — emit it beside `compression_dict_file` — and default off,
so static-only deployments never serve identity to dict-capable
clients. Tradeoff: a dictionary miss pays runtime compression instead
of the sidecar.

`compression_http_version 1.0|1.1` (default `1.1`, gzip_http_version
parity — Mark's call from the soak): HTTP/1.0 requests defer to core
gzip untouched, since an RFC 1945-era client is gzip-at-best and 1.0
frequently means an ancient intermediary. The skip is a deferral, not
a veto — lowering `gzip_http_version` still serves those clients gzip.

`compression_max_length <size>` is the parents' worker-protection
ceiling: declared bodies above it skip compression, and a running
input counter enforces the same limit on chunked/undeclared streams
mid-response (a misdeclaring upstream aborts the request — protecting
the worker beats completing one runaway response). Unset by default.
The `$compression_ratio`, `$compression_bytes_in` and
`$compression_bytes_out` variables (parent `$zstd_*` parity) are
log-phase counters for the compressed response.

Bypass predicates round out the phase-3 filter directives:
`compression_bypass $var ...` serves identity when any predicate
variable resolves non-empty and not `"0"` (the parents' zstd_bypass /
brotli_bypass semantics), and `compression_bypass_vary <header>`
names the request header the decision varies on so shared caches key
correctly — emitted on both the bypassed and compressed responses.
One deliberate delta from the parents: bypass vetoes the `gzip`
election token too. In the standalone modules a bypassed response can
still come back gzip-compressed by core gzip; here gzip is part of
the stack, and "do not compress this endpoint" has to mean the whole
stack.

A response carrying a `Cache-Control: no-transform` directive is
served identity with no directive needed (RFC 9110 §7.7; the parent
repo's #251): every `Cache-Control` line in the response headers is
checked, the match is per-directive (a quoted parameter value like
`extension="no-transform"` does not trigger it), and the same
whole-stack rule applies — the gzip election token is vetoed too.
Only headers already present when the filter runs count, which in
practice means proxied/upstream responses; an `add_header` in the
same location runs after the compression decision.

[myguard-labs/nginx-zstd-module#109]: https://github.com/myguard-labs/nginx-zstd-module/issues/109
