# AGENTS.md — working in zstd-nginx-module

Guidance for AI agents (and humans) modifying this repository. Everything
here was verified against the source at the time of writing; if code and
this file disagree, **trust the code and fix this file**.

## What this is

An nginx C module providing Zstandard compression, in two parts compiled
together:

| Module | File | Role |
|---|---|---|
| `ngx_http_zstd_filter_module` | `filter/ngx_http_zstd_filter_module.c` | On-the-fly response compression (HTTP body filter) |
| `ngx_http_zstd_static_module` | `static/ngx_http_zstd_static_module.c` | Serves pre-compressed `.zst` files (gzip_static equivalent) |
| shared | `ngx_http_zstd_common.h` | `static inline` helpers used by both — notably `ngx_http_zstd_accept_encoding()` (RFC 7231 parser) and `ngx_http_zstd_ok()` |

Build glue: top-level `config` sources `filter/config` + `static/config`
(autoconf-style nginx add-module). `ZSTD_INC` / `ZSTD_LIB` env vars
select a custom libzstd; unset = system zstd. Dynamic linking is
preferred by the configs.

## Hard rules

1. **No AI co-author trailers.** Never add `Co-Authored-By: Claude ...`
   (or any AI attribution) to commits, squash messages, or PR bodies.
   This is a standing project rule (also in `/opt/packages/CLAUDE.md`).
2. **Never commit to `master` directly.** Branch, PR, let CI go green,
   squash-merge. The repo takes no required status checks today, but
   merging red is not acceptable.
3. **Don't fabricate work.** If an investigation shows a proposed change
   is unnecessary (e.g. the audited `disable_symlinks` "gap" that turned
   out to already be correct), drop it and say so — do not invent a
   diff to make a task look done.
4. **Verify, don't assume.** Build it, run the suite, exercise the path
   against a real nginx before claiming it works. Local YAML/lint
   passing is necessary, not sufficient.

## Repository layout

```
filter/ngx_http_zstd_filter_module.c   filter module (~1.2k LoC)
static/ngx_http_zstd_static_module.c   static module
ngx_http_zstd_common.h                 shared inline helpers
config, filter/config, static/config   nginx add-module build glue
t/00-filter.t                          Perl Test::Nginx::Socket suite (filter)
t/01-static.t                          Perl Test::Nginx::Socket suite (static)
t/suite/                               test fixture (`test`, `test.zst`)
tools/test_encoding.py                 end-to-end smoke tester (decompresses, asserts)
tools/test_terminal_frame.py           empty-output ZSTD_e_end regression
tools/test_reload_leak.sh              CDict reload-leak check (run under ASAN)
tools/test_test_*.py                   unit tests for the Python harness itself
tools/ci-build.sh                      local "build nginx + module" helper
fuzz/                                  libFuzzer harness (see below)
.github/workflows/                     build-test / codeql / security-scanners / fuzzing
valgrind.suppress                      local valgrind suppressions
.clang-format                          C style
```

## Directives (source of truth: the `ngx_command_t` tables)

Filter module — context `http, server, location` unless noted:

| Directive | Notes |
|---|---|
| `zstd on\|off` | also valid in `if` (LIF) |
| `zstd_comp_level` | int; supports negative levels (custom setter) |
| `zstd_types` | mime list; default is common textual web formats (see README) |
| `zstd_buffers` | num size |
| `zstd_min_length` | size; default `1024` |
| `zstd_max_length` | size; default unset. Enforced in the header filter on known `Content-Length` **and** in the body filter on chunked/no-length responses (aborts the request) |
| `zstd_target_cblock_size` | size; needs libzstd ≥ 1.5.6 |
| `zstd_window_log` | int exponent; caps `ZSTD_c_windowLog` → per-request memory ceiling |
| `zstd_dict_file` | **`http` context only** (`NGX_HTTP_MAIN_CONF`) |

Static module: `zstd_static on|off|always`.

Variables (log-phase, backed by `ctx->bytes_in/bytes_out`): `$zstd_ratio`,
`$zstd_bytes_in`, `$zstd_bytes_out`.

> Note: there is **no `zstd_bypass`** on `master` as of this writing
> (it exists on a feature branch / open PR). Check the command table
> before assuming a directive exists. Conversely, do not "add" a
> directive that an open PR already introduces — check open PRs first.

## Adding a directive — the established pattern

Mirror `zstd_target_cblock_size` / `zstd_window_log` exactly:

1. Field in `ngx_http_zstd_loc_conf_t` (or `_main_conf_t` for http-only).
2. Entry in `ngx_http_zstd_filter_commands[]` (right slot fn:
   `ngx_conf_set_num_slot` for ints, `_size_slot` for sizes,
   `ngx_http_set_predicate_slot` for variable lists, etc.).
3. Init in `create_loc_conf` (`NGX_CONF_UNSET` / `NGX_CONF_UNSET_PTR`).
4. `ngx_conf_merge_*` in `merge_loc_conf` with the documented default.
5. If it drives the encoder: apply via `ZSTD_CCtx_setParameter` in
   `ngx_http_zstd_filter_init_cctx`, **always** guarded by
   `ZSTD_isError(rc)` → log `NGX_LOG_ALERT` → `return NGX_ERROR`
   (graceful per-request fallback to uncompressed).
6. Document in `README.md` (directive section **and** the TOC).
7. Add a regression test (see below) and update the plan constant.

Prefer nginx's own primitives over hand-rolled logic (e.g.
`ngx_http_test_predicates`, `ngx_http_set_disable_symlinks`).

## Testing

Build a test nginx (the suites need a binary, not just headers):

```bash
bash tools/ci-build.sh            # nginx 1.31.0 by default
# or a full configure with --add-module=$(pwd) + extra http modules
```

Run the Perl suites (require `Test::Nginx::Socket`, typically under
`~/perl5`, so set `PERL5LIB`):

```bash
export PERL5LIB=$HOME/perl5/lib/perl5
export TEST_NGINX_BINARY=/path/to/built/nginx
export TEST_NGINX_SERVROOT=/tmp/srv && mkdir -p "$TEST_NGINX_SERVROOT"
prove t/00-filter.t t/01-static.t
```

End-to-end + harness unit tests:

```bash
python3 tools/test_encoding.py --nginx-binary /path/to/nginx
python3 tools/test_terminal_frame.py --nginx-binary /path/to/nginx
(cd tools && python3 -m unittest test_test_encoding test_test_package_artifact)
bash tools/test_reload_leak.sh /path/to/asan-built/nginx   # real under ASAN
```

### Perl suite gotchas (these will bite you)

- **`plan tests => repeat_each() * (blocks() * 3) + N;`** — `blocks()`
  auto-counts, but the `+ N` constant is a hand-maintained "extra
  assertions" budget. Adding/removing a test, or using
  `--- ignore_response`, changes the real subtest count. Run the suite,
  read the `planned X but ran Y` line, adjust `N` by the delta. A "Bad
  plan" with `0 Failed` is *only* the constant being off.
  Current: filter `+147`, static `+63`. (38 filter tests, 20 static.)
- `--- config` is injected inside `server{}`. `http`-context directives
  (`map`, `zstd_dict_file`, `log_format`) must go in `--- http_config`.
- `$TEST_NGINX_HTML_DIR` is **not** a shell env var and the literal
  token (even inside a `#` comment in a config section) triggers a
  Test::Nginx substitution bail. Use `$TEST_NGINX_SERVER_ROOT` for
  absolute paths; `--- user_files` land in `<servroot>/html`.
- A deliberately aborted request needs `--- ignore_response` plus
  `--- error_log` (assert the log line) — not `--- response_headers`.
- Static suite needs `touch -d @1541504307 t/suite/test t/suite/test.zst`
  and a servroot positioned so `root ../../t/suite` resolves (CI uses
  `TEST_NGINX_SERVROOT=$GITHUB_WORKSPACE/t/servroot-static`).

## Fuzzing (`fuzz/`)

Target: `ngx_http_zstd_accept_encoding()` and the
`ngx_http_zstd_eval_qvalue()` helper it calls. Both are **sliced from
the shipped header at build time** by `fuzz/extract_parser.sh` into
`generated_parser.inc` (gitignored), in definition order — there is
intentionally **no hand-maintained copy**. `fuzz/ngx_shim.h` reproduces the few nginx
primitives the parser needs, copied faithfully from upstream
`src/core/ngx_string.{c,h}` with citations.

```bash
bash fuzz/build.sh && ./fuzz/fuzz_accept_encoding -max_total_time=60 fuzz/corpus/
```

If you change the parser signature/body and the fuzz build fails,
`extract_parser.sh`'s anchor regex needs updating — it fails loudly on
purpose rather than fuzz nothing. Don't commit `fuzz/corpus/` units a
local run discovered; only the curated `NN_name` seeds are tracked
(enforced by `.gitignore`).

## CI (4 workflows; actionlint gates them)

| File | Name | Scope |
|---|---|---|
| `build-test.yml` | Build & Test | actionlint + lint, build matrix **nginx 1.31.0 mainline + Angie 1.11.5**, Perl/Python tests, ASAN/UBSAN |
| `codeql.yml` | CodeQL | `security-extended`; needs a full `make` (static `--add-module` compiles into the binary — `make modules` sees nothing) |
| `security-scanners.yml` | Security Scanners | flawfinder / clang-tidy / semgrep → SARIF |
| `fuzzing.yml` | Fuzzing | nightly + bounded-PR libFuzzer |

CI-specific facts that have caused failures before:

- **Actions expression contexts**: `${{ env.X }}` is **not** allowed in
  a job-level `name:` (it is fine in `with:`/`run:`/`path:`/`key:`).
  `${{ matrix.X }}` *is* allowed in a job `name:`. actionlint catches
  this; run it locally on every workflow edit.
- All third-party actions are **pinned to commit SHAs**; the canonical
  pin table is the header comment in `build-test.yml` — keep all four
  files consistent with it.
- `run:` blocks are shellcheck'd by actionlint. Quote variables; for
  flag-list variables that *must* word-split into compiler args, use a
  scoped `# shellcheck disable=SC2086` **with a rationale comment**.
- CodeQL "default setup" (a repo Settings toggle) conflicts with the
  advanced `codeql.yml` and rejects its SARIF. It is currently disabled
  via the API; this is a repo setting, not in any diff.

Validate locally before pushing:

```bash
actionlint .github/workflows/*.yml          # must exit 0
python3 -c "import glob,yaml;[yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')]"
```

## Module behaviour worth knowing before you touch it

- Per-request `ZSTD_CCtx` is created/reset per request and freed via a
  pool cleanup (a recurring historical bug area — `774b4a5`, `a209f96`).
  Don't reintroduce worker-global compression state.
- The header filter gate (status/length/type/`header_only`) decides
  eligibility; `ngx_http_zstd_ok()` checks `Accept-Encoding`. The body
  filter runs the streaming compress loop with a `failed:` path that
  sets `ctx->done` and returns `NGX_ERROR`.
- Once compression starts the client is mid-`Content-Encoding: zstd`
  stream — you **cannot** switch to passthrough; the only safe failure
  is aborting the request (this is why the chunked `max_length` cap
  aborts rather than passes through).
- `$zstd_ratio` etc. are log-phase only — `not_found` until
  `ctx->done`. They are not usable in `add_header`.

## PR conventions

- One logical change per PR, scoped commit message, no AI co-author.
- If multiple in-flight PRs each append tests to `t/00-filter.t` off
  `master`, they will collide on test numbering + the plan constant.
  Flag this in the PR body; whichever merges later gets a trivial
  renumber rebase. Don't hide the conflict.

### Stacked PRs (one PR per issue/change)

When a single piece of work decomposes into several independent
changes, ship them as a **stack** — one PR per logical change, each
based on the previous PR's branch rather than all on `master`. This
keeps every PR small and individually reviewable while preserving the
real dependency order, instead of one sprawling diff or several PRs
that secretly conflict.

Rules:

- **One PR per issue/change.** Each branch contains exactly one
  logical change and its docs (README reference **and** TOC) — never
  bundle an unrelated fix because it was convenient.
- **Push and open each PR immediately, before starting the next one.**
  Don't batch the work and push at the end. The moment a PR's code is
  committed and locally verified, push the branch and open the PR so
  CI starts running on it while you build the next PR in the stack. CI
  here takes several minutes (CodeQL, ASAN/UBSAN, multi-target builds);
  pushing eagerly overlaps that wall-clock time with development
  instead of serialising it. By the time the stack is fully written,
  the lower PRs' CI is usually already green.
- **Base each PR on the one below it**, not on `master`. The base
  branch of PR _n_ is the head branch of PR _n−1_. Set it explicitly:
  `gh pr create --base <lower-branch>`.
- **Order by dependency, lowest-risk first.** Pure refactors and
  hot-path cleanups go at the bottom of the stack; new directives and
  default changes on top. A reviewer reading bottom-up sees each diff
  in isolation.
- **State the stack in every PR body.** List the full stack with links
  and mark this PR's position, e.g. `Stack: #12 ← #13 (this) ← #14`,
  and note "merge bottom-up".
- **Merge strictly bottom-up, and do NOT delete the base branch on
  merge.** Squash-merge the base PR with the branch **kept**
  (`--squash` without `--delete-branch`). Deleting the base branch
  does **not** auto-retarget the next PR — GitHub *closes* it (a PR
  whose base branch no longer exists cannot stay open and cannot be
  reopened against the missing base; you must recreate it). Instead,
  after the base merges: retarget the next PR to `master` explicitly
  via the REST API (`gh api -X PATCH .../pulls/N -f base=master` —
  `gh pr edit --base` can fail on the projects-classic GraphQL
  deprecation), then rebase its branch onto the new `master` and
  force-push so CI re-runs against the real post-merge base (a
  retarget alone does not re-trigger the workflows). Only delete all
  the stack branches at the very end, once everything is merged.
  Never merge a higher PR before its base — that pulls the lower
  change's diff in with it.
- **A rejected lower PR collapses the stack.** If the base PR needs
  rework, rebase the rest of the stack onto its updated branch before
  continuing; don't let higher PRs drift onto stale bases.
- Update `README.md` (reference **and** TOC) in the same PR as any
  user-visible directive/variable change. Keep `.github/CI_SETUP.md`
  truthful if you change CI structure.
- `gh` may resolve the wrong repo here (multiple remotes — `origin` =
  `eilandert/zstd-nginx-module`, `upstream` = `tokers/zstd-nginx-module`). Pass
  `--repo eilandert/zstd-nginx-module` or rely on the configured
  default.
