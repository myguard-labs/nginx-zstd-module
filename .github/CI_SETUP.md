# CI/CD Pipeline

Automated build, test, and security analysis for the zstd-nginx-module.

## Workflow

Defined in [`.github/workflows/ci.yml`](workflows/ci.yml). Triggers:

- **Push** to `master`, `main`, `dev`
- **Pull requests** to `master`, `main`
- **Weekly schedule** — Monday 04:17 UTC, catches nginx API drift against
  newly released nginx versions even with no commits
- **Manual** — `workflow_dispatch`

Workflow-level hardening:

- `concurrency` — superseded runs on the same ref are cancelled, no pile-up
- `permissions: contents: read` by default; `codeql` and `secure` request
  `security-events: write` only where needed
- `timeout-minutes` on every job — a hung nginx test cannot burn runner hours
- All third-party actions are **pinned to commit SHAs** (see the header
  comment in `ci.yml`), not floating tags

## nginx versions

| Role | Version | Where |
|---|---|---|
| Mainline (default + artifact + tests) | **1.31.0** | `env.NGINX_VERSION`, `build` matrix, `build-asan` |
| Stable | **1.28.3** | `build` matrix |

`1.31.0` is the current nginx mainline release. The `build` job uses a
`strategy.matrix` over both so module/nginx API drift is caught on the stable
line as well as mainline. The shared test binary is the mainline one.

There is **no special "CI module" for nginx** — CI builds nginx from source
with `--add-module` (full binary) or `--with-compat` + nginx-dev headers (for
lint tools). The realistic extra HTTP modules the zstd filter runs alongside
are compiled in so the module is exercised in a real nginx, not a stripped one:
`ssl`, `v2`, `v3`, `gzip_static`, `realip`, `sub`, `addition`, `stub_status`,
`auth_request`, plus `--with-threads` and `--with-file-aio`.

### Debug compile flags

The `build` job configures with full debug flags:

- `--with-debug` — nginx `ngx_log_debug*` logging compiled in
- `-g3` — maximum debug info including macro definitions
- `-O0` — no optimisation, accurate line/variable info
- `-fno-omit-frame-pointer` — reliable gdb/valgrind backtraces
- `-funwind-tables` — unwind info for crash backtraces
- `-DNGX_DEBUG_PALLOC=1` — pool-allocator debug bookkeeping

Module sources additionally get a strict compile pass with
`-Wall -Wextra -Wshadow -Wstrict-aliasing -Wunreachable-code -Wunused
-Wwrite-strings -Werror`.

## Jobs

| Job | Depends on | Purpose |
|---|---|---|
| `validation` | — | shellcheck, cppcheck, clang static analyzer, Python harness unit tests |
| `codeql` | — | GitHub first-party C/C++ security analysis (`security-extended`) |
| `build` | — | Build nginx binary (matrix: stable + mainline), strict module compile, ccache, upload artifact |
| `build-asan` | — | Build nginx with `-fsanitize=address,undefined` |
| `tests` | `build` | Perl `Test::Nginx::Socket` suites + Python end-to-end smoke tests |
| `tests-asan` | `build-asan` | Re-run smoke tests under ASAN+UBSAN, fail on any memory/UB error |
| `secure` | — | flawfinder, clang-tidy, semgrep — results uploaded as SARIF to the Security tab |

`validation`, `codeql`, `build`, `build-asan`, and `secure` all start in
parallel. Only `tests`/`tests-asan` wait, on their respective build job.
(The scanners no longer have a pointless dependency on the nginx build.)

### `tests` coverage

- `t/00-filter.t` — filter module Perl suite
- `t/01-static.t` — static module Perl suite
- `tools/test_encoding.py` — truncation, Vary, boundary-size (1900 lines),
  repeated-request, concurrent-request smoke tests
- `tools/test_terminal_frame.py` — empty-output `ZSTD_e_end` terminal-frame
  regression (the bug fixed in `a209f96`)

### Caching

- apt archives per job
- nginx source tarballs keyed by version
- **ccache** for the nginx + module compile, keyed on source/header hashes
- Perl modules (`~/perl5`)
- nginx-dev generated headers
- semgrep rules and pip cache

## Security analysis

Five layers, results surfaced in the GitHub **Security → Code scanning** tab
via SARIF (not just buried in artifacts):

| Tool | Job | Output |
|---|---|---|
| CodeQL (`security-extended`) | `codeql` | SARIF (native) |
| flawfinder | `secure` | SARIF + log |
| semgrep (`p/c`, `p/security-audit`) | `secure` | SARIF + log |
| clang-tidy (`cert-*`, `bugprone-*`, `clang-analyzer-security.*`) | `secure` | log |
| cppcheck / clang static analyzer | `validation` | log artifacts |

ASAN+UBSAN (`tests-asan`) is the runtime memory-safety layer — it directly
targets the lifetime/UB bug classes in this module's history (per-request
context handling, terminal-frame emission).

## Local testing

Build against nginx locally before pushing:

```bash
bash tools/ci-build.sh            # default nginx 1.31.0
bash tools/ci-build.sh 1.28.3     # specific version
```

Run the test suites locally (requires `Test::Nginx::Socket`):

```bash
cd t
perl 00-filter.t
perl 01-static.t
python3 ../tools/test_encoding.py --nginx-binary /path/to/nginx
python3 ../tools/test_terminal_frame.py --nginx-binary /path/to/nginx
```

Run the Python harness unit tests:

```bash
cd tools
python3 -m unittest test_test_encoding test_test_package_artifact
```

## Status badge

```markdown
[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
```

## See also

- [`workflows/ci.yml`](workflows/ci.yml) — workflow definition
- `tools/ci-build.sh` — local build script
- `tools/test_encoding.py` — end-to-end encoding tester
- `tools/test_terminal_frame.py` — terminal-frame regression test
- `valgrind.suppress` — suppression file for local valgrind runs
