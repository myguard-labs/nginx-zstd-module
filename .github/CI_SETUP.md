# CI/CD Pipeline

Automated build, test, and security analysis for the zstd-nginx-module.

## Workflows

The pipeline is split across four workflow files:

| File | Purpose |
|---|---|
| [`build-test.yml`](workflows/build-test.yml) | Lint/validation, build matrix (nginx mainline + Angie), Perl/Python tests, ASAN/UBSAN |
| [`codeql.yml`](workflows/codeql.yml) | CodeQL `security-extended` analysis |
| [`security-scanners.yml`](workflows/security-scanners.yml) | flawfinder, clang-tidy, semgrep + SARIF upload |
| [`fuzzing.yml`](workflows/fuzzing.yml) | libFuzzer Accept-Encoding parser fuzzing |

Common triggers (`build-test.yml`, `codeql.yml`, `security-scanners.yml`):

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
  comment in `build-test.yml`), not floating tags

## nginx versions

| Role | Version | Where |
|---|---|---|
| nginx mainline (default + artifact + tests) | **1.31.0** | `env.NGINX_VERSION`, `build` matrix, `build-asan` |
| Angie (nginx fork, also packaged) | **1.11.5** | `build` matrix |

`1.31.0` is the current nginx mainline release. The `build` job uses a
`strategy.matrix` (include entries with `flavor`/`version`/`url`/`dir`) so the
module is compiled against both nginx mainline and Angie — the actively
developed fork this module also ships packages for (see
`tools/test_package_artifact.py`). The shared test binary is the nginx
mainline one.

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

| Workflow | Job | Depends on | Purpose |
|---|---|---|---|
| build-test | `validation` | — | actionlint, shellcheck, cppcheck, clang static analyzer, Python harness unit tests |
| build-test | `build` | — | Build matrix (nginx mainline + Angie), strict module compile, ccache, upload artifact |
| build-test | `build-asan` | — | Build nginx with `-fsanitize=address,undefined` |
| build-test | `tests` | `build` | Perl `Test::Nginx::Socket` suites + Python end-to-end smoke tests |
| build-test | `tests-asan` | `build-asan` | Re-run smoke tests under ASAN+UBSAN, fail on any memory/UB error |
| codeql | `codeql` | — | GitHub first-party C/C++ security analysis (`security-extended`) |
| security-scanners | `secure` | — | flawfinder, clang-tidy, semgrep — results uploaded as SARIF to the Security tab |

Within `build-test`, `validation`, `build`, and `build-asan` start in
parallel; only `tests`/`tests-asan` wait on their respective build job.
`codeql` and `security-scanners` are independent workflows running in
parallel with it.

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
bash tools/ci-build.sh 1.29.8     # specific nginx version
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
[![Build & Test](https://github.com/OWNER/REPO/actions/workflows/build-test.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/build-test.yml)
```

## See also

- [`workflows/build-test.yml`](workflows/build-test.yml) — main build/test workflow definition
- `tools/ci-build.sh` — local build script
- `tools/test_encoding.py` — end-to-end encoding tester
- `tools/test_terminal_frame.py` — terminal-frame regression test
- `valgrind.suppress` — suppression file for local valgrind runs
