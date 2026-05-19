# Fuzzing

Coverage-guided fuzzing of the RFC 7231 Accept-Encoding / q-value parser
in [`../ngx_http_zstd_common.h`](../ngx_http_zstd_common.h): the entry
point `ngx_http_zstd_accept_encoding()` and the `ngx_http_zstd_eval_qvalue()`
helper it calls. Both are sliced into the fuzz target together.

## Why this target

It parses attacker-controlled header bytes in C, does pointer arithmetic
against `ae->data`/`ae->len`, and runs the NUL-terminated `ngx_strcasestrn()`
over the same buffer. That length-bounded vs. NUL-bounded mix, plus q-value
edge cases, is the bug class the Perl suite cannot reach and that matches this
module's historical bug profile (truncation, terminal-frame, lifetime).

## No copy drift

There is **no hand-maintained copy** of the parser. `extract_parser.sh`
slices the verbatim bodies of both parser functions
(`ngx_http_zstd_eval_qvalue` then `ngx_http_zstd_accept_encoding`, in
definition order) out of the shipped header into `generated_parser.inc`
at build time, and fails loudly if it cannot find either.
`ngx_shim.h` supplies only the tiny nginx surface the function needs
(`ngx_str_t`, `ngx_tolower`, `ngx_strncasecmp`, `ngx_strcasestrn`), copied
faithfully from upstream `src/core/ngx_string.{h,c}` with citations.

## Run locally

```bash
bash fuzz/build.sh          # needs clang with libFuzzer
cd fuzz
./../fuzz_accept_encoding -max_total_time=60 corpus/
```

A crash drops a `crash-*` reproducer. Replay it with:

```bash
./../fuzz_accept_encoding crash-<hash>
```

## CI

[`.github/workflows/fuzzing.yml`](../.github/workflows/fuzzing.yml), kept
separate from the build/test pipeline so it never slows PR feedback:

- **Nightly** — 15-min discovery run, merges + uploads the grown corpus
- **PR** — 2-min bounded regression run, *only* when the parser, `fuzz/`, or
  the workflow changes (`paths:` filter)
- **Manual** — `workflow_dispatch` with a custom duration

ASAN+UBSAN are compiled in, so memory and undefined-behaviour bugs abort the
run and fail the job. The harness also traps if the parser ever returns a
value other than `NGX_OK`/`NGX_DECLINED`.
