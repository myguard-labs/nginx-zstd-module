# Fuzzing

Coverage-guided fuzzing of the RFC 9110 Accept-Encoding / q-value parser
in [`../ngx_http_brotli_common.h`](../ngx_http_brotli_common.h): the entry
point `ngx_http_brotli_accept_encoding()`, the weight walkers
`ngx_http_brotli_coding_weight()` and `ngx_http_brotli_coding_weight_ex()`
behind it, and the `ngx_http_brotli_eval_qvalue()` and
`ngx_http_brotli_skip_quoted()` helpers they call. All five are sliced
into the fuzz target together.

## Why this target

It parses attacker-controlled header bytes in C and does pointer arithmetic
against `ae->data`/`ae->len`. Length-bounded walking over a buffer with no
trailing NUL, plus the q-value edge cases, is the bug class the Perl suite
cannot reach.

## No copy drift

There is **no hand-maintained copy** of the parser. `extract_parser.sh`
slices the verbatim bodies of the five functions, in definition order, out
of the shipped header into `generated_parser.inc` at build time, and fails
loudly if it cannot find one of them.
`ngx_shim.h` supplies only the tiny nginx surface the functions need
(`ngx_str_t`, `ngx_tolower`, `ngx_strncasecmp`, `ngx_strcasestrn`), copied
faithfully from upstream `src/core/ngx_string.{h,c}` with citations.

## Run locally

`build.sh` writes the binary next to itself, as `fuzz/fuzz_accept_encoding`.

```bash
bash fuzz/build.sh          # needs clang with libFuzzer
cd fuzz
./fuzz_accept_encoding -max_total_time=60 corpus/
```

A crash drops a `crash-*` reproducer. Replay it from the same directory:

```bash
./fuzz_accept_encoding crash-<hash>
```

## CI

This repository has no fuzzing workflow: the target is run by hand with
the commands above. The parser's twin in nginx-zstd-module is fuzzed on a
schedule there, and the two are kept rule-for-rule equal, so a finding in
either is a finding in both.

ASAN+UBSAN are compiled in, so memory and undefined-behaviour bugs abort the
run. The harness also traps if the parser ever returns a value other than
`NGX_OK`/`NGX_DECLINED`, or disagrees with its independent reference oracle
on an input the oracle is confident about.
