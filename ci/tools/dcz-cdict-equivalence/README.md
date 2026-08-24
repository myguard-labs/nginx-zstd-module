# dcz CDict-vs-refPrefix equivalence probes

Standalone libzstd probes used to evaluate caching a `ZSTD_CDict` at config
time in place of the per-request `ZSTD_CCtx_refPrefix()` on the dcz path
(`ngx_http_zstd_filter_module.c`, `init_cctx`).

Verdict: **not equivalent**. `ZSTD_CCtx_refCDict()` and
`ZSTD_CCtx_refPrefix()` produce different wire bytes at every compression
level, not only at the fast-strategy levels 1-2. Substituting one for the
other changes the compressed output of every dcz response.

## Build and run

Both probes read `dict.bin` (1 MiB) and `body.bin` (256 KiB) from the
working directory. Generate them with:

    python3 gen_corpus.py

The corpus must be realistic, non-degenerate text-like data: a synthetic
periodic buffer compresses to a few dozen bytes, masks the effect, and
reports spurious byte-identity.

    gcc -O2 -o equivalence_probe equivalence_probe.c -lzstd
    gcc -O2 -o timing_probe      timing_probe.c      -lzstd

`equivalence_probe` sweeps dictionary sizes {4 KiB, 64 KiB, 256 KiB, 1 MiB}
x body sizes {512 B, 8 KiB, 128 KiB} x levels 1..19, with the **full**
compression-parameter set (windowLog, chainLog, hashLog, searchLog,
minMatch, targetLength, strategy) pinned identically on both paths, and
reports every combination whose output differs.

`timing_probe` measures per-request cost of both paths and verifies that
CDict output still round-trips through a decoder using the raw dictionary
as a prefix.

## Observed (libzstd 1.5.7)

    identical 86/228   (142 of 228 combinations diverge)
    diverging=142 cdict_worse=59 cdict_better=59 same_size=24
    mean size delta +0.30%, worst single regression +12.31%

Divergence is present at levels 1-19 and at every dictionary size, so no
level cutoff exists that makes the substitution byte-safe.

Timing (level 9, 8 KiB body):

    dict 4 KiB    refPrefix  363.6 us/req   cachedCDict 301.7 us/req
    dict 64 KiB   refPrefix  313.5 us/req   cachedCDict 217.1 us/req
    dict 1 MiB    refPrefix 2012.3 us/req   cachedCDict 151.6 us/req

The speed win is real and grows with dictionary size; it is the wire-byte
equivalence, not the performance, that blocks the change.
