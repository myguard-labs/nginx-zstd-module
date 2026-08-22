# Adoption findings (PR2, phase 5)

Findings from steps 21-26 that are not simply "done" — either a mutation
result worth recording, or something the module already had that diverges
from what the phase asked for. Feeds step 33.

## Step 21 — unit tests over the real decision TU

`ci/tests/unit/run.sh` + `test_accept_encoding.c`. Unlike the skeleton's scan
core, the Accept-Encoding parser in `src/ngx_http_zstd_common.h` is pure,
self-contained ASCII walking that needs only `ngx_strncasecmp()` /
`ngx_strcasestrn()` — `ci/fuzz/ngx_shim.h` already supplies faithful copies
of those, so this layer reuses the shim rather than linking a full nginx
build tree's real `ngx_string.c`. That is a deliberate divergence from the
skeleton's convention (which links the real upstream TU because its scan
core calls `ngx_unescape_uri()`), not an oversight: this module's parser has
no such dependency, and the shim's own header cites the exact upstream
functions it copies. `run.sh` still regenerates
`ci/fuzz/generated_parser.inc` from the shipped header via
`extract_parser.sh` before every build, so the shipped parser is what gets
linked, never a hand copy.

24 checks, all green:

```
$ bash ci/tests/unit/run.sh 2>&1 | tail -3
ok   an unterminated quoted parameter value does not hang the walk and does not fabricate a matching zstd token

24/24 checks passed
```

### Mutation pass (all 5 applied to `src/ngx_http_zstd_common.h`, observed,
### reverted — tree diffed clean against a pre-mutation backup after each)

1. **Wildcard/explicit precedence flipped** — swapped the order of the two
   `if` blocks at the end of `ngx_http_zstd_coding_weight()` so `star_q` is
   checked before `coding_q`.
   Command: manual `perl -0pi` swap, then `bash ci/tests/unit/run.sh`.
   Result: `22/24 checks passed` — `FAIL explicit 'zstd;q=0' overrides a
   permissive '*'`, `FAIL explicit 'zstd' overrides a restrictive '*;q=0'`.
   Reverted; `diff` against backup identical; re-run confirmed `24/24`.

2. **`scale /= 10` removed** from the fractional-digit loop in
   `ngx_http_zstd_eval_qvalue()` (line ~153) — every digit after the decimal
   point is now weighted 100 instead of decaying ×10 per digit, which also
   breaks the implicit 3-digit cap the `scale > 0` guard enforces.
   Result: `23/24 checks passed` — `FAIL a fourth q decimal digit makes the
   element non-matching`. (Originally expected this to move the 2-digit
   `q=0.05` case instead; it did not, because 2 digits at weight 100 each
   still lands >0 either way. Corrected the code comment in
   `test_accept_encoding.c` to describe the actually-observed failure rather
   than the originally-assumed one — see [[feedback-inference-stated-as-verified-fact]].)

3. **Malformed-weight fallback to q=1** — inserted `if (q < 0) { q = 1000; }`
   before the `if (q >= 0)` block in `ngx_http_zstd_coding_weight()`, so a
   malformed `;q=` no longer makes the element non-matching.
   Result: `20/24 checks passed` — 4 checks fail (fourth-digit, missing
   value, bare `q`, end-of-buffer `q=`).

4. **`ngx_http_zstd_skip_quoted()` disabled** — `return p;` inserted before
   its own bounds check, unconditionally.
   Result: **the suite did not FAIL, it HUNG.** `case_skip_quoted_unterminated`'s
   unterminated `"..."` value makes the caller's element-skip loop
   (`while (*p != ',') { if (*p=='"') p = skip_quoted(p,end); else p++; }`)
   call the now-no-op `skip_quoted()` at the same `p` forever.
   Command: built to a distinct binary, ran under `timeout 5`.
   `$ timeout 5 /tmp/t2; echo exit=$?` → `exit=124`.
   This is exactly why `case_skip_quoted_unterminated` exists — a plain
   pass/fail assertion cannot distinguish "quote skip is a no-op" from "quote
   skip is correct but slow"; only a bounded run can. Recorded the observed
   hang, not the originally-assumed FAIL, in the test's own header comment.

5. **Off-by-one in the parameter-name scan** — `p < end` → `p <= end` in the
   name-scan loop inside `ngx_http_zstd_eval_qvalue()` (line 104).
   Ran under `clang -fsanitize=address,undefined` as well as plain `cc`.
   Result: `23/24 checks passed` — `FAIL 'q' with no '=value' makes the
   element non-matching, not an implicit q=1`. **No ASan trap fired** — the
   outer `while (p < end && *p == ';')` guard means the widened inner
   condition is only ever reached with `p == end` already inside the
   caller's bound, so this specific off-by-one is a logic bug, not a memory
   -safety one. Recorded rather than assumed: "off by one" does not
   automatically imply "overread", and asserting it would would have been an
   unverified claim.

All 5 mutations caught (none SURVIVED per rejected-test item 8); each
tripped a different, correctly-attributed check (no rejected-test item 4
shared-counter false-positive — verified per-mutation which named checks
flipped, not just the aggregate count).

## Step 22 — live-server layer

The module already has its own mature live-server driver convention:
separate, purpose-named scripts under `ci/tools/` (`test_reload_under_load.py`,
`test_concurrent_cctx_isolation.py`, `test_slow_drain.py`, `test_dcz.py`,
`test_compression_matrix.py`, ...) rather than the skeleton's single
`ci/tools/test_runtime.py` driver file. Per "adopt the convention, keep the
content", this session kept the module's own multi-script convention rather
than collapsing it into one `test_runtime.py` — the reviewed reason (step
22's "what belongs here" line) is about *placement* (driver vs `ci/t/`), and
every existing script here already only does what the driver's three
exemptions allow (concurrency, a signal at the master mid-traffic, or N
separate own-connection requests), so nothing needed to move.

**Gap found and closed: no baseline loaded-and-blocking control.** None of
the existing driver scripts prove the module is actually acting — they
assert response *correctness* under a stressor, which a module that failed
to load, or whose `enable` predicate silently decided OFF, could still
satisfy by accident (an unmodified passthrough is still byte-correct).
Added `ci/tools/test_baseline_loaded.py`: two live requests against the same
backend, one with `zstd on;` (must compress, decode byte-exact), one with NO
zstd directive at all (must NOT be zstd-encoded — the compiled-in default).
Wired into `build-test.yml`'s `tests-asan` job (`--port 18107
--backend-port 18108 --off-port 18112`, ports checked against every existing
`--port`/`--backend-port` literal in the file to avoid a collision) because
that job's binary is the one static (`--add-module`) build already produced
in this pipeline (asan.yml's own build), and the "no directive" case needs a
build where the module is compiled in but not turned on by config — a
dynamic `load_module`-based build cannot express that distinction cleanly
(no directive → unknown directive, config fails to parse, which the module-
unloaded case already covers via a different binary).

### Mutation pass

Ran locally against a hand-built static `--add-module` nginx (not part of
the fast PR lane; the CI wiring above uses the pipeline's own asan.yml
artifact instead).

1. **Module genuinely unloaded** — built the SAME nginx tree with no
   `--add-module` at all, ran the baseline script against it.
   `$ python3 ci/tools/test_baseline_loaded.py --nginx-binary
   /tmp/nginx-no-module`
   Result: `RuntimeError: nothing listening on 127.0.0.1:18110` (nginx fails
   to start at all — `zstd on;` is an unknown directive) — the script itself
   raises rather than silently passing. Confirms the baseline genuinely
   depends on the module being present.

2. **`enable` default flipped ON** — `src/ngx_http_zstd_filter_module.c`
   line 1919, `ngx_conf_merge_value(conf->enable, prev->enable, 0)` →
   `..., 1)`. Rebuilt (`objs/nginx`, distinct mtime/size verified against
   the pre-mutation binary each time — see
   [[feedback-stale-binary-fakes-a-hang]]), ran against a build with the
   mutation and a build without.
   Unmutated: `2/2 checks passed`, exit 0.
   Mutated: `FAIL baseline: response was zstd-encoded with NO zstd
   directive present -- compiled-in default is not OFF`, exit 1.
   **First attempt at this mutation test silently passed 2/2 against the
   mutated binary** — the script's own `--off-port` originally defaulted to
   `args.port + 1`, which collided with `--backend-port`'s default
   (18111 == 18110+1), so the "no directive" nginx failed to bind and the
   client request landed directly on the backend instead, which is
   trivially never zstd-encoded regardless of the mutation. Fixed by giving
   the off-case its own `--off-port` argument, distinct from both `--port`
   and `--backend-port`; re-ran and got the FAIL above. Left as a comment in
   the script at the call site so the next port choice does not repeat it.
   This is exactly the class of finding rejected-test item 4 (a shared
   resource that lets one check's assertion satisfy an unrelated one)
   generalizes to outside pure counters — recorded here rather than
   shipping the false-negative test.

Reverted both source and binaries after; `diff` against the pre-mutation
`.c` backup confirmed clean before committing.

## Step 25 note (out of my 21-26 slice but adjacent, flagged for step 33)

`ci/tools/soak.sh` under Valgrind (`USE_VALGRIND=1`, wired in
`.github/workflows/valgrind.yml`) runs with **no `--suppressions` file at
all** — there is no `valgrind.supp` anywhere in this repo, unlike the
skeleton's `ci/tools/valgrind.supp` (nginx-core process-lifetime leak
suppressions + two Helgrind entries). This may be a genuinely clean state
(no false-positive leak noise observed against this module's build), or it
may mean the memcheck-lite job has never actually gone green against a real
run and nobody has looked. Did NOT run a local valgrind soak to check —
that is an explicit long-runner under the worker contract (build + soak).
**Flag for whoever owns step 25/30**: run `USE_VALGRIND=1 ci/tools/soak.sh
<nginx-binary> 60 4` once, and if nginx-core noise appears, add a
target-specific `ci/tools/valgrind.supp` derived from that real run (per the
skeleton's own instructions on how to build one — never a copy).

## Stopped here

Landed: step 21 (unit tests, 5/5 mutations caught) and step 22 (baseline
loaded-and-blocking control added + its mutation pass, existing driver
scripts reviewed and kept as-is). Steps 23-26 not started this session. See
the worker return banner for exact scope remaining.
