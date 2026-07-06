# Contributing

Thank you for contributing — genuinely. Small modules like this live or die
on people who show up with a patch, a bug report, or an awkward question.
You are welcome here.

That said: this document is not decoration. Every rule below exists because
someone (usually us) broke something in a way that took a weekend to clean
up. Read it once before your first PR and you will save us both a round
trip. Break the rules and CI will catch you anyway — the robots are
patient, but they do not negotiate.

If anything here is unclear, **ask**. Asking early is a sign you're doing it
right, not that you're slow. Open an issue, open a draft PR, or mail
**github@myguard.nl**. We answer, and we mentor — everyone who works on
this code started by not knowing nginx internals either.

## TL;DR checklist

- [ ] One feature or fix per PR — no stacked PRs, no drive-by refactors.
- [ ] Code follows nginx style and matches the code around it.
- [ ] Every new feature or bugfix ships a test in the same PR.
- [ ] README updated in the same PR if behaviour changed.
- [ ] All CI checks green. No skipping, no "it works on my machine".
- [ ] Commit messages: imperative subject, body explains *why*.
      No AI co-author trailers.

## How CI works here

Every push and every PR runs four short gates. They exist to catch the
classes of bugs that C code in a web server cannot afford:

- **Build & Test** — builds the module against current nginx (and, where
  applicable, Angie) and runs the unit tests under **ASan/UBSan**.
  AddressSanitizer and UndefinedBehaviorSanitizer are compiler
  instrumentation that make memory bugs (use-after-free, buffer overflows,
  signed overflow) crash loudly at the exact line instead of corrupting
  memory silently. If ASan complains, the bug is real — fix it, don't
  suppress it.
- **Security scanners** (`security-scanners.yml`) — flawfinder, clang-tidy
  (`cert-*`, `clang-analyzer-security.*`) and semgrep over the module
  sources. Static analysis: it reads the code without running it and
  flags dangerous patterns.
- **Fuzzing** (`fuzzing.yml`) — a ~120-second libFuzzer regression run over
  the module's input parsers. Fuzzing feeds a parser millions of mutated
  inputs and watches for crashes. Short on PRs so feedback stays fast.
- **Valgrind** (`valgrind.yml`) — a short Memcheck soak. Valgrind executes
  the code in an emulated CPU and reports every invalid read/write and
  every leaked byte.

The expensive versions of these — hours-long fuzzing per target, full
Memcheck **and** Helgrind (thread-race detection) soaks — run monthly and
on manual dispatch in `ci-deep.yml`, not on your PR. Some modules also run
an extra runtime test suite; check the repo's `.github/workflows/` and the
badges at the top of the README for the exact set.

Your PR merges when **all** checks are green. If a gate fails and you
believe the gate is wrong, say so in the PR — with evidence, not vibes.

Before pushing a parser or fuzz-harness change, fuzz locally first:
`fuzz/build.sh` compiles every `fuzz/fuzz_*.c` with `-Werror`, so a stale
harness signature fails right there instead of in CI.

## Coding conventions

- **nginx style.** This is an nginx module: follow the
  [nginx style guide](https://nginx.org/en/docs/dev/development_guide.html#code_style)
  — 4-space indents, `ngx_` types (`ngx_int_t`, `ngx_str_t`, …), K&R-ish
  bracing as used by nginx core, `/* comments */`.
- **Match the surrounding code.** When in doubt, the file you are editing
  is the style guide. A patch that reads like the code around it is a
  patch we can review quickly.
- **Memory comes from pools.** Allocate from the request/config pool
  (`ngx_palloc`) unless you have a documented reason not to. If you
  `malloc`, you own the cleanup handler.
- **Handle every error path.** nginx runs for months; "can't happen"
  happens. Check return values, log with `ngx_log_error`, fail closed.
- **Comments explain *why*, not *what*.** A surprising nginx-internals
  fact, a footgun, a rejected alternative — write it down at the call
  site or in the README. No undocumented behaviour ships.

## Tests

Every function and every feature gets a test **in the same PR** that adds
it. Not a follow-up PR. Not "later". Same PR.

- New parser or handler → a unit or runtime test exercising it, including
  the ugly inputs (empty, oversized, malformed, truncated).
- Bug fix → a regression test that **fails before the fix and passes
  after**. That's the proof the test actually tests something.
- New input parser → a libFuzzer target in `fuzz/`.

Where tests live varies slightly per module (unit suites, `t/*.t`
Test::Nginx files, runtime suites under `tools/`) — look at the existing
tests in this repo and put yours next to them. A PR that adds code without
a test will not be merged, and yes, we check.

## Pull requests

- **One feature or issue per PR.** The title says what it does. If a PR
  grows a second concern, split it.
- **No stacked PRs.** Every PR branches from and targets the default
  branch independently. Stacks fall over the moment PR #1 gets review
  changes, and untangling them costs more than the stacking saved.
- **Open an issue first** for anything non-trivial; the PR references it
  (`Closes #N`).
- **Keep it reviewable in one sitting.** Small PRs merge fast; 2000-line
  PRs grow moss while we find an afternoon to do them justice.
- **Update the README in the same PR** when behaviour, directives, or
  defaults change. The README must never lag the default branch.
- The default branch is protected by convention: changes land via PR with
  green CI, not direct push.

## Commits

- Imperative subject line ("add X", "fix Y"), ≤ 72 chars.
- Body explains *why* — the design choice made and what was rejected.
- No AI co-author trailers. None.

## Ask for help

Stuck on nginx internals? Not sure where a test belongs? Fuzzer output
looks like hieroglyphics? Ask. Open a draft PR with what you have and say
what you're unsure about — a draft PR full of questions is a perfectly
good contribution. We would much rather spend ten minutes pointing you in
the right direction than review a week of effort aimed at the wrong wall.

## Contact

Questions, security reports, or anything that doesn't fit an issue:
**github@myguard.nl**
