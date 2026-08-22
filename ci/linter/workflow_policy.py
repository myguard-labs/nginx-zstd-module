#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Repo-policy checks over .github/workflows/ that no off-the-shelf linter makes.

    ci/linter/workflow_policy.py runners     runner trust boundary + pool labels
    ci/linter/workflow_policy.py ports       per-job test port bands
    ci/linter/workflow_policy.py docs        README <-> workflows drift
    ci/linter/workflow_policy.py cadence     one PR entry point per member
    ci/linter/workflow_policy.py secrets     typed per-member secrets, no inherit

Each subcommand is wrapped by a ci/linter/lint-*.sh so run-all.sh picks it up by
glob and a human can select it with LINT_ONLY. Exit: 0 clean, 1 findings,
2 could not run.

WHY THESE ARE NOT actionlint OR zizmor RULES. Both of those read a workflow
against GENERAL knowledge -- syntax, and a catalogue of known attack shapes.
The checks here encode facts about THIS repo that no general tool can know:
which self-hosted labels exist, that the runners are persistent and shared with
package builds, which port band each job owns, which files document the
pipeline, that ci.yml is the single orchestrator, and that a member's secret
surface is declared at the member. They are the checks that go red when a NEW workflow is
added without the property every existing one happens to have -- the case where
copying an existing file is the only thing standing between the repo and a
regression, and nothing enforces the copy.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - exercised by the selftest doc
    print(
        "workflow_policy: PyYAML not installed (apt-get install python3-yaml).\n"
        "  Refusing to run rather than degrading to a regex scan: every check\n"
        "  here was bypassable by VALID YAML while it parsed workflows by\n"
        "  regex, which is the vacuous-gate shape this file exists to prevent.",
        file=sys.stderr,
    )
    raise SystemExit(2) from None

# WORKFLOW_POLICY_ROOT points the checks at a fixture tree instead of the repo.
# It exists so ci/linter/selftest.sh can assert the FAILING direction of every
# check against a committed, readable fixture -- rather than by planting a file
# in the live .github/workflows/ and hoping the cleanup runs. A check whose red
# path is never exercised is indistinguishable from one that cannot go red.
ROOT = pathlib.Path(
    os.environ.get("WORKFLOW_POLICY_ROOT")
    or pathlib.Path(__file__).resolve().parents[2]
)
WORKFLOWS = ROOT / ".github" / "workflows"


class PolicyError(Exception):
    """Could not run the check (exit 2) -- never confused with "clean"."""


# The one approved runner selector: the pool is a repo VARIABLE, with a
# GitHub-hosted fallback baked into the expression.
#
#     runs-on: ${{ fromJSON(vars.POOL || '["ubuntu-latest"]') }}
#
# Set `POOL` on a repo and its jobs run on the self-hosted pool; leave it unset
# and they fall back to `ubuntu-latest`. That is the access-granting mechanism:
# per repo, from the GitHub UI, with no pool label anywhere in the tree.
#
# What replaced what, so this is not "simplified" back later: every selector
# used to inline `["self-hosted","builder02","lxc"]` behind a
# `github.event.pull_request.head.repo.fork` ternary, in 15 places. The fork arm
# kept a fork PR's code off the persistent build host; the duplication meant a
# mistyped label was a job that queued forever, which is why this check existed.
#
# Both concerns moved, deliberately (2026-08-13):
#   - The pool label is now ONE value in the GitHub UI, so there is nothing left
#     in the tree to spell wrong and 15 copies cannot disagree. The typo did not
#     become impossible, though, only single-sited: `POOL` set to
#     `["self-hosted","buidler02","lxc"]` is valid JSON and non-empty, so
#     `fromJSON` parses it and the `||` fallback never fires. That job queues
#     against a label nobody answers, exactly as before. Only a MALFORMED value
#     fails loudly (fromJSON parse error) and only an UNSET one falls back to
#     hosted. Nothing in this repo can check the variable's contents; that is
#     the residual risk of moving it out of the tree.
#   - Fork trust is now GitHub's `all_external_contributors` approval policy:
#     every fork PR needs an explicit approval before any job runs. Verified
#     set on this repo 2026-08-13.
#
# That second move is why `pull_request_target` stays forbidden below and why
# that ban matters MORE than it used to. `pull_request_target` runs the base
# repo's workflow, with full secrets, against the fork's code -- and it would
# read `vars.POOL` like any other job, putting unreviewed fork code on the build
# host. The approval policy does not gate it. The ban in check_runners() is the
# only thing in this repo that does.
APPROVED_SELECTOR = "${{ fromJSON(vars.POOL || '[\"ubuntu-latest\"]') }}"

# Adopters that own no self-hosted pool set this to None: there is then no
# approved self-hosted selector, every job must be GitHub-hosted, and the
# positive-control fixture pair does not apply (ci/linter/fixture-selector.py
# exits 1, selftest.sh skips that case). Kept as an explicit switch because a
# hosted-only repo must not have to edit the check itself to be correct --
# reported by the nginx-cache-turbo-module adoption, 2026-08-10.
SELF_HOSTED_ALLOWED = True

HOSTED = re.compile(r"ubuntu-(?:latest|[0-9]+\.[0-9]+)")

# The runtime driver. A job that starts it is a "runtime-bearing" job and owes
# the port-band declaration checked below.
RUNTIME_DRIVER = "ci/tools/test_runtime.py"

# The band verifier, and everything that BINDS the band. The ordering check
# below needs both: a verify step is only a guard for the binders that come
# after it, and `prove` is a binder even though it is not the runtime driver.
BAND_VERIFIER = "ci/tools/max-port.sh"
# Word-bounded on purpose: a bare "prove" substring also matches `approve`,
# `improve` and `prover`, and a run block that merely says "improve the fixture"
# is not a binder. A shell comment inside a run block still counts -- treating a
# commented-out binder as absent is the safe direction here, since the finding is
# about the step that DOES bind.
BINDERS = (
    re.escape(RUNTIME_DRIVER),
    r"(?<![\w./-])prove(?![\w./-])",
    re.escape("ci/tools/coverage.sh"),
)
BINDER_RE = re.compile("|".join(BINDERS))
# Ways a line NAMES a binder without being one. Reported by the
# nginx-cache-turbo-module adoption 2026-08-10, where both produced a finding
# that is false by inspection and left the gate red on arrival -- which is how a
# checker teaches everyone to --no-verify.
#
# `python3 -m py_compile ci/tools/test_runtime.py` checks syntax. It starts no
# server and binds no port, so a job whose only mention of the driver is that
# does not owe a port band.
NON_BINDING_RE = re.compile(r"py_compile")
# `prove` alone, for the pass-through check below: it is the one binder whose
# band arrives through an env var (TEST_NGINX_PORT) rather than an argument.
PROVE_RE = re.compile(r"(?<![\w./-])prove(?![\w./-])")


def workflows() -> list[pathlib.Path]:
    """Every workflow file, BOTH extensions.

    GitHub reads `*.yml` and `*.yaml` alike. Globbing one of them made all three
    checks below skip a `.yaml` workflow entirely -- an undocumented, unchecked,
    possibly self-hosted PR entry point that reported clean.
    """
    return sorted(
        [*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")],
        key=lambda p: p.name,
    )


def load(path: pathlib.Path) -> dict:
    """Parse a workflow. A file that will not parse is exit 2, never clean."""
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path.name}: unparsable YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise PolicyError(f"{path.name}: top level is not a mapping")
    return doc


def events(doc: dict) -> set[str]:
    """The trigger names, from any of the three legal `on:` spellings.

    `on: [pull_request]`, `on: pull_request` and the indented mapping form mean
    exactly the same thing to GitHub. Only the mapping form was recognised
    before, so the two others walked past the runner-trust check.

    PyYAML resolves the bare key `on` to the boolean True (YAML 1.1 truthiness),
    so the True key is where the node actually lands unless it was quoted.
    """
    node = doc.get("on", doc.get(True))
    if isinstance(node, str):
        return {node}
    if isinstance(node, list):
        return {str(e) for e in node}
    if isinstance(node, dict):
        return {str(k) for k in node}
    return set()


def jobs(doc: dict) -> list[tuple[str, dict]]:
    """(name, node) for every job. A non-mapping `jobs:` yields nothing."""
    node = doc.get("jobs")
    if not isinstance(node, dict):
        return []
    return [(str(k), v) for k, v in node.items() if isinstance(v, dict)]


def selector(node) -> str:
    """Render a `runs-on:` node back to one comparable string.

    The list and mapping forms are rendered rather than flattened so that a
    `runs-on: [self-hosted, builder02]` fails the membership test as ONE finding
    naming the whole selector, instead of one confusing finding per label.
    """
    if isinstance(node, str):
        return node.strip()
    if isinstance(node, list):
        return "[" + ", ".join(selector(v) for v in node) + "]"
    if isinstance(node, dict):
        return "{" + ", ".join(f"{k}: {selector(v)}" for k, v in node.items()) + "}"
    return str(node)


def report(name: str, errors: list[str], ok_msg: str) -> int:
    if errors:
        print(f"{name}: {len(errors)} finding(s)", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    print(f"{name}: {ok_msg}")
    return 0


# --------------------------------------------------------------------------
# runners


def check_runners() -> int:
    errors: list[str] = []
    for path in workflows():
        doc = load(path)
        trigger = events(doc)

        # pull_request_target runs with the BASE repo's secrets against the
        # HEAD's code. There is no configuration of it that is safe here, so it
        # is refused outright rather than conditioned.
        if "pull_request_target" in trigger:
            errors.append(f"{path.name}: pull_request_target is forbidden")

        # PR-REACHABLE, not just pull_request-triggered. Every heavy workflow in
        # this repo is `workflow_call`-only and reached from ci.yml, whose sole
        # trigger IS pull_request -- and a called workflow inherits the caller's
        # event payload, so `github.event.pull_request.head.repo.fork` is
        # populated inside it. A check that only looked for a literal
        # `pull_request:` trigger would therefore pass every single one of them
        # while checking nothing, which is precisely the vacuous-gate shape this
        # repo keeps re-learning.
        pr_reachable = bool(trigger & {"pull_request", "workflow_call"})

        wf_jobs = jobs(doc)
        if not wf_jobs:
            if pr_reachable:
                errors.append(f"{path.name}: PR-reachable workflow declares no jobs")
            continue
        for job, node in wf_jobs:
            # A `uses:` job is a call into another workflow, which carries its
            # own runs-on and is checked as its own file. It owes no runner.
            if "uses" in node:
                continue
            if "runs-on" not in node:
                # Only a PR-reachable job OWES a runner declaration here: that is
                # the trust question. A schedule-only job without one is invalid
                # to GitHub itself and is not this check's business.
                if pr_reachable:
                    errors.append(
                        f"{path.name}:{job} is PR-reachable and declares no runs-on"
                    )
                continue
            runner = selector(node["runs-on"])
            approved = SELF_HOSTED_ALLOWED and runner == APPROVED_SELECTOR
            if approved or HOSTED.fullmatch(runner):
                continue
            if pr_reachable:
                errors.append(
                    f"{path.name}:{job} has runs-on: {runner} -- must be "
                    "GitHub-hosted or the approved vars.POOL selector "
                    "(see APPROVED_SELECTOR in ci/linter/workflow_policy.py)"
                )
                continue
            # NOT PR-reachable, so there is no fork-trust question to answer --
            # but the check still runs, because nothing else in the toolchain
            # looks at these selectors at all.
            #
            # actionlint validates runner labels only for a LITERAL `runs-on`.
            # Every selector here is a `fromJSON(...)` expression, so actionlint
            # goes QUIET on all of them -- and silence reads exactly like a pass.
            # Skipping schedule-only workflows would leave bump.yml and
            # ci-deep.yml (six selectors) unchecked by anything: measured
            # 2026-08-02 against the old inline labels, a typo in build-test.yml
            # was reported while the same edit in bump.yml and ci-deep.yml was
            # silent on both this check and actionlint.
            #
            # The pool label itself now lives in the `POOL` repo variable and is
            # no longer spellable here, so what this catches is a selector that
            # has drifted from the approved form -- an inlined label set, a
            # resurrected fork ternary, a hand-edited fallback. Those fail at
            # dispatch as a job that never picks up a runner, on a weekly
            # schedule nobody is watching.
            errors.append(
                f"{path.name}:{job} has runs-on: {runner} -- not the approved "
                "selector. This workflow is not PR-reachable, so the finding is "
                "about the SELECTOR SHAPE, not fork trust: nothing else "
                "validates it (actionlint skips non-literal runs-on) and a "
                "drifted selector is a job that never starts "
                "(see APPROVED_SELECTOR in ci/linter/workflow_policy.py)"
            )
    return report(
        "lint-ci-runners",
        errors,
        "no pull_request_target; every runs-on is hosted or the vars.POOL selector",
    )


# --------------------------------------------------------------------------
# ports


def _body(node: dict) -> str:
    """A job node re-serialised, for the substring questions asked below.

    The job SPLIT is structural (see jobs()); only the "does this job mention
    the driver / --port" questions are textual, and those are asked of this
    normalised dump rather than of the file. Two consequences, both wanted: a
    comment can no longer hide a job from the split -- `runtime: # note` used
    to yield ZERO jobs and a cheerful "no runtime-bearing jobs" -- and a port
    mentioned only in a comment no longer counts as a declaration.
    """
    dumped = yaml.safe_dump(node, default_flow_style=False, sort_keys=False)
    # Shell comments inside a `run:` block survive the YAML round-trip, so prose
    # that merely NAMES the driver used to make a job runtime-bearing and demand
    # a band. Strip comments and non-binding invocations before the substring
    # questions below are asked.
    #
    # Split on ESCAPED newlines as well as real ones. safe_dump folds a
    # multi-line `run:` into one quoted scalar containing literal "\n", so a
    # naive per-dumped-line strip cuts at the first '#' and discards every real
    # command after it -- including the `--port $TEST_BASE_PORT` that proves a
    # job is wired. That direction fails OPEN, which is the worse one.
    kept = []
    for line in re.split(r"\\n|\n", dumped):
        code = line.split("#", 1)[0]
        if NON_BINDING_RE.search(code):
            continue
        kept.append(code)
    return "\n".join(kept)


def _steps(node: dict) -> list[str]:
    """Each step's `run:` text, in declaration order. Non-run steps keep their
    slot as an empty string so an index comparison stays an ORDER comparison."""
    out: list[str] = []
    for step in node.get("steps") or []:
        if not isinstance(step, dict):
            out.append("")
            continue
        run = step.get("run")
        out.append(run if isinstance(run, str) else "")
    return out


def _order_finding(where: str, node: dict) -> str | None:
    """A band verifier that runs after something has already bound the band.

    The verify step is not a property of the job, it is a property of a
    POSITION: it can only speak for the steps below it. `build-test.yml` shipped
    it between `prove` and the runtime suite, which reads as guarded and left
    the first binder unguarded -- the failure max-port.sh exists to name still
    arrived inside `prove` as a bind error or a timeout with no cause attached.
    Only jobs that already carry the verifier are checked here; whether a
    binding job must carry one at all is the declaration check above.
    """
    runs = _steps(node)
    verify = next((i for i, r in enumerate(runs) if BAND_VERIFIER in r), None)
    if verify is None:
        return None
    first_bind = next((i for i, r in enumerate(runs) if BINDER_RE.search(r)), None)
    if first_bind is None or first_bind > verify:
        return None
    # Same step: a multi-line `run:` block may legitimately verify and then bind.
    # Index order cannot separate those, so fall back to position within the text.
    if first_bind == verify:
        run = runs[verify]
        # Bound to a local so the None case is handled rather than assumed.
        # first_bind == verify means BINDER_RE already matched this step, so
        # `bind` cannot be None in practice -- but calling .start() straight off
        # the search result makes that an invariant mypy cannot see, and a
        # future edit to BINDER_RE would turn it into an AttributeError inside a
        # linter: exit 2 "could not run" for what is really a clean step.
        bind = BINDER_RE.search(run)
        if bind is None or run.index(BAND_VERIFIER) < bind.start():
            return None
        return (
            f"{where} binds the band earlier in the same step than it runs "
            f"{BAND_VERIFIER} (step {verify + 1}) -- verify first, then bind"
        )
    return (
        f"{where} runs {BAND_VERIFIER} at step {verify + 1}, after step "
        f"{first_bind + 1} has already bound the band -- the verifier only "
        "guards the steps below it, so move it above the FIRST binder"
    )


def check_ports() -> int:
    errors: list[str] = []
    bands: dict[str, str] = {}  # port value -> "file:job" that claimed it

    for path in workflows():
        doc = load(path)
        for job, node in jobs(doc):
            body = _body(node)
            declared = re.search(r"(?m)^\s*TEST_BASE_PORT:\s*[\"']?(\d+)", body)
            starts_runtime = RUNTIME_DRIVER in body
            binds_band = BINDER_RE.search(body) is not None
            where = f"{path.name}:{job}"

            order = _order_finding(where, node)
            if order:
                errors.append(order)

            # THE CHECK THAT MATTERS MOST. A new runtime-bearing job added later
            # with no band is invisible to the uniqueness check below (it
            # declares nothing to collide), silently takes the driver's default
            # --port, and reintroduces exactly the cross-job collision the bands
            # exist to prevent: two jobs pinned to the same runner, disjoint
            # concurrency groups, nothing serialising them, both binding 18880.
            # Any BINDER (not just the runtime driver) owes this declaration --
            # `prove` and coverage.sh are binders too (see BINDERS above), and a
            # job whose only binder is `prove` was exempt here while still being
            # treated as a binder by the ordering check. That gap is a live
            # negative-control failure downstream: deleting a prove-only job's
            # band left this check GREEN.
            if binds_band and not declared:
                errors.append(
                    f"{where} binds a port (via "
                    f"{RUNTIME_DRIVER if starts_runtime else 'prove/coverage.sh'}) "
                    "without declaring TEST_BASE_PORT -- it would take the "
                    "default port and collide with any other runtime job on "
                    "the same runner"
                )
                continue

            if not declared:
                continue

            port = declared.group(1)
            if port in bands:
                errors.append(
                    f"{where} and {bands[port]} both claim TEST_BASE_PORT "
                    f"{port} -- bands must be disjoint across ALL workflows"
                )
            else:
                bands[port] = where

            # The same requirement for a `prove` binder. Test::Nginx reads
            # TEST_NGINX_PORT and knows nothing about TEST_BASE_PORT, so a job
            # can declare a unique band, satisfy every check above, and still
            # bind 1984. Distinct from the driver case only in which variable
            # carries the value: there it is an argument, here an env var.
            if PROVE_RE.search(body):
                nginx_port = re.search(
                    r"(?m)^\s*TEST_NGINX_PORT:\s*[\"']?([^\"'\n]+)", body
                )
                # Either spelling is correct: an expression referring to the
                # band, or the literal band value. What matters is that the
                # number prove binds is the one this job declared -- a
                # TEST_NGINX_PORT naming some OTHER port is the same defect as
                # not setting it at all.
                wired = nginx_port is not None and (
                    "TEST_BASE_PORT" in nginx_port.group(1)
                    or nginx_port.group(1).strip() == port
                )
                # TEST_NGINX_RANDOMIZE is the one case where a runtime-bearing
                # job legitimately does NOT bind its declared band. It is what
                # makes `prove -jN` safe: Test::Nginx's Util.pm gen_rand_port
                # picks a port PER PARALLEL JOB and binds only ports it has
                # proved free, so pinning TEST_NGINX_PORT would re-share the
                # resource the randomization just separated. The band is still
                # declared and still swept, which is what reserves the job's
                # territory on the shared runner.
                #
                # Reported by the nginx-cache-turbo-module adoption 2026-08-10;
                # that repo's prove job randomizes and this one does not, so the
                # gap was invisible here.
                if re.search(r"(?m)^\s*TEST_NGINX_RANDOMIZE:", body):
                    wired = True
                if not wired:
                    errors.append(
                        f"{where} declares TEST_BASE_PORT but never passes it "
                        "to prove as TEST_NGINX_PORT -- Test::Nginx does not "
                        "read TEST_BASE_PORT, so it would bind its 1984 "
                        "default anyway"
                    )

            # A declared band that is not passed through is decoration: the
            # driver still binds its default.
            if starts_runtime and "--port" not in body:
                errors.append(
                    f"{where} declares TEST_BASE_PORT but never passes --port; "
                    "the driver would bind its default anyway"
                )
            if starts_runtime and "TEST_BASE_PORT" not in body.split("--port")[-1][:40]:
                errors.append(
                    f"{where} passes --port with something other than "
                    "$TEST_BASE_PORT -- the declaration and the bind must be "
                    "the same value or they drift"
                )

    return report(
        "lint-ci-ports",
        errors,
        f"{len(bands)} runtime job(s), all with distinct port bands"
        if bands
        else "no runtime-bearing jobs",
    )


# --------------------------------------------------------------------------
# docs


def check_docs() -> int:
    """Every workflow is documented, and every documented workflow exists.

    The drift this catches is silent in both directions and neither direction
    fails anything else: a workflow added without a README row is a gate nobody
    knows exists (so nobody notices when it is later removed), and a README row
    for a deleted workflow is a badge that 404s and a claim of coverage the repo
    does not have. Structural facts only -- deliberately NOT exact job counts or
    durations, which are the brittle claims that get a drift check deleted.
    """
    errors: list[str] = []
    readme = ROOT / "README.md"
    if not readme.is_file():
        print("lint-docs-drift: no README.md", file=sys.stderr)
        return 2
    text = readme.read_text(encoding="utf-8")

    names = {p.name for p in workflows()}
    for name in sorted(names):
        if name not in text:
            errors.append(
                f"{name} exists under .github/workflows/ but is not mentioned "
                "in README.md -- an undocumented gate"
            )
    # Only PATH-QUALIFIED references. A bare "ci.yml" in prose could mean any
    # file; ".github/workflows/ci.yml" is unambiguously a claim that this repo
    # has that workflow, which is the claim worth checking.
    for ref in sorted(set(re.findall(r"\.github/workflows/([\w.-]+\.ya?ml)", text))):
        if ref not in names:
            errors.append(
                f"README.md references .github/workflows/{ref}, which does not "
                "exist -- a dead link or a stale badge"
            )
    return report(
        "lint-docs-drift",
        errors,
        f"{len(names)} workflow(s), all documented in README.md",
    )


# --------------------------------------------------------------------------
# cadence


def check_cadence() -> int:
    """A `workflow_call` member carries no second entry point of its own.

    `workflow_call` does not suppress a member's own triggers. A member reached
    from ci.yml that ALSO carries `push:` runs twice per change: once on the PR,
    once on the merge commit, against a tree identical to the PR head that
    already passed. The two runs get different concurrency keys, so
    `cancel-in-progress` does not collapse them, and BOTH are green -- the only
    symptoms are the bill and a README that no longer describes what runs when.

    Nothing else catches this. Every member here is correct today, but that
    correctness is asserted only by a comment in each file ("No push/pull_request
    trigger here on purpose"), and a comment does not survive the next workflow
    copied in from a repo with a different topology. Downstream this cost five
    stray post-merge runs across six of seven members before review caught it.

    `schedule:` is explicitly allowed: codeql.yml and ci-deep.yml are reachable
    both from ci.yml and on their own cadence, which is the intended shape and
    not a duplicate run of the same tree.
    """
    errors: list[str] = []
    for path in workflows():
        trigger = events(load(path))
        if "workflow_call" not in trigger:
            continue
        for dupe in sorted(trigger & {"push", "pull_request"}):
            errors.append(
                f"{path.name} is a workflow_call member and also carries "
                f"`{dupe}:` -- it would run twice per change, on two "
                "concurrency keys that cannot cancel each other. Reach it "
                "from ci.yml only (schedule: is allowed)"
            )
    return report(
        "lint-ci-cadence",
        errors,
        "every workflow_call member has ci.yml as its only PR entry point",
    )


# --------------------------------------------------------------------------
# secrets


def check_secrets() -> int:
    """A member declares the secrets it needs, by name and typed; no `inherit`.

    `workflow_call: {}` with no `secrets:` stanza is not "this member needs no
    secrets" -- it is "this member can never receive one". An undeclared secret
    is simply not passed, so a member that starts needing a token gets an empty
    string and fails somewhere downstream of the cause: a checkout that 404s, a
    curl that 401s. Nothing says the secret was dropped at the call boundary.

    The stance this enforces is (a) of the two available: every member names the
    secrets it needs with `required: true`, and callers wire them explicitly.
    The rejected alternative is `secrets: inherit` at the caller, which is less
    boilerplate and widens every member's blast radius to the caller's FULL
    secret set -- including the ones that member has no business reading. A
    member's secret surface should be visible at the member.

    `required: true` over `required: false` is the load-bearing half. A false
    (or omitted) `required` restores exactly the silent-empty-string failure
    this check exists to prevent; true makes GitHub refuse to start the call.

    NOTE FOR AN ADOPTER: this repo declares no secrets, and that is the correct
    state for it -- every job is `contents: read` over a public tree. The check
    is therefore VACUOUSLY GREEN here by design, and its value is entirely in
    the moment an adopter adds the first one. It is not a no-op: the caller-side
    half below goes red on `secrets: inherit` and on a secret passed to a member
    that never declared it, both of which are reachable in this repo today.
    """
    errors: list[str] = []
    declared: dict[str, set[str]] = {}

    for path in workflows():
        data = load(path)
        # Same `on:`-spelling quirk events() documents: PyYAML resolves the bare
        # key to True. Only the mapping form can carry a secrets: block.
        node = data.get("on", data.get(True))
        # `workflow_call:` (null) and `workflow_call: {}` are the same workflow
        # to GitHub. Both must register as members, or a caller passing a secret
        # to a null-spelled member reads as "unknown member" and goes unchecked.
        if not isinstance(node, dict) or "workflow_call" not in node:
            continue
        call = node["workflow_call"]
        if call is not None and not isinstance(call, dict):
            raise PolicyError(f"{path.name}: workflow_call is not a mapping")
        secrets = (call or {}).get("secrets") or {}
        if not isinstance(secrets, dict):
            raise PolicyError(f"{path.name}: workflow_call.secrets is not a mapping")
        declared[path.name] = set(secrets)
        for name, spec in sorted(secrets.items()):
            # These two branches must not overlap. An earlier split tested
            # `"required" not in spec` here and the VALUE below, but every spec
            # missing the key yields None from .get(), and `None is not True`,
            # so the value branch decided both cases and deleting this one
            # changed no verdict -- a mutant that survived every fixture. This
            # branch now owns only the not-a-mapping shape, which .get() cannot
            # be asked about at all; the value branch owns every mapping.
            if not isinstance(spec, dict):
                errors.append(
                    f"{path.name} declares secret `{name}` untyped -- give it "
                    "`required: true`, or a member that stops being passed it "
                    "fails on an empty string instead of refusing to start"
                )
            elif spec.get("required") is not True:
                errors.append(
                    f"{path.name} declares secret `{name}` with "
                    # str(): a YAML-facing message must not print Python's
                    # `False` for what the author wrote as `false`.
                    f"`required: {str(spec.get('required')).lower()}` -- use "
                    "`required: true`; "
                    "an optional secret reintroduces the silent empty string"
                )

    # Caller side. `uses: ./.github/workflows/X.yml` with a `secrets:` block.
    for path in workflows():
        for job, spec in (load(path).get("jobs") or {}).items():
            if not isinstance(spec, dict):
                continue
            uses = spec.get("uses")
            if not isinstance(uses, str):
                continue
            passed = spec.get("secrets")
            local = uses.startswith("./.github/workflows/")
            # `inherit` is judged BEFORE the local-member filter, because the
            # blast radius it hands over is worst for the calls this filter used
            # to drop: `owner/repo/.github/workflows/x.yml@ref` sends the
            # caller's entire secret set to ANOTHER REPOSITORY. Everything below
            # this point compares against `declared`, which only knows local
            # members, so the rest of the loop stays local-only.
            if passed == "inherit":
                errors.append(
                    f"{path.name} job `{job}` uses `secrets: inherit` -- name "
                    "the secrets the member needs instead; inherit hands it the "
                    "caller's entire secret set, including ones it never reads"
                )
                continue
            if passed is not None and not isinstance(passed, dict):
                # Shape is judged BEFORE the local-member filter, for the same
                # reason `inherit` is: `secrets:` that is neither a mapping nor
                # `inherit` is a caller GitHub will refuse, and dropping it here
                # because the member happens to live in another repository
                # reports CLEAN over a call that cannot work. The filter below
                # exists only to gate `declared` lookups, which are meaningless
                # for an external member -- it was never meant to gate validity.
                #
                # Without this, a bare string reaching `set(passed)` below is
                # iterated CHARACTER by character, reporting a finding per
                # letter -- red for the wrong reason.
                raise PolicyError(
                    f"{path.name} job `{job}`: `secrets:` is neither a mapping "
                    f"nor `inherit` ({type(passed).__name__})"
                )
            if not local:
                continue
            member = uses.rsplit("/", 1)[-1]
            # The other direction: a member that REQUIRES a secret nobody wires.
            # GitHub refuses to start that call, which is the loud failure
            # `required: true` was chosen for -- but it fails on the first run
            # after merge, and the pairing is checkable here at review time.
            # `inherit` and every non-mapping shape have already been rejected
            # above, so `passed` here is a mapping or None -- None meaning the
            # caller wires nothing, which is exactly what this loop reports.
            supplied = set(passed) if passed is not None else set()
            for name in sorted(declared.get(member, set()) - supplied):
                errors.append(
                    f"{path.name} job `{job}` calls {member}, which requires "
                    f"secret `{name}`, but does not pass it -- GitHub refuses "
                    "to start the call"
                )
            if passed is None:
                continue
            if member not in declared:
                # Not our business here: `docs`/`cadence` cover missing members.
                continue
            for name in sorted(set(passed) - declared[member]):
                errors.append(
                    f"{path.name} job `{job}` passes secret `{name}` to "
                    f"{member}, which does not declare it -- it is silently "
                    "dropped at the call boundary"
                )

    total = sum(len(v) for v in declared.values())
    return report(
        "lint-ci-secrets",
        errors,
        f"{len(declared)} workflow_call member(s), {total} typed secret(s), no inherit",
    )


COMMANDS = {
    "runners": check_runners,
    "ports": check_ports,
    "docs": check_docs,
    "cadence": check_cadence,
    "secrets": check_secrets,
}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in COMMANDS:
        print(f"usage: {argv[0]} {{{'|'.join(COMMANDS)}}}", file=sys.stderr)
        return 2
    if not WORKFLOWS.is_dir():
        print(f"no {WORKFLOWS} -- wrong tree?", file=sys.stderr)
        return 2
    try:
        return COMMANDS[argv[1]]()
    except PolicyError as exc:
        # 2, not 1: the check did not RUN. A workflow this file cannot parse is
        # also a workflow GitHub may read differently, so reporting "clean" or
        # even "findings" over the rest of the tree would be a claim the run
        # cannot support.
        print(f"workflow_policy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
