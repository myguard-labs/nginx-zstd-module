#!/usr/bin/env bash
# ci/tools/test_ci_dependency_bootstrap.sh -- ensure fork fallbacks install
# their non-runner dependencies before CI uses them.
#
# Usage: ci/tools/test_ci_dependency_bootstrap.sh
# Inputs: repository .github/workflows/*.yml files.
# Side effects: none.  Exit non-zero on a missing bootstrap or package.

set -euo pipefail

root=${CI_DEPENDENCY_ROOT:-$(git rev-parse --show-toplevel)}
cd "$root"

# The apt packages a step's `run` installs, and the checks built on it:
# require_apt_package accepts the package installed by ANY step of the
# file; require_bootstrap_package demands it from EVERY step named
# "Install bootstrap dependencies"; require_resolver_jobs walks each JOB
# that runs the nginx resolver and demands that the same job has a
# bootstrap step before it installing curl and python3 -- a file-wide
# check would stay green with one job's bootstrap deleted as long as any
# other job still carried one.
APT_STEP_PY='
import pathlib, shlex, sys, yaml

path, wanted, mode = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
BOOTSTRAP = "Install bootstrap dependencies"
RESOLVER = "ci/tools/nginx-releases.sh"
NEEDED = ("curl", "python3")


def installed(run):
    found = set()
    logical = run.replace("\\\n", " ")
    for line in logical.splitlines():
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
            lexer.whitespace_split = True
            lexer.commenters = "#"
            words = list(lexer)
        except ValueError:
            continue
        start = 0
        for end in [
            *[i for i, word in enumerate(words) if word in {";", "&&", "||", "|"}],
            len(words),
        ]:
            command = words[start:end]
            start = end + 1
            apt = 1 if command[:1] == ["sudo"] else 0
            if len(command) > apt and command[apt] == "apt-get" \
                    and "install" in command[apt + 1:]:
                install = command.index("install", apt + 1)
                found |= {w for w in command[install + 1:] if not w.startswith("-")}
    return found


doc = yaml.safe_load(path.read_text(encoding="utf-8"))

if mode == "jobs":
    bad = 0
    resolving = 0
    for name, job in (doc.get("jobs") or {}).items():
        steps = job.get("steps", []) if isinstance(job, dict) else []
        steps = [s for s in steps if isinstance(s, dict)]
        resolver = [i for i, s in enumerate(steps)
                    if isinstance(s.get("run"), str) and RESOLVER in s["run"]]
        if not resolver:
            continue
        resolving += 1
        boots = [i for i, s in enumerate(steps)
                 if s.get("name") == BOOTSTRAP and i < resolver[0]]
        if not boots:
            print(f"FAIL: {path}: job {name!r} runs the nginx resolver (step "
                  f"{resolver[0]}) with no {BOOTSTRAP!r} step before it in "
                  "that job", file=sys.stderr)
            bad += 1
            continue
        packages = installed(steps[boots[-1]].get("run") or "")
        for pkg in NEEDED:
            if pkg not in packages:
                print(f"FAIL: {path}: job {name!r}: the {BOOTSTRAP!r} step "
                      f"before the resolver does not install apt package "
                      f"{pkg}", file=sys.stderr)
                bad += 1
    if resolving == 0:
        print(f"FAIL: {path}: no job runs {RESOLVER}", file=sys.stderr)
        bad += 1
    raise SystemExit(1 if bad else 0)

bootstrap_steps = 0
for job in (doc.get("jobs") or {}).values():
    for step in job.get("steps", []) if isinstance(job, dict) else []:
        if not isinstance(step, dict) or not isinstance(step.get("run"), str):
            continue
        packages = installed(step["run"])
        if mode == "any":
            if wanted in packages:
                raise SystemExit(0)
        elif step.get("name") == BOOTSTRAP:
            bootstrap_steps += 1
            if wanted not in packages:
                print(f"FAIL: {path}: the {BOOTSTRAP!r} step itself must install "
                      f"apt package {wanted} (a later step installing it does not "
                      "count -- the resolver runs right after the bootstrap)",
                      file=sys.stderr)
                raise SystemExit(1)
if mode == "bootstrap" and bootstrap_steps:
    raise SystemExit(0)
if mode == "bootstrap":
    print(f"FAIL: {path} has no {BOOTSTRAP!r} step to check", file=sys.stderr)
else:
    print(f"FAIL: {path} must install apt package {wanted}", file=sys.stderr)
raise SystemExit(1)
'

require_apt_package() {
  local file=$1 package=$2
  local base=${CI_DEPENDENCY_ROOT:-$root}
  python3 -c "$APT_STEP_PY" "$base/$file" "$package" any
}

require_bootstrap_package() {
  local file=$1 package=$2
  local base=${CI_DEPENDENCY_ROOT:-$root}
  python3 -c "$APT_STEP_PY" "$base/$file" "$package" bootstrap
}

require_resolver_jobs() {
  local file=$1
  local base=${CI_DEPENDENCY_ROOT:-$root}
  python3 -c "$APT_STEP_PY" "$base/$file" - jobs
}


require() {
  local file=$1 needle=$2
  if ! grep -Fq -- "$needle" "$file"; then
    echo "FAIL: $file must declare $needle for its fork fallback" >&2
    exit 1
  fi
}

require_before() {
  local file=$1 first=$2 second=$3 first_line second_line
  first_line=$(grep -n -m1 -F -- "$first" "$file" | cut -d: -f1 || true)
  second_line=$(grep -n -m1 -F -- "$second" "$file" | cut -d: -f1 || true)
  if [ -z "$first_line" ] || [ -z "$second_line" ] || [ "$first_line" -ge "$second_line" ]; then
    echo "FAIL: $file must install curl and python3 before resolving nginx" >&2
    exit 1
  fi
}

require_regex() {
  local file=$1 pattern=$2
  if ! grep -Eq -- "$pattern" "$file"; then
    echo "FAIL: $file must declare a matching fork fallback dependency" >&2
    exit 1
  fi
}

# These workflows resolve nginx with curl before their normal package profile.
# A fork has no vars.POOL, so ubuntu-latest must receive curl explicitly first.
for file in \
  .github/workflows/asan.yml \
  .github/workflows/build-test.yml \
  .github/workflows/ci-deep.yml \
  .github/workflows/codeql.yml \
  .github/workflows/valgrind.yml; do
  require "$file" 'name: Install bootstrap dependencies'
done

# The resolver reads the GitHub releases feed with curl and parses it with
# python3. Every JOB that runs it must carry its own "Install bootstrap
# dependencies" step ahead of the resolver step, installing both; a later
# job-specific install, or another job's bootstrap, must not satisfy that.
# Checked per job rather than per file: ci-deep.yml resolves in two jobs,
# and a file-wide ordering check stayed green with one of them stripped.
for file in \
  .github/workflows/asan.yml \
  .github/workflows/build-test.yml \
  .github/workflows/ci-deep.yml \
  .github/workflows/codeql.yml \
  .github/workflows/valgrind.yml; do
  require_resolver_jobs "$file"
done

# Detached nginx signatures are verified by these fallback workflows.  Do not
# let their green runs depend on gpg having happened to be in a runner image.
for file in \
  .github/workflows/asan.yml \
  .github/workflows/build-test.yml \
  .github/workflows/bump.yml \
  .github/workflows/ci-deep.yml \
  .github/workflows/codeql.yml \
  .github/workflows/harness-fault-arms.yml \
  .github/workflows/security-scanners.yml \
  .github/workflows/valgrind.yml; do
  require_apt_package "$file" gnupg
done

# Test::Nginx is deliberately installed from its pinned CPAN distribution;
# semgrep is deliberately installed through pipx/pip.  Keep both paths
# visible in the workflow rather than assuming a persistent builder carries
# either tool already.
require_apt_package .github/workflows/build-test.yml cpanminus
# The validation job runs this script through git, while cvary-interop clones
# the real comparison module.  Check both declarations rather than allowing a
# package in one job to mask a missing package in the other.
require_regex .github/workflows/build-test.yml '^[[:space:]]+git[[:space:]]+\\$'
require .github/workflows/build-test.yml \
  'sudo apt-get install -y build-essential git gnupg libzstd-dev'
require_apt_package .github/workflows/ci-deep.yml cpanminus
require .github/workflows/security-scanners.yml 'semgrep==1.173.0'

# The soak workers construct their dictionary digest with the openssl CLI;
# likewise, the deep fuzz failure notification serializes JSON with Python.
require_apt_package .github/workflows/asan.yml openssl
require_apt_package .github/workflows/valgrind.yml openssl
require_apt_package .github/workflows/ci-deep.yml openssl
require_apt_package .github/workflows/ci-deep.yml clang
require_apt_package .github/workflows/ci-deep.yml curl
require_apt_package .github/workflows/ci-deep.yml python3

# CodeQL inspects its database through Python and unpacks src.zip when the
# action stores extracted sources as an archive.
require_apt_package .github/workflows/codeql.yml python3
require_apt_package .github/workflows/codeql.yml unzip
# The dependency parser itself uses yaml.safe_load; keep that import available
# in the validation job that executes this script.
require_apt_package .github/workflows/build-test.yml python3-yaml

# Negative control: comments are not package installations.
mutant=$(mktemp -d "${TMPDIR:-/tmp}/dependency-bootstrap.XXXXXX")
trap 'rm -rf "$mutant"' EXIT
mkdir -p "$mutant/.github/workflows"
cp .github/workflows/asan.yml "$mutant/.github/workflows/asan.yml"
sed -i 's/gnupg/libgcrypt20-dev/g' "$mutant/.github/workflows/asan.yml"
printf '\n# gnupg was removed from the apt install above\n' \
  >>"$mutant/.github/workflows/asan.yml"
sed -i '/set -euo pipefail/a\          echo install gnupg' \
  "$mutant/.github/workflows/asan.yml"
sed -i '/set -euo pipefail/a\          echo "apt-get install gnupg"' \
  "$mutant/.github/workflows/asan.yml"
if CI_DEPENDENCY_ROOT="$mutant" require_apt_package \
    .github/workflows/asan.yml gnupg >/dev/null 2>&1; then
  echo 'FAIL: dependency comment mutant was accepted as an installation' >&2
  exit 1
fi
echo 'OK: dependency comment mutant rejected'

# Negative control: strip ONE resolver job's bootstrap step (ci-deep.yml's
# helgrind job) while the memcheck job keeps its own. A file-wide check
# accepted this; the per-job check must not.
cp .github/workflows/ci-deep.yml "$mutant/.github/workflows/ci-deep.yml"
python3 - "$mutant/.github/workflows/ci-deep.yml" <<'PY'
import pathlib, sys, yaml
path = pathlib.Path(sys.argv[1])
doc = yaml.safe_load(path.read_text(encoding="utf-8"))
job = doc["jobs"]["helgrind"]
before = len(job["steps"])
job["steps"] = [s for s in job["steps"]
                if not (isinstance(s, dict)
                        and s.get("name") == "Install bootstrap dependencies")]
if len(job["steps"]) != before - 1:
    raise SystemExit("mutant did not remove exactly one bootstrap step")
path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
PY
if CI_DEPENDENCY_ROOT="$mutant" require_resolver_jobs \
    .github/workflows/ci-deep.yml >/dev/null 2>&1; then
  echo 'FAIL: a resolver job with its bootstrap step removed was accepted' >&2
  exit 1
fi
echo 'OK: single-job bootstrap removal mutant rejected'

echo 'OK: fork fallback dependencies are explicitly bootstrapped'
