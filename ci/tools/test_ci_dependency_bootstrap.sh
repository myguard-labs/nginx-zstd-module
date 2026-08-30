#!/usr/bin/env bash
# ci/tools/test_ci_dependency_bootstrap.sh -- ensure fork fallbacks install
# their non-runner dependencies before CI uses them.
#
# Usage: ci/tools/test_ci_dependency_bootstrap.sh
# Inputs: repository .github/workflows/*.yml files.
# Side effects: none.  Exit non-zero on a missing bootstrap or package.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

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
    echo "FAIL: $file must install curl before resolving nginx" >&2
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

for file in \
  .github/workflows/asan.yml \
  .github/workflows/build-test.yml \
  .github/workflows/ci-deep.yml \
  .github/workflows/codeql.yml \
  .github/workflows/valgrind.yml; do
  require_before "$file" 'name: Install bootstrap dependencies' \
    'curl -fsSL https://nginx.org/en/download.html'
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
  require "$file" 'gnupg'
done

# Test::Nginx is deliberately installed from its pinned CPAN distribution;
# semgrep is deliberately installed through pipx/pip.  Keep both paths
# visible in the workflow rather than assuming a persistent builder carries
# either tool already.
require .github/workflows/build-test.yml 'cpanminus'
# The validation job runs this script through git, while cvary-interop clones
# the real comparison module.  Check both declarations rather than allowing a
# package in one job to mask a missing package in the other.
require_regex .github/workflows/build-test.yml '^[[:space:]]+git[[:space:]]+\\$'
require .github/workflows/build-test.yml \
  'sudo apt-get install -y build-essential git gnupg libzstd-dev'
require .github/workflows/ci-deep.yml 'cpanminus'
require .github/workflows/security-scanners.yml 'semgrep==1.173.0'

# The soak workers construct their dictionary digest with the openssl CLI;
# likewise, the deep fuzz failure notification serializes JSON with Python.
require .github/workflows/asan.yml 'openssl'
require .github/workflows/valgrind.yml 'openssl'
require .github/workflows/ci-deep.yml 'openssl'
require .github/workflows/ci-deep.yml 'sudo apt-get install -y clang curl python3'

# CodeQL inspects its database through Python and unpacks src.zip when the
# action stores extracted sources as an archive.
require .github/workflows/codeql.yml 'python3'
require .github/workflows/codeql.yml 'unzip'

echo 'OK: fork fallback dependencies are explicitly bootstrapped'
