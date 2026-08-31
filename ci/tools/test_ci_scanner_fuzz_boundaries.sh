#!/usr/bin/env bash
# Gate CI C scanner selectors and the production-sized fuzz domain.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

assert_contract() {
  local base=${1:-.}
  grep -Fq "'^(src|ci)/.*\.[ch]$'" "$base/ci/linter/lint-c.sh" || return 1
  [ "$(grep -Fc "files: '^(src|ci)/.*\.[ch]$'" "$base/.pre-commit-config.yaml")" -ge 3 ] \
    || return 1
  # The workflow expression is intentionally literal.
  # shellcheck disable=SC2016
  grep -Fq '"$GITHUB_WORKSPACE/ci/"' \
    "$base/.github/workflows/security-scanners.yml" || return 1
  # shellcheck disable=SC2016
  grep -Fq 'find "$GITHUB_WORKSPACE/src" "$GITHUB_WORKSPACE/ci"' \
    "$base/.github/workflows/security-scanners.yml" || return 1
  [ "$(grep -Fc -- '-max_len=65536' "$base/.github/workflows/fuzzing.yml")" -ge 2 ] \
    || return 1
  grep -Fq -- '-max_len=65536' "$base/.github/workflows/ci-deep.yml" \
    || return 1
  grep -Fq 'for size in 4095 4096 4097 65535 65536' \
    "$base/.github/workflows/fuzzing.yml" || return 1
}

assert_contract

work=$(mktemp -d "${TMPDIR:-/tmp}/scanner-fuzz-contract.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/ci/linter"
cp ci/linter/lint-c.sh "$work/ci/linter/"
cp .pre-commit-config.yaml "$work/"
cp -a .github "$work/"
sed -i 's/(src|ci)/src/g; s/65536/4096/g' \
  "$work/ci/linter/lint-c.sh" "$work/.pre-commit-config.yaml" \
  "$work/.github/workflows/security-scanners.yml" "$work/.github/workflows/fuzzing.yml" \
  "$work/.github/workflows/ci-deep.yml"
if assert_contract "$work" >/dev/null 2>&1; then
  echo 'FAIL: scanner/max_len mutant did not make the contract gate red' >&2
  exit 1
fi
assert_contract
echo 'OK: CI C scanner selectors and >4096 fuzz boundaries are enforced'
