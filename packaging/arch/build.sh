#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)

rm -rf -- "${script_dir:?}/dist"
mkdir -p "$script_dir/dist"
docker build --no-cache --build-context "checkout=$repo_root" --target test \
    --output type=cacheonly "$script_dir"
docker build --target artifact --output "type=local,dest=$script_dir/dist" \
    "$script_dir"

find "$script_dir/dist" -maxdepth 1 -type f -name 'nginx-mod-zstd-*.pkg.tar.zst' \
    -print
