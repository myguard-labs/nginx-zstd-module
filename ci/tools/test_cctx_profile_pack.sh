#!/bin/bash
set -e

cd "$(dirname "$0")"
gcc -Wall -Wextra -o test_cctx_profile_pack test_cctx_profile_pack.c
./test_cctx_profile_pack
