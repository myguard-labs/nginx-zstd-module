# ci/tools/windows-pins.sh -- the pinned sources of the Windows build.
#
# THE one place the Windows build's versions and SHA-256 digests live.
# ci/tools/build-windows.sh sources this file (and refuses to run without
# it) and .github/workflows/windows-build.yml reads it into each job's
# environment; a version bump edits this file and nothing else. Plain
# KEY=value lines only -- no quoting, no expansion, no logic -- so any
# consumer (a workflow step, a bump script, a human) can read it as data.
#
# Bumping: the weekly Bump workflow (ci/tools/bump-versions.sh) rewrites
# these lines for every source but nasm, which has no release feed to
# query. By hand: set VER_X, then SHA_X to the tarball's sha256 (the build
# script prints the actual digest on a mismatch, so a stale digest is a
# copy-paste away from fixed). nginx tarballs also carry a detached PGP
# signature -- verify it with ci/tools/verify-nginx-tarball.sh before
# recording a new digest.
#
# Data only: every assignment here is consumed by the sourcing script,
# which shellcheck cannot see when it lints this file on its own.
# shellcheck shell=sh disable=SC2034
VER_NGINX=1.31.6
SHA_NGINX=974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1
VER_PCRE2=10.49
SHA_PCRE2=929f0b20e62879252a15886b06c89f1edef61a363cbd5826fb041080a5e557ae
VER_OPENSSL=4.0.3
SHA_OPENSSL=325b5c806167c13b40b1ffeadfe0248197c00eccc4cf123ec1e28d2d2fd216d9
VER_ZLIB=1.3.2
SHA_ZLIB=bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16
VER_NASM=3.02
SHA_NASM=f504227b2f529e658d41629075f0503b38d67d790af345f34eba4af60c6a5998
VER_ZSTD=1.5.7
SHA_ZSTD=eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3
