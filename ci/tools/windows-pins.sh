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
VER_NGINX=1.31.8
SHA_NGINX=0652b760b3b772d2ec17b47c2fc15d9a95e6fe35cd5b877eadc1a62d9bc75af1
VER_PCRE2=10.49
SHA_PCRE2=929f0b20e62879252a15886b06c89f1edef61a363cbd5826fb041080a5e557ae
VER_OPENSSL=4.1.0
SHA_OPENSSL=50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd
VER_ZLIB=1.4
SHA_ZLIB=02dd159783677a749c04adbdd02b55b8a2bcc7e054f51b76b549199a916ad584
VER_NASM=3.02
SHA_NASM=f504227b2f529e658d41629075f0503b38d67d790af345f34eba4af60c6a5998
VER_ZSTD=1.5.7
SHA_ZSTD=eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3
