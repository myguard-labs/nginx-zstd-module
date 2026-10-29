#!/usr/bin/env bash
# Pinned Test::Nginx::Socket install (upstream #214 + #249 lineage).
# The @version pin alone still trusts the CPAN index at run time twice:
# the version->dist resolution and the dependency graph both float. So
# before installing, assert (1) the index resolves the pinned version to
# the exact expected dist, and (2) the resolver's dependency graph is
# byte-identical to the committed lock -- a new dep, a dropped dep, or a
# version-range bump all fail loudly instead of installing silently.
#
# Usage: install_test_nginx_socket.sh [--sudo | --local-lib DIR]
set -euo pipefail

mode="${1:---sudo}"
libdir="${2:-}"

version="${TEST_NGINX_SOCKET_VERSION:-0.32}"
dist="AGENT/Test-Nginx-${version}.tar.gz"
lock="$(dirname "$0")/test-nginx-socket.cpan.lock"
spec="Test::Nginx::Socket@${version}"

resolved="$(cpanm --info "$spec" 2>/dev/null \
	| awk '/^[A-Z0-9]+\/.*\.tar\.gz$/ {print; exit}')"
if [ "$resolved" != "$dist" ]; then
	echo "::error::$spec resolved to '$resolved', expected '$dist'" >&2
	exit 1
fi

# LC_ALL=C on both sorts: the lock is committed in byte order, and a
# locale-collated sort (e.g. en_US: List before LWP) would diff clean
# content as a mismatch
deps="$(cpanm --showdeps "$spec" 2>/dev/null \
	| awk '/^[A-Za-z0-9_:]+(~[^[:space:]]+)?$/ {print}' | LC_ALL=C sort)"
locked="$(grep -Ev '^\s*(#|$)' "$lock" | LC_ALL=C sort)"
if [ "$deps" != "$locked" ]; then
	echo "::error::$spec CPAN dependency graph differs from $lock" >&2
	diff <(echo "$locked") <(echo "$deps") >&2 || true
	exit 1
fi

case "$mode" in
--sudo)
	sudo cpanm --notest --quiet "$spec"
	installed="$(perl -MTest::Nginx::Socket \
		-e 'print $Test::Nginx::Socket::VERSION')"
	;;
--local-lib)
	: "${libdir:?--local-lib needs a directory}"
	cpanm -l "$libdir" --notest --quiet "$spec"
	installed="$(perl -I "$libdir/lib/perl5" -MTest::Nginx::Socket \
		-e 'print $Test::Nginx::Socket::VERSION')"
	;;
*)
	echo "usage: $0 [--sudo | --local-lib DIR]" >&2
	exit 2
	;;
esac

echo "Test::Nginx::Socket installed version: $installed"
if [ "$installed" != "$version" ]; then
	echo "::error::Test::Nginx::Socket version mismatch:" \
		"pinned $version, got $installed" >&2
	exit 1
fi
