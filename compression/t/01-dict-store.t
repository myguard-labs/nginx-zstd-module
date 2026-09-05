use Test::Nginx::Socket;
use Digest::SHA qw(sha256_hex);
use File::Temp qw(tempdir);
use File::Basename qw(dirname);

# Phase-1a store rules as a regression suite: every config-load rule
# from the shell matrix, plus the $compression_dicts_hashed witness
# and the inheritance semantics only Test::Nginx can express cleanly.
# The dictionary contents are Perl constants so their hashes are
# computed here, never hardcoded.

our $dict_a  = "const shared = 'store fixture material, dictionary A';\n" x 40;

# strict-walk fixtures (parent #199): an out-of-servroot tempdir whose
# ABSOLUTE path goes into the config verbatim, with a real directory
# and a symlinked alias to it — the walk must refuse the alias at the
# intermediate component and accept the real chain — plus (parent
# #316) a world-writable and a sticky world-writable parent, which the
# walk must refuse as ancestors.
#
# NOT under /tmp: /tmp is 1777, and the walk now vets every ancestor,
# so a fixture there would fail its positive control for the /tmp's
# sake, not the test's. The tempdir goes under $HOME, and the whole
# ancestor chain is checked to be root- or self-owned and not
# group/world-writable; a host where it is not (a shared /home, a
# drvfs mount) skips these tests rather than failing them for a reason
# that is not what they test.
# Guarded, not die-on-failure (CodeRabbit round 5): only the walk tests
# consume this fixture, and a host that cannot symlink (a Windows-side
# checkout without SeCreateSymbolicLink, a restricted tmp) must skip
# them via skip_eval instead of killing the whole file at file scope.
our $walkdir;
our $have_walk = eval {
    my $base = $ENV{HOME};
    die "no HOME for a vetted fixture base\n" unless defined $base && -d $base;
    $walkdir = tempdir(DIR => $base, CLEANUP => 1);
    for (my $d = $walkdir; ; $d = dirname($d)) {
        my @st = stat($d) or die "stat $d: $!";
        die "ancestor $d owned by uid $st[4], neither root nor uid $>\n"
            if $st[4] != 0 && $st[4] != $>;
        die sprintf("ancestor %s is mode %04o, writable by group or other\n", $d, $st[2] & 07777)
            if $st[2] & 022;
        last if $d eq '/';
    }
    mkdir "$walkdir/real" or die "mkdir: $!";
    open my $h, '>', "$walkdir/real/w.dict" or die "spew: $!";
    print $h "strict walk fixture dictionary contents\n" x 20;
    close $h;
    symlink("$walkdir/real", "$walkdir/link") or die "symlink: $!";
    for my $arm (['open', 0777], ['sticky', 01777]) {
        my ($name, $mode) = @$arm;
        mkdir "$walkdir/$name" or die "mkdir $name: $!";
        open my $f, '>', "$walkdir/$name/w.dict" or die "spew $name: $!";
        print $f "strict walk fixture dictionary contents\n" x 20;
        close $f;
        chmod $mode, "$walkdir/$name" or die "chmod $name: $!";
        my @st = stat("$walkdir/$name");
        die "chmod $name did not stick\n" if ($st[2] & 07777) != $mode;
    }
    1;
} || 0;
our $dict_b  = "let other = 'store fixture material, dictionary B';\n" x 40;
our $hex_a   = sha256_hex($dict_a);
our $badhex  = '0' x 64;

# six distinct dictionaries to force the store's pointer array past its
# initial capacity (WRINKLES 14: growth relocates a value-array's
# element storage; this pins the pointer-store fix)
our @growth = map { "growth dictionary number $_ fixture content\n" x 20 } 1..6;

no_long_string();
log_level 'warn';
# config-load errors/warnings and the cycle-owned counter are observed
# once per start; repeats would re-read a wiped error.log
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: a computed dictionary loads, and the witness counts one pass
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config
    compression_dict_file html/a.dict;
--- config
    location /w {
        default_type text/plain;
        return 200 "hashed=$compression_dicts_hashed";
    }
--- request
GET /w
--- response_body: hashed=1
--- no_error_log
[error]



=== TEST 2: a supplied hash is verified by default
# parent #198/#220: the literal declares what the operator believes
# the file to be, and the default computes the truth to check it — the
# counter reads 1 where the old trust-verbatim contract read 0. That
# contract lives on behind compression_dict_trust_hashes (TEST 28).
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_file html/a.dict $::hex_a;\n}
--- config
    location /w {
        default_type text/plain;
        return 200 "hashed=$compression_dicts_hashed";
    }
--- request
GET /w
--- response_body: hashed=1
--- no_error_log
[error]



=== TEST 3: store dedup + verified-entry reuse, witnessed exactly
# a.dict supplied at http (1 verify compute — the #198 default) +
# b.dict computed (1) + a.dict re-referenced UNSUPPLIED in a location
# (0 — the entry was verified at load, so the mandated-audit rule has
# nothing left to check) = 2. Same total as the old trust-verbatim
# arithmetic (0+1+1), but the passes moved to load time; the audit's
# own compute is pinned under trust_hashes in TEST 30. The same files
# referenced from two levels load once each.
--- user_files eval
[ [ "a.dict" => $::dict_a ], [ "b.dict" => $::dict_b ] ]
--- http_config eval
qq{    compression_dict_file html/a.dict $::hex_a;
    compression_dict_file html/b.dict;\n}
--- config
    location /w {
        compression_dict_file html/a.dict;
        compression_dict_file html/b.dict;
        default_type text/plain;
        return 200 "hashed=$compression_dicts_hashed";
    }
--- request
GET /w
--- response_body: hashed=2
--- no_error_log
[error]



=== TEST 4: a malformed hash is reported BEFORE the file is opened
# ordering pin from the parent repo: the path here does not exist, and
# the error must still be about the hash — the operator fixes their
# config once, not twice
--- http_config
    compression_dict_file html/does-not-exist.dict zz11;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
invalid dictionary hash
--- no_error_log
[alert]



=== TEST 5: a missing dictionary file fails at config load
--- http_config
    compression_dict_file html/does-not-exist.dict;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
failed
--- no_error_log
[alert]



=== TEST 6: two different paths with identical content collide on hash
# RFC 9842 negotiation keys on the hash alone; duplicates would be
# ambiguous. Config error, naming the colliding path.
--- user_files eval
[ [ "a.dict" => $::dict_a ], [ "a-copy.dict" => $::dict_a ] ]
--- http_config
    compression_dict_file html/a.dict;
    compression_dict_file html/a-copy.dict;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
has the same hash as
--- no_error_log
[alert]



=== TEST 7: the same path twice in one list is a duplicate
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config
    compression_dict_file html/a.dict;
    compression_dict_file html/a.dict;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
duplicate dictionary
--- no_error_log
[alert]



=== TEST 8: a stale supplied hash is caught at FIRST load (verify default)
# parent #198: the wrong literal dies at its own line now, naming both
# values — no unsupplied reference needed to force the audit. The
# audit-catches-it contract this block used to pin survives under
# trust_hashes as TEST 30, where the audit is the only net left.
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_file html/a.dict $::badhex;\n}
--- config
    location /t {
        compression_dict_file html/a.dict;
        return 200 "x";
    }
--- must_die
--- error_log eval
qr/does not match the supplied hash "$::badhex": the file's SHA-256 is "$::hex_a"/
--- no_error_log
[alert]



=== TEST 9: conflicting supplied hashes for one path are a config error
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_file html/a.dict $::hex_a;\n}
--- config eval
qq{    location /t {
        compression_dict_file html/a.dict $::badhex;
        return 200 "x";
    }\n}
--- must_die
--- error_log
conflicting sha256
--- no_error_log
[alert]



=== TEST 10: duplicate detection survives store growth (WRINKLES 14)
# six dictionaries force the pointer array past its initial capacity;
# re-declaring the FIRST afterwards must still be caught — the
# value-array store silently accepted this after growth relocated the
# entries out from under the list's aliases
--- user_files eval
[ map { [ "g$_.dict" => $::growth[$_ - 1] ] } 1..6 ]
--- http_config
    compression_dict_file html/g1.dict;
    compression_dict_file html/g2.dict;
    compression_dict_file html/g3.dict;
    compression_dict_file html/g4.dict;
    compression_dict_file html/g5.dict;
    compression_dict_file html/g6.dict;
    compression_dict_file html/g1.dict;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
duplicate dictionary
--- no_error_log
[alert]



=== TEST 11: an empty dictionary file is a config error
--- user_files eval
[ [ "empty.dict" => "" ] ]
--- http_config
    compression_dict_file html/empty.dict;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
empty or unreadable
--- no_error_log
[alert]



=== TEST 12: a 63-character hash is rejected (one under valid)
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_file html/a.dict } . ("0" x 63) . qq{;\n}
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
invalid dictionary hash
--- no_error_log
[alert]



=== TEST 13: a 65-character hash is rejected (one over valid)
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_file html/a.dict } . ("0" x 65) . qq{;\n}
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
invalid dictionary hash
--- no_error_log
[alert]


=== TEST 14: a dictionary above the 8 MB browser window warns at load
# parent parity: content beyond the window cannot reference the far
# end of the dictionary; loading proceeds, the operator is told
--- user_files eval
[ [ "big.dict" => ("x" x 8388609) ] ]
--- http_config
    compression_dict_file html/big.dict;
--- config
    location /t {
        compression on;
        default_type text/html;
        gzip_vary on;
        return 200 "oversized dictionary fixture body long enough\n";
    }
--- request
GET /t
--- error_log
larger than the 8 MB window browsers enforce


=== TEST 15: a MISSING optional dictionary warns and the server starts
# the operator-insistence demotion (intentional RFC deviation): a
# botched deploy must not take the site down — clients holding the
# absent dictionary degrade to the base coding
--- config
    location /t {
        compression on;
        compression_dict_file html/does-not-exist.dict optional;
        default_type text/html;
        gzip_vary on;
        return 200 "optional-missing fixture body long enough here\n";
    }
--- request
GET /t
--- error_code: 200
--- error_log
skipping optional dictionary


=== TEST 16: a missing dictionary WITHOUT optional still refuses to start
--- config
    location /t {
        compression on;
        compression_dict_file html/does-not-exist.dict;
        default_type text/html;
        return 200 "strict-missing fixture body long enough here\n";
    }
--- must_die
--- error_log
open() dictionary


=== TEST 17: an EMPTY optional dictionary warns and the server starts
--- user_files eval
[ [ "empty.dict" => "" ] ]
--- config
    location /t {
        compression on;
        compression_dict_file html/empty.dict optional;
        default_type text/html;
        gzip_vary on;
        return 200 "optional-empty fixture body long enough here\n";
    }
--- request
GET /t
--- error_code: 200
--- error_log
skipping optional dictionary


=== TEST 18: same-hash different-path with optional aliases and warns
--- user_files eval
[ [ "a.dict" => ("alias fixture dictionary content\n" x 20) ],
  [ "b.dict" => ("alias fixture dictionary content\n" x 20) ] ]
--- config
    location /t {
        compression on;
        compression_dict_file html/a.dict;
        compression_dict_file html/b.dict optional;
        default_type text/html;
        gzip_vary on;
        return 200 "alias fixture body long enough to compress here\n";
    }
--- request
GET /t
--- error_code: 200
--- error_log
using the existing entry


=== TEST 19: a duplicate optional line in one list warns and skips
--- user_files eval
[ [ "a.dict" => ("dup fixture dictionary content\n" x 20) ] ]
--- config
    location /t {
        compression on;
        compression_dict_file html/a.dict optional;
        compression_dict_file html/a.dict optional;
        default_type text/html;
        gzip_vary on;
        return 200 "dup fixture body long enough to compress here\n";
    }
--- request
GET /t
--- error_code: 200
--- error_log
skipping the duplicate


=== TEST 20: garbage where the hash belongs stays FATAL even with optional
# a typo is a config bug to fix once, not a deploy race to ride out
--- user_files eval
[ [ "a.dict" => ("typo fixture dictionary content\n" x 20) ] ]
--- config
    location /t {
        compression_dict_file html/a.dict zzzz optional;
    }
--- must_die
--- error_log
invalid dictionary hash "zzzz"


=== TEST 21: a non-regular dictionary path is FATAL, unconditionally (parent #165)
# html/ resolves to a directory; ngx_is_file() rejects it before any read.
# Not gated on strict_path — a FIFO/socket/dir was never a valid dictionary.
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config
    compression_dict_file html;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
is not a regular file
--- no_error_log
[alert]


=== TEST 22: compression_dict_strict_path is MAIN_CONF only (parent #165)
# The store is cycle-global, so the strict-trust policy is a property of the
# whole load — declared once in http{}, never per-location. A location-level
# use is a directive-context error caught at config parse.
--- config
    location /t {
        compression_dict_strict_path on;
        return 200 "x";
    }
--- must_die
--- error_log
directive is not allowed here
--- no_error_log
[alert]

=== TEST 23: strict_path declared AFTER a dict_file is a config error
# Order-dependent fail-open (review round 3): the flag is read at
# parse time, so a load above the "on" line ran without O_NOFOLLOW or
# the writable-target check. Directives are conventionally
# order-independent -- rejecting the ordering outright beats silently
# skipping the vetting the operator asked for, and beats re-opening
# every dictionary in init_main_conf (which would reintroduce the
# TOCTOU window the fstat-after-open checks close). Parent shape.
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config
    compression_dict_file html/a.dict;
    compression_dict_strict_path on;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
"compression_dict_strict_path on" was declared AFTER
--- no_error_log
[alert]


=== TEST 24: strict_path declared BEFORE the dict_file loads and serves
# Positive control for TEST 23: same directives, sanctioned order --
# the load runs under the strict checks and the server starts.
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config
    compression_dict_strict_path on;
    compression_dict_file html/a.dict;
--- config
    location /t { return 200 "ok\n"; }
--- request
GET /t
--- error_code: 200
--- response_body
ok
--- no_error_log
[error]

=== TEST 25: strict mode refuses a ".." path component
# parent #199 (M3): ".." would climb back above a component the walk
# already verified, making its guarantee unstatable — refused rather
# than resolved. The same file loads through its plain path (TEST 26's
# positive control), so nothing but the component check rejects this.
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config
    compression_dict_strict_path on;
    compression_dict_file html/../html/a.dict;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
contains a "." or ".." component
--- no_error_log
[alert]


=== TEST 26: strict mode refuses a symlinked INTERMEDIATE component
# parent #199 (M3): O_NOFOLLOW on a whole-path open guards only the
# leaf, so the classic "current -> releases/7" layout walked straight
# through the old check. The component walk refuses the symlink where
# it sits. The real chain (positive control below) is byte-identical.
--- skip_eval: 3: !$::have_walk
--- http_config eval
"compression_dict_strict_path on;
 compression_dict_file $::walkdir/link/w.dict;"
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
a symlink at any component is refused
--- no_error_log
[alert]


=== TEST 27: the same dictionary loads through its real component chain
# Positive control for TESTs 25/26: identical file, symlink-free
# absolute path, strict on — the walk verifies every component and the
# server starts.
--- skip_eval: 3: !$::have_walk
--- http_config eval
"compression_dict_strict_path on;
 compression_dict_file $::walkdir/real/w.dict;"
--- config
    location /t { return 200 "ok\n"; }
--- request
GET /t
--- error_code: 200
--- response_body
ok
--- no_error_log
[error]

=== TEST 27a: strict mode refuses a world-writable PARENT directory
# parent #316 (A33-F2): both leaf checks pass — the file is self-owned
# 0644 — but its parent is 0777, so any local user could rename() a
# different file into the leaf position; the walk refuses the ancestor,
# not the leaf. TEST 27c loads the identical file with strict off.
--- skip_eval: 3: !$::have_walk
--- http_config eval
"compression_dict_strict_path on;
 compression_dict_file $::walkdir/open/w.dict;"
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
directory component "open" of
writable by group or other
--- no_error_log
[alert]


=== TEST 27b: strict mode refuses a STICKY world-writable parent too
# parent #316: no sticky-bit exemption. A 1777 parent stops other users
# deleting the file, but still lets any of them create the next path
# component beside it — the steering the walk exists to refuse.
--- skip_eval: 3: !$::have_walk
--- http_config eval
"compression_dict_strict_path on;
 compression_dict_file $::walkdir/sticky/w.dict;"
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
directory component "sticky" of
no sticky-bit exemption
--- no_error_log
[alert]


=== TEST 27c: the same file under the world-writable parent loads with strict off
# Positive control for 27a/27b: default mode leaf-checks the file only,
# so the ancestor's mode is not its concern and the server starts.
--- skip_eval: 3: !$::have_walk
--- http_config eval
"compression_dict_file $::walkdir/open/w.dict;"
--- config
    location /t { return 200 "ok\n"; }
--- request
GET /t
--- error_code: 200
--- response_body
ok
--- no_error_log
[error]


=== TEST 28: trust_hashes on — the zero-hashing fast path, restored
# The old TEST 2 contract, now behind the flag (parent #220): a
# trusted literal contributes ZERO to the counter. Substituting the
# literal after hashing anyway (trust as a no-op) reads 1 here.
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_trust_hashes on;
    compression_dict_file html/a.dict $::hex_a;\n}
--- config
    location /w {
        default_type text/plain;
        return 200 "hashed=$compression_dicts_hashed";
    }
--- request
GET /w
--- response_body: hashed=0
--- no_error_log
[error]


=== TEST 29: trust_hashes on — a wrong literal LOADS (the operator owns it)
# The exact config TEST 8 must_die's under the default. The
# negotiation-level proof that the declared value is the live key is
# 02-dict-negotiation TEST 28; here the config-load contract: server
# starts, zero hashing.
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_trust_hashes on;
    compression_dict_file html/a.dict $::badhex;\n}
--- config
    location /w {
        default_type text/plain;
        return 200 "hashed=$compression_dicts_hashed";
    }
--- request
GET /w
--- response_body: hashed=0
--- no_error_log
[error]


=== TEST 30: trust_hashes on — the unsupplied-reference audit is the net
# "A supplied hash never satisfies a directive that didn't supply one"
# has real work again under trust: the location's unsupplied reference
# mandates a computation, and that computation catches the stale
# trusted literal — TEST 8's old contract, preserved where it is the
# only check left.
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_trust_hashes on;
    compression_dict_file html/a.dict $::badhex;\n}
--- config
    location /t {
        compression_dict_file html/a.dict;
        return 200 "x";
    }
--- must_die
--- error_log
does not match the file
--- no_error_log
[alert]


=== TEST 31: trust_hashes declared AFTER a literal line is a config error
# Same ordering trap and remedy as compression_dict_strict_path: the
# flag is read at parse time, so a literal above the "on" line was
# verified — correct bytes, but the pass the directive exists to skip
# was silently paid. Reject rather than be quietly position-dependent.
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_file html/a.dict $::hex_a;
    compression_dict_trust_hashes on;\n}
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
"compression_dict_trust_hashes on" was declared AFTER
--- no_error_log
[alert]


=== TEST 32: trust_hashes on does not excuse a malformed literal
# Trust changes what a well-formed literal means, not what a malformed
# one does: syntax is validated before the file is opened under either
# policy (and stays FATAL even with "optional", as always).
--- http_config
    compression_dict_trust_hashes on;
    compression_dict_file html/does-not-exist.dict zz11;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
invalid dictionary hash
--- no_error_log
[alert]


=== TEST 33: verify default + "optional" — a stale literal warns, computed wins
# The optional demotion composes with #198's verify exactly like the
# audit path always did: warn, and the computed truth keys the entry
# so clients holding the REAL file still negotiate. The counter proves
# the verify pass ran.
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_file html/a.dict $::badhex optional;\n}
--- config
    location /w {
        default_type text/plain;
        return 200 "hashed=$compression_dicts_hashed";
    }
--- request
GET /w
--- response_body: hashed=1
--- error_log
stale supplied sha256; the file's computed hash wins
--- no_error_log
[error]
