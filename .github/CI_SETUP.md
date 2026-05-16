# CI/CD Pipeline

Automated testing and validation for the zstd-nginx-module.

## GitHub Actions Workflow

The CI pipeline is defined in `.github/workflows/build.yml` and automatically runs on:
- **Push** to `master`, `main`, or `dev` branches
- **Pull requests** to `master` or `main`

### Jobs

The workflow consists of 4 independent, parallel jobs:

#### 1. Syntax Check
Validates C code syntax without compiling full nginx:
- Checks filter module (`filter/ngx_http_zstd_filter_module.c`)
- Checks static module (`static/ngx_http_zstd_static_module.c`)
- Uses GCC with `-Wall -Wextra -Werror` flags
- No linking required - just compilation check

**What it catches:**
- ✓ Missing includes
- ✓ Type mismatches
- ✓ Syntax errors
- ✓ Implicit function declarations

**Runtime:** ~30 seconds

#### 2. Test Suite
Runs the Perl test suite plus focused truncation and stability smoke tests:
- 29 filter module tests
- 18 static module tests
- 5 end-to-end smoke tests
- Total: 47 Perl tests + 5 end-to-end smoke tests

**What it covers:**
- ✓ Encoding detection and priority
- ✓ RFC 7231 quality values (q parameter)
- ✓ Compression levels and ratios
- ✓ HTTP method handling
- ✓ Pre-compressed file serving
- ✓ gzip interaction
- ✓ HEAD/204/205/304 no-body filter behaviour
- ✓ 403/404 compressed error-response behaviour
- ✓ Vary: Accept-Encoding emission when gzip_vary is enabled
- ✓ Boundary-sized large-response integrity near the historical truncation threshold
- ✓ Per-request CCtx handling across sequential requests
- ✓ Two concurrent requests against the same nginx worker
- ✓ Large JavaScript response integrity after zstd decompression

**Runtime:** ~1-2 minutes

#### 3. Tools Validation
Validates testing and deployment tools:
- Python script syntax check (test_encoding.py)
- Bash script validation (syntax check with `bash -n`)
- Shell script linting with shellcheck
- Tool help output verification

**What it validates:**
- ✓ test_encoding.py works
- ✓ validate_zstd_module.sh syntax
- ✓ run_zstd_tests.sh syntax
- ✓ package_zstd_module.sh syntax
- ✓ ci-build.sh syntax

**Runtime:** ~20 seconds

#### 4. Code Linting & Analysis
Comprehensive code quality scanning:
- cppcheck (static analysis)
- flawfinder (security vulnerability scanner)
- clang static analyzer (code flow analysis)
- Strict compiler warnings (-Wpedantic -Wshadow -Wstrict-aliasing)

**What it detects:**
- ✓ Potential null pointer dereferences
- ✓ Buffer overflow vulnerabilities
- ✓ Memory leaks and use-after-free issues
- ✓ Integer overflows
- ✓ Uninitialized variables
- ✓ Security vulnerabilities (minlevel 2+)
- ✓ Dead/unreachable code

**Reports:**
- cppcheck.log, flawfinder.log, clang-scan.log
- filter-warnings.log, static-warnings.log
- All saved as artifacts (7-day retention)

**Runtime:** ~1-2 minutes

---

### Total CI Time

**All 4 jobs run in parallel:**
- Syntax Check: ~30 seconds
- Test Suite: ~1-2 minutes
- Tools Validation: ~20 seconds
- Code Linting: ~1-2 minutes

**Total wall-clock time: ~3-4 minutes**

---

## Local Testing

Use the `ci-build.sh` script to test module compilation locally (against full nginx):

```bash
# Test with default nginx version (1.29.8)
bash tools/ci-build.sh

# Test with specific nginx version
bash tools/ci-build.sh 1.27.0
bash tools/ci-build.sh 1.28.0
```

**Output:**
```
==========================================================================
  zstd-nginx-module CI Build
==========================================================================

Module: /opt/packages/modules/zstd-nginx-module
Nginx version: 1.29.8
Build directory: /tmp/nginx-build-12345

==========================================================================
Phase 1: Downloading nginx 1.29.8
==========================================================================

✓ Downloaded nginx-1.29.8.tar.gz

==========================================================================
Phase 2: Configuring nginx with zstd module
==========================================================================

✓ Configuration complete

==========================================================================
Phase 3: Compiling nginx
==========================================================================

[Compilation output]

==========================================================================
Phase 4: Verifying compiled modules
==========================================================================

✓ Filter module compiled: objs/ngx_http_zstd_filter_module.so
-rwxr-xr-x 1 root root 145K May  9 23:25 objs/ngx_http_zstd_filter_module.so

✓ Static module compiled: objs/ngx_http_zstd_static_module.so
-rwxr-xr-x 1 root root 89K May  9 23:25 objs/ngx_http_zstd_static_module.so

==========================================================================
✓ Build successful!
==========================================================================
```

---

## Pull Request Workflow

When you create a PR:

1. **GitHub Actions automatically runs all 4 jobs:**
   - ✅ Syntax Check
   - ✅ Test Suite
   - ✅ Tools Validation
   - ✅ Code Linting & Analysis

2. **Status checks appear on PR:**
   - ✅ Syntax Check / ubuntu-latest
   - ✅ Test Suite / ubuntu-latest
   - ✅ Tools Validation / ubuntu-latest
   - ✅ Code Linting & Analysis / ubuntu-latest

3. **All checks must pass before merging**

---

## Why This Approach?

### No Full Nginx Compilation in CI

**Advantages:**
- ✓ Fast feedback (3 min vs 10+ min with full nginx build)
- ✓ Validates module syntax is correct
- ✓ Tests run quickly and reliably
- ✓ Tools are validated independently
- ✓ Catches most issues (syntax, logic, tests)

**For Full Nginx Testing:**
- Use `tools/ci-build.sh` before merging
- Test on staging servers
- Validate with production traffic

### Available Nginx Versions

The `tools/ci-build.sh` script supports testing against:
```
✓ nginx-1.27.0
✓ nginx-1.28.0
✓ nginx-1.29.0
✓ nginx-1.29.8  (latest)
```

---

## CI Configuration Details

### Dependencies Installed

**Syntax Check:**
- `build-essential` - GCC compiler
- `libzstd-dev` - zstd library headers
- `nginx-dev` - nginx headers

**Test Suite:**
- `perl` - Perl interpreter
- `libtest-nginx-perl` - Test framework
- `libzstd-dev` - zstd library
- `zstd` - CLI decompressor for the truncation smoke test
- `python3`, `python3-requests` - Python test tools

**Tools Validation:**
- `python3` - Python interpreter
- `python3-requests` - Python HTTP library
- `shellcheck` - Shell script linter

### Compilation Flags

```bash
# Module syntax check (no linking)
gcc -c -Wall -Wextra -Werror \
  -I/usr/include/nginx \
  -I/usr/include \
  filter/ngx_http_zstd_filter_module.c
```

---

## Troubleshooting CI Failures

### Syntax Check fails: "ngx_isdigit not found"
**Solution:** Ensure `ngx_ctype.h` is included
```c
#include <ngx_ctype.h>
```

### Test Suite fails
**Solution:** Check test output for specific failures
```bash
cd t
perl 00-filter.t
perl 01-static.t
python3 ../tools/test_encoding.py --nginx-binary /path/to/nginx
```

### Tools Validation fails
**Solution:** Check shellcheck output
```bash
shellcheck tools/*.sh
```

---

## Extending the CI

### Add more test coverage:
Edit `.github/workflows/build.yml` and add a new job

### Change test framework:
Update `test` job in `.github/workflows/build.yml`

### Modify syntax check:
Update `syntax` job parameters

---

## Pre-Commit Hook

A Git pre-commit hook is configured to automatically run the CI build script before each commit.

### How it Works

When you attempt to commit changes:
1. The `.git/hooks/pre-commit` hook is triggered
2. Runs `tools/ci-build.sh` to compile against nginx
3. If compilation **passes**: commit is allowed ✅
4. If compilation **fails**: commit is blocked ❌

### Usage

The hook runs automatically - no additional setup needed. Just commit normally:

```bash
git add filter/ngx_http_zstd_filter_module.c
git commit -m "fix: my changes"

# Hook runs automatically before commit
# ✅ CI build passed - commit allowed
# [master 1a2b3c4] fix: my changes
```

### Bypassing the Hook (Not Recommended)

If you need to skip the hook for testing purposes:

```bash
git commit --no-verify -m "test: skipping CI build"
```

**Warning:** Commits should always pass CI before pushing.

### Hook Output

```
Running CI build before commit...

==========================================================================
  zstd-nginx-module CI Build
==========================================================================

Module: /opt/packages/modules/zstd-nginx-module
Nginx version: 1.29.8
Build directory: /tmp/nginx-build-XXXXX

[... build output ...]

✅ CI build passed - commit allowed
[master a1b2c3d] chore: my changes
 1 file changed, X insertion(s)+
```

---

## Status Badges

To add CI status to README.md:

```markdown
[![CI Status](https://github.com/YOUR_USERNAME/zstd-nginx-module/actions/workflows/build.yml/badge.svg)](https://github.com/YOUR_USERNAME/zstd-nginx-module/actions/workflows/build.yml)
```

---

## See Also

- `.github/workflows/build.yml` - Workflow definition
- `tools/ci-build.sh` - Local build script
- `tools/validate_zstd_module.sh` - Module validator
- `tools/test_encoding.py` - Encoding tester
- [GitHub Actions documentation](https://docs.github.com/en/actions)
