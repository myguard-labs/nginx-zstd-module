/*
 * FAKE OpenSSL EVP header for the unit fixture: declarations only, no
 * OpenSSL required. tools/test_sha256_unit.c supplies implementations
 * whose failure modes are scripted (partial digest write + failure
 * return, wrong output length, scripted success), so the EVP-to-
 * portable fallback in ngx_http_zstd_sha256.h can be exercised
 * deterministically. This directory is passed with -I ahead of the
 * system paths, so this header shadows the real <openssl/evp.h> for
 * the fixture build only.
 */

#ifndef NGX_SHIM_FAKE_EVP_H
#define NGX_SHIM_FAKE_EVP_H

#include <stddef.h>

typedef struct fake_evp_md_st  EVP_MD;

const EVP_MD *EVP_sha256(void);
int EVP_Digest(const void *data, size_t count, unsigned char *md,
    unsigned int *size, const EVP_MD *type, void *impl);

#endif /* NGX_SHIM_FAKE_EVP_H */
