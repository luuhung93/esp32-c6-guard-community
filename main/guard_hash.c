#include "guard_hash.h"
#ifdef ESP_PLATFORM
#include "mbedtls/sha256.h"
void guard_sha256(const void *p, size_t n, uint8_t out[32]) {
  mbedtls_sha256(p, n, out, 0);
}
#else
#include <CommonCrypto/CommonDigest.h>
void guard_sha256(const void *p, size_t n, uint8_t out[32]) {
  CC_SHA256(p, (CC_LONG)n, out);
}
#endif
uint64_t guard_domain_hash(const char *p, size_t n) {
  uint8_t digest[32];
  guard_sha256(p, n, digest);
  uint64_t v = 0;
  for (unsigned i = 0; i < 8; i++)
    v |= (uint64_t)digest[i] << (8 * i);
  return v;
}
