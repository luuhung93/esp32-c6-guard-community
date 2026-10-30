#include "filter.h"
#include "config.h"
#include <string.h>
#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"
#else
#include <CommonCrypto/CommonDigest.h>
#endif
static uint32_t le32(const uint8_t *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
         (uint32_t)p[3] << 24;
}
static uint64_t number(const uint8_t *p, unsigned w) {
  uint64_t x = 0;
  for (unsigned i = 0; i < w; i++)
    x |= (uint64_t)p[i] << (i * 8);
  return x;
}
bool filter_validate(FILE *f, const char *id, filter_meta_t *m) {
  uint8_t h[144], page[1024], digest[32];
  if (fseek(f, 0, SEEK_SET) || fread(h, 1, sizeof(h), f) != sizeof(h) ||
      memcmp(h, "C6GF", 4) || h[4] != 1 || h[5] != 1 ||
      (h[6] != 8 && h[6] != 5) || h[7])
    return false;
  if (!memchr(h + 8, 0, 64) || !h[8])
    return false;
  for (unsigned i = 8; i < 72; i++) {
    if (!h[i]) {
      for (unsigned j = i; j < 72; j++)
        if (h[j])
          return false;
      break;
    }
    if (!((h[i] >= 'a' && h[i] <= 'z') || (h[i] >= 'A' && h[i] <= 'Z') ||
          (h[i] >= '0' && h[i] <= '9') || h[i] == '-' || h[i] == '_'))
      return false;
  }
  if (id && strcmp(id, (char *)h + 8))
    return false;
  uint32_t count = le32(h + 72), bytes = le32(h + 76);
  if (!count || count > 500000 || bytes != count * h[6])
    return false;
  if (fseek(f, 0, SEEK_END) || ftell(f) != (long)(144 + bytes) ||
      fseek(f, 144, SEEK_SET))
    return false;
#ifdef ESP_PLATFORM
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
#else
  CC_SHA256_CTX ctx;
  CC_SHA256_Init(&ctx);
#endif
  uint64_t prev = 0;
  uint32_t done = 0;
  unsigned bucket = 0;
  memset(m, 0, sizeof(*m));
  while (done < count) {
    unsigned n = count - done;
    if (n > 128)
      n = 128;
    size_t len = n * h[6];
    if (fread(page, 1, len, f) != len)
      return false;
#ifdef ESP_PLATFORM
    mbedtls_sha256_update(&ctx, page, len);
#else
    CC_SHA256_Update(&ctx, page, (CC_LONG)len);
#endif
    for (unsigned i = 0; i < n; i++) {
      uint64_t v = number(page + i * h[6], h[6]);
      if ((done || i) && v <= prev)
        return false;
      while (bucket <= (unsigned)(v >> (h[6] * 8 - 8)))
        m->buckets[bucket++] = done + i;
      prev = v;
    }
    done += n;
#ifdef ESP_PLATFORM
    if (done % 4096 == 0)
      vTaskDelay(1);
#endif
  }
  while (bucket <= 256)
    m->buckets[bucket++] = count;
#ifdef ESP_PLATFORM
  mbedtls_sha256_finish(&ctx, digest);
  mbedtls_sha256_free(&ctx);
#else
  CC_SHA256_Final(digest, &ctx);
#endif
  if (memcmp(digest, h + 112, 32))
    return false;
  strcpy(m->id, (char *)h + 8);
  m->width = h[6];
  m->count = count;
  memcpy(m->digest, digest, 32);
  return true;
}
filter_result_t filter_lookup(FILE *f, const filter_meta_t *m, uint64_t hash) {
  if (m->width == 5)
    hash &= UINT64_C(0xffffffffff);
  unsigned bucket = hash >> (m->width * 8 - 8);
  uint32_t lo = m->buckets[bucket], hi = m->buckets[bucket + 1];
  uint8_t b[512];
  while (hi - lo > 64) {
    uint32_t mid = lo + (hi - lo) / 2;
    if (fseek(f, 144 + (long)mid * m->width, SEEK_SET) ||
        fread(b, 1, m->width, f) != m->width)
      return FILTER_READ_ERROR;
    uint64_t v = number(b, m->width);
    if (v == hash)
      return FILTER_HIT;
    if (v < hash)
      lo = mid + 1;
    else
      hi = mid;
  }
  uint32_t count = hi - lo;
  if (count && (fseek(f, 144 + (long)lo * m->width, SEEK_SET) ||
                fread(b, m->width, count, f) != count))
    return FILTER_READ_ERROR;
  lo = 0;
  hi = count;
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    uint64_t v = number(b + mid * m->width, m->width);
    if (v == hash)
      return FILTER_HIT;
    if (v < hash)
      lo = mid + 1;
    else
      hi = mid;
  }
  return FILTER_MISS;
}
