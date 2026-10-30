#include "dns_cache.h"
#include "config.h"
#include <stdlib.h>
#include <string.h>
#define CACHE_PACKET 512
#define TTL_MAX 16
typedef struct {
  char name[254];
  uint16_t type, flags, len, ttl_offset[TTL_MAX];
  unsigned ttls;
  uint32_t minimum, generation;
  uint64_t inserted;
  uint8_t packet[CACHE_PACKET];
} cache_entry_t;
struct dns_cache {
  cache_entry_t entries[GUARD_CACHE_MAX];
  unsigned next;
};
static uint32_t get32(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
         p[3];
}
static void put32(uint8_t *p, uint32_t x) {
  p[0] = x >> 24;
  p[1] = x >> 16;
  p[2] = x >> 8;
  p[3] = x;
}
dns_cache_t *dns_cache_create(void) { return calloc(1, sizeof(dns_cache_t)); }
void dns_cache_destroy(dns_cache_t *c) { free(c); }
bool dns_cache_get(dns_cache_t *c, const dns_question_t *q, uint16_t id,
                   uint64_t now, uint32_t gen, uint8_t *out, size_t cap,
                   size_t *n) {
  if (!c || q->qclass != 1 || q->cache_unsafe)
    return false;
  for (unsigned i = 0; i < GUARD_CACHE_MAX; i++) {
    cache_entry_t *e = &c->entries[i];
    uint64_t age = (now - e->inserted) / 1000;
    if (!e->len || e->generation != gen || e->type != q->qtype ||
        e->flags != (q->flags & 0x0110) || strcmp(e->name, q->name) ||
        age >= e->minimum || e->len > cap)
      continue;
    memcpy(out, e->packet, e->len);
    dns_put16(out, id);
    for (unsigned j = 0; j < e->ttls; j++) {
      unsigned off = e->ttl_offset[j];
      put32(out + off, get32(e->packet + off) - (uint32_t)age);
    }
    *n = e->len;
    return true;
  }
  return false;
}
void dns_cache_put(dns_cache_t *c, const dns_question_t *q, const uint8_t *p,
                   size_t n, uint64_t now, uint32_t gen) {
  if (!c || q->cache_unsafe || n > CACHE_PACKET || n < 12 ||
      (q->qtype != 1 && q->qtype != 28) || q->qclass != 1 ||
      (q->flags & 0x10) || (dns_u16(p + 2) & 0x022f) || dns_u16(p + 8) ||
      dns_u16(p + 10) || !dns_u16(p + 6) || dns_u16(p + 6) > TTL_MAX)
    return;
  cache_entry_t candidate = {0};
  size_t pos = 12;
  char name[254];
  if (!dns_name_read(p, n, &pos, name) || pos + 4 > n)
    return;
  pos += 4;
  uint32_t minimum = UINT32_MAX;
  for (unsigned i = 0; i < dns_u16(p + 6); i++) {
    if (!dns_name_read(p, n, &pos, name) || pos + 10 > n)
      return;
    uint16_t type = dns_u16(p + pos), klass = dns_u16(p + pos + 2),
             len = dns_u16(p + pos + 8);
    if (type != q->qtype || klass != 1 || len != (type == 1 ? 4 : 16) ||
        pos + 10 + len > n)
      return;
    uint32_t ttl = get32(p + pos + 4);
    if (!ttl)
      return;
    if (ttl < minimum)
      minimum = ttl;
    candidate.ttl_offset[candidate.ttls++] = pos + 4;
    pos += 10 + len;
  }
  if (pos != n)
    return;
  candidate.minimum = minimum;
  candidate.inserted = now;
  candidate.generation = gen;
  candidate.type = q->qtype;
  candidate.flags = q->flags & 0x0110;
  candidate.len = n;
  strcpy(candidate.name, q->name);
  memcpy(candidate.packet, p, n);
  c->entries[c->next++ % GUARD_CACHE_MAX] = candidate;
}
