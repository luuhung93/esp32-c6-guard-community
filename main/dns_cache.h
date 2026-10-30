#pragma once
#include "dns_packet.h"
typedef struct dns_cache dns_cache_t;
dns_cache_t *dns_cache_create(void);
void dns_cache_destroy(dns_cache_t *);
bool dns_cache_get(dns_cache_t *, const dns_question_t *, uint16_t id,
                   uint64_t now, uint32_t generation, uint8_t *, size_t,
                   size_t *);
void dns_cache_put(dns_cache_t *, const dns_question_t *, const uint8_t *,
                   size_t, uint64_t now, uint32_t generation);
