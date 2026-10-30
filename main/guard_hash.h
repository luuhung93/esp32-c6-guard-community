#pragma once
#include <stddef.h>
#include <stdint.h>
void guard_sha256(const void *, size_t, uint8_t out[32]);
uint64_t guard_domain_hash(const char *, size_t);
