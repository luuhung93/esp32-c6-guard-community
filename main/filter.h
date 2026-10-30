#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
typedef struct {
  char id[64];
  uint32_t count;
  uint8_t width;
  uint8_t digest[32];
  uint32_t buckets[257];
} filter_meta_t;
bool filter_validate(FILE *, const char *expected_id, filter_meta_t *);
typedef enum { FILTER_READ_ERROR = -1, FILTER_MISS, FILTER_HIT } filter_result_t;
filter_result_t filter_lookup(FILE *, const filter_meta_t *, uint64_t hash);
