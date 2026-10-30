#pragma once
#include <stdbool.h>
#include <stddef.h>
typedef enum { DOMAIN_OK, DOMAIN_INVALID } domain_result_t;
domain_result_t guard_domain_normalize(const char *src, size_t len,
                                       char out[254]);
bool guard_domain_is_suffix(const char *name, const char *suffix);
