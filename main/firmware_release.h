#pragma once
#include <stdbool.h>
#include <stddef.h>
bool firmware_release_valid(const char *chip, const char *version,
                            const char *build, const char *sha256,
                            const char *url, double bytes, size_t partition_size);
