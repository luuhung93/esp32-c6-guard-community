#pragma once
#include <stdbool.h>
#include <stdint.h>
bool updater_url_allowed(const char *);
bool updater_check_due(int64_t now, int64_t checked, int64_t attempted);
