#include "update_policy.h"
#include <string.h>
bool updater_url_allowed(const char *url) {
  const char prefix[] = "https://luuhung93.github.io/esp32-c6-guard-filters/";
  return url && !strncmp(url, prefix, sizeof(prefix) - 1) &&
         strlen(url) < 384 && !strpbrk(url, "?#@%\\") && !strstr(url, "/../") &&
         !strstr(url, "/./");
}
bool updater_check_due(int64_t now, int64_t checked, int64_t attempted) {
  return now >= 1700000000 && now >= checked && now >= attempted &&
         now - checked >= 30 * 86400 && now - attempted >= 3600;
}
