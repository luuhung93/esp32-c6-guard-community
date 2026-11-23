#include "firmware_release.h"
#include "update_policy.h"
#include <math.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
static bool digest(const char *s) {
  if (!s || strlen(s) != 64)
    return false;
  for (unsigned i = 0; i < 64; i++)
    if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
      return false;
  return true;
}
bool firmware_release_valid(const char *chip, const char *version,
                            const char *build, const char *sha256,
                            const char *url, double bytes, size_t partition_size) {
  const char prefix[] = "https://luuhung93.github.io/esp32-c6-guard-filters/firmware/";
  return chip && !strcmp(chip, "esp32c6") && version && version[0] &&
         strlen(version) < 32 && digest(build) && digest(sha256) &&
         updater_url_allowed(url) && !strncmp(url, prefix, sizeof(prefix) - 1) &&
         isfinite(bytes) && bytes >= 65536 && bytes <= partition_size &&
         bytes == (size_t)bytes;
}

static bool version_parts(const char *s, unsigned parts[3]) {
  if (!s) return false;
  for (unsigned i = 0; i < 3; i++) {
    if (*s < '0' || *s > '9') return false;
    char *end;
    errno = 0;
    unsigned long value = strtoul(s, &end, 10);
    if (errno || value > UINT_MAX || *end != (i == 2 ? '\0' : '.'))
      return false;
    parts[i] = (unsigned)value;
    s = end + (i < 2);
  }
  return true;
}
bool firmware_release_newer(const char *candidate, const char *current) {
  unsigned next[3], running[3];
  if (!version_parts(candidate, next) || !version_parts(current, running))
    return false;
  for (unsigned i = 0; i < 3; i++)
    if (next[i] != running[i]) return next[i] > running[i];
  return false;
}
