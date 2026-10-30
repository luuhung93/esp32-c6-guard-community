#include "firmware_release.h"
#include "update_policy.h"
#include <math.h>
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
