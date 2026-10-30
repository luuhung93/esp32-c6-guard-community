#include "domain.h"
#include <string.h>
domain_result_t guard_domain_normalize(const char *src, size_t len,
                                       char out[254]) {
  if (!src || !out || !len)
    return DOMAIN_INVALID;
  if (src[len - 1] == '.')
    len--;
  if (!len || len > 253)
    return DOMAIN_INVALID;
  size_t label = 0;
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)src[i];
    if (c >= 'A' && c <= 'Z')
      c += 'a' - 'A';
    if (c == '.') {
      if (!label || out[i - 1] == '-')
        return DOMAIN_INVALID;
      label = 0;
    } else {
      if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
        return DOMAIN_INVALID;
      if ((!label && c == '-') || ++label > 63)
        return DOMAIN_INVALID;
    }
    out[i] = (char)c;
  }
  if (!label || out[len - 1] == '-')
    return DOMAIN_INVALID;
  out[len] = 0;
  return DOMAIN_OK;
}
bool guard_domain_is_suffix(const char *name, const char *suffix) {
  size_t n = strlen(name), s = strlen(suffix);
  return n >= s && !strcmp(name + n - s, suffix) &&
         (n == s || name[n - s - 1] == '.');
}
