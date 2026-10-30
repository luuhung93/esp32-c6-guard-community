#include "settings.h"
#include <stdio.h>
#include <string.h>
static bool ipv4(const char *s, uint32_t *out) {
  unsigned a, b, c, d;
  char tail;
  if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4 || a > 255 ||
      b > 255 || c > 255 || d > 255)
    return false;
  char canonical[16];
  snprintf(canonical, sizeof(canonical), "%u.%u.%u.%u", a, b, c, d);
  if (strcmp(s, canonical))
    return false;
  *out = (a << 24) | (b << 16) | (c << 8) | d;
  return true;
}
static bool unicast(uint32_t x) {
  unsigned a = x >> 24, b = (x >> 16) & 255;
  return a > 0 && a < 224 && a != 127 && !(a == 169 && b == 254);
}
bool guard_public_ipv4(const char *s) {
  uint32_t x;
  if (!ipv4(s, &x))
    return false;
  unsigned a = x >> 24, b = (x >> 16) & 255;
  return a && a != 10 && a != 127 && a < 224 &&
         !(a == 100 && b >= 64 && b <= 127) && !(a == 169 && b == 254) &&
         !(a == 172 && b >= 16 && b <= 31) &&
         !(a == 192 && (b == 168 || b == 0 || b == 2)) &&
         !(a == 198 && (b == 18 || b == 19 || b == 51)) &&
         !(a == 203 && b == 0);
}
void guard_settings_defaults(guard_settings_t *s) {
  memset(s, 0, sizeof(*s));
  s->version = 1;
  s->dhcp = true;
  s->history = true;
  strcpy(s->upstream, "1.1.1.1");
}
bool guard_settings_validate(const guard_settings_t *s, bool initial) {
  /* NVS blobs can contain invalid _Bool bytes; inspect storage before loading. */
  if (*(const unsigned char *)&s->dhcp > 1 ||
      *(const unsigned char *)&s->history > 1)
    return false;
  if (s->version != 1 || !memchr(s->ssid, 0, sizeof(s->ssid)) ||
      !memchr(s->password, 0, sizeof(s->password)) ||
      !memchr(s->upstream, 0, 16) || !memchr(s->ip, 0, 16) ||
      !memchr(s->gateway, 0, 16) || !memchr(s->netmask, 0, 16) ||
      !memchr(s->recovery, 0, 64))
    return false;
  if (!guard_public_ipv4(s->upstream) || (!initial && !s->ssid[0]))
    return false;
  size_t p = strlen(s->password);
  if (p && (p < 8 || p > 63))
    return false;
  if (s->dhcp)
    return true;
  uint32_t ip, mask, gw, upstream;
  if (!ipv4(s->ip, &ip) || !ipv4(s->gateway, &gw) || !ipv4(s->netmask, &mask) ||
      !ipv4(s->upstream, &upstream))
    return false;
  if ((upstream & mask) == (ip & mask) || !unicast(ip) || !unicast(gw))
    return false;
  uint32_t inv = ~mask;
  return mask && inv >= 3 && (inv & (inv + 1)) == 0 && (ip & inv) != 0 &&
         (ip & inv) != inv && (gw & mask) == (ip & mask) && (gw & inv) != 0 &&
         (gw & inv) != inv && ip != gw;
}
#ifdef ESP_PLATFORM
#include "nvs.h"
esp_err_t guard_settings_load(guard_settings_t *s) {
  guard_settings_defaults(s);
  nvs_handle_t h;
  esp_err_t e = nvs_open("guard", NVS_READONLY, &h);
  if (e == ESP_ERR_NVS_NOT_FOUND)
    return ESP_OK;
  if (e != ESP_OK)
    return e;
  size_t n = sizeof(*s);
  e = nvs_get_blob(h, "settings", s, &n);
  nvs_close(h);
  if (e == ESP_ERR_NVS_NOT_FOUND) {
    guard_settings_defaults(s);
    return ESP_OK;
  }
  return e == ESP_OK && n == sizeof(*s) && guard_settings_validate(s, true)
             ? ESP_OK
             : ESP_ERR_INVALID_STATE;
}
esp_err_t guard_settings_save(const guard_settings_t *s) {
  if (!guard_settings_validate(s, false))
    return ESP_ERR_INVALID_ARG;
  nvs_handle_t h;
  esp_err_t e = nvs_open("guard", NVS_READWRITE, &h);
  if (e != ESP_OK)
    return e;
  e = nvs_set_blob(h, "settings", s, sizeof(*s));
  if (e == ESP_OK)
    e = nvs_commit(h);
  nvs_close(h);
  return e;
}
#endif
