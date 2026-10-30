#pragma once
#include <stdbool.h>
#include <stdint.h>
typedef struct {
  uint32_t version;
  bool dhcp, history;
  char ssid[33], password[65], ip[16], gateway[16], netmask[16], upstream[16],
      recovery[64];
} guard_settings_t;
void guard_settings_defaults(guard_settings_t *);
bool guard_settings_validate(const guard_settings_t *, bool allow_unconfigured);
bool guard_public_ipv4(const char *);
#ifdef ESP_PLATFORM
#include "esp_err.h"
esp_err_t guard_settings_load(guard_settings_t *);
esp_err_t guard_settings_save(const guard_settings_t *);
#endif
