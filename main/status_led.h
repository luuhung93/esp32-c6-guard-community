#pragma once
#include <stdbool.h>
#include <stdint.h>
typedef struct {
  uint8_t r, g, b;
} status_led_rgb_t;
enum {
  LED_CONNECTED = 1u << 0,
  LED_EVER_CONNECTED = 1u << 1,
  LED_READY = 1u << 2,
  LED_SETUP = 1u << 3,
  LED_UPDATING = 1u << 4,
  LED_FAULT = 1u << 5,
  LED_UPDATE_FAILED = 1u << 6
};
status_led_rgb_t status_led_color(unsigned flags, uint64_t uptime_ms);
#ifdef ESP_PLATFORM
#include "esp_err.h"
esp_err_t status_led_start(void);
void status_led_set(unsigned flags, bool enabled);
#endif
