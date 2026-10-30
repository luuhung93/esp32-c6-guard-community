#include "status_led.h"
status_led_rgb_t status_led_color(unsigned flags, uint64_t uptime_ms) {
  if (flags & (LED_FAULT | LED_UPDATE_FAILED))
    return (status_led_rgb_t){8, 0, 0};
  if (flags & LED_UPDATING)
    return (status_led_rgb_t){8, 0, 8};
  if (flags & LED_SETUP)
    return (status_led_rgb_t){8, 8, 0};
  if ((flags & (LED_CONNECTED | LED_READY)) == (LED_CONNECTED | LED_READY))
    return (status_led_rgb_t){0, 8, 0};
  if (!(flags & LED_CONNECTED) &&
      ((flags & LED_EVER_CONNECTED) || uptime_ms >= 30000))
    return (status_led_rgb_t){8, 0, 0};
  return (status_led_rgb_t){0, 0, (uptime_ms / 500) % 2 ? 0 : 8};
}
#ifdef ESP_PLATFORM
#include "config.h"
#include "driver/gpio.h"
#include "driver/rmt_encoder.h"
#include "driver/rmt_tx.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include <stdatomic.h>
#include <string.h>
static _Atomic unsigned state;
static rmt_channel_handle_t channel;
static rmt_encoder_handle_t encoder;
void status_led_set(unsigned flags, bool enabled) {
  if (enabled) {
    if (flags & LED_CONNECTED)
      flags |= LED_EVER_CONNECTED;
    atomic_fetch_or(&state, flags);
  } else
    atomic_fetch_and(&state, ~flags);
}
static void release(void) {
  if (channel) {
    rmt_disable(channel);
    rmt_del_channel(channel);
    channel = NULL;
  }
  if (encoder) {
    rmt_del_encoder(encoder);
    encoder = NULL;
  }
}
static esp_err_t show(status_led_rgb_t rgb) {
  uint8_t grb[] = {rgb.g, rgb.r, rgb.b};
  rmt_symbol_word_t symbols[25] = {0};
  for (unsigned i = 0; i < 24; i++) {
    bool one = grb[i / 8] & (0x80 >> (i % 8));
    symbols[i] = (rmt_symbol_word_t){.level0 = 1,
                                     .duration0 = one ? 9 : 3,
                                     .level1 = 0,
                                     .duration1 = one ? 3 : 9};
  }
  /* WS2812 GRB: 10 MHz ticks, then at least 300 us low to latch. */
  symbols[24] = (rmt_symbol_word_t){.duration0 = 3000, .duration1 = 1};
  rmt_transmit_config_t cfg = {0};
  esp_err_t e = rmt_transmit(channel, encoder, symbols, sizeof(symbols), &cfg);
  return e == ESP_OK ? rmt_tx_wait_all_done(channel, 100) : e;
}
static void render(void *unused) {
  (void)unused;
  status_led_rgb_t previous = {255, 255, 255};
  for (;;) {
    status_led_rgb_t color =
        status_led_color(atomic_load(&state), esp_timer_get_time() / 1000);
    if (memcmp(&color, &previous, sizeof(color))) {
      esp_err_t e = show(color);
      if (e != ESP_OK) {
        ESP_LOGE("status-led", "Output stopped: %s", esp_err_to_name(e));
        release();
        vTaskDelete(NULL);
        return;
      }
      previous = color;
    }
    vTaskDelay(pdMS_TO_TICKS(100));
  }
}
esp_err_t status_led_start(void) {
  int pin = CONFIG_GUARD_LED_GPIO;
  if (pin < 0) {
    ESP_LOGI("status-led", "Disabled: onboard RGB GPIO not configured");
    return ESP_OK;
  }
  if (!GPIO_IS_VALID_OUTPUT_GPIO(pin) || pin == GUARD_BOOT_GPIO || pin == 12 ||
      pin == 13)
    return ESP_ERR_INVALID_ARG;
  rmt_tx_channel_config_t cfg = {.gpio_num = pin,
                                 .clk_src = RMT_CLK_SRC_DEFAULT,
                                 .resolution_hz = 10000000,
                                 .mem_block_symbols = 48,
                                 .trans_queue_depth = 1};
  esp_err_t e = rmt_new_tx_channel(&cfg, &channel);
  rmt_copy_encoder_config_t copy = {0};
  if (e == ESP_OK)
    e = rmt_new_copy_encoder(&copy, &encoder);
  if (e == ESP_OK)
    e = rmt_enable(channel);
  if (e == ESP_OK &&
      xTaskCreate(render, "status-led", 3072, NULL, 1, NULL) != pdPASS)
    e = ESP_ERR_NO_MEM;
  if (e != ESP_OK)
    release();
  else
    ESP_LOGI("status-led", "Onboard WS2812 enabled on GPIO%d", pin);
  return e;
}
#endif
