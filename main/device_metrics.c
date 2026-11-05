#include "device_metrics.h"
#include "driver/temperature_sensor.h"
#include "esp_clk_tree.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include <math.h>

static temperature_sensor_handle_t sensor;
static bool attempted;
void device_metrics_start(void) {
  if (attempted)
    return;
  attempted = true;
  temperature_sensor_config_t config = TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10, 80);
  esp_err_t e = temperature_sensor_install(&config, &sensor);
  if (e != ESP_OK) {
    sensor = NULL;
    ESP_LOGW("metrics", "Temperature sensor unavailable: %s", esp_err_to_name(e));
    return;
  }
  e = temperature_sensor_enable(sensor);
  if (e != ESP_OK) {
    ESP_LOGW("metrics", "Temperature sensor enable failed: %s", esp_err_to_name(e));
    esp_err_t cleanup = temperature_sensor_uninstall(sensor);
    if (cleanup != ESP_OK)
      ESP_LOGW("metrics", "Temperature sensor cleanup failed: %s",
               esp_err_to_name(cleanup));
    sensor = NULL;
  }
}
device_metrics_t device_metrics_read(void) {
  device_metrics_t out = {.heap_total = heap_caps_get_total_size(MALLOC_CAP_DEFAULT)};
  uint32_t hz;
  if (esp_clk_tree_src_get_freq_hz(SOC_MOD_CLK_CPU,
          ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED, &hz) == ESP_OK)
    out.cpu_mhz = hz / 1000000;
  if (sensor && temperature_sensor_get_celsius(sensor, &out.temperature_c) == ESP_OK)
    out.temperature_valid = isfinite(out.temperature_c);
  return out;
}
