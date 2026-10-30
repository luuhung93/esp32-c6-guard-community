#include "config.h"
#include "dns.h"
#include "esp_log.h"
#include "esp_system.h"
#include "filter_store.h"
#include "firmware_ota.h"
#include "guard_hash.h"
#include "my_rules.h"
#include "network.h"
#include "nvs_flash.h"
#include "settings.h"
#include "status_led.h"
#include "updater.h"
#include "web.h"
#include "web_auth.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
extern const unsigned char starter_start[] asm("_binary_starter_bin_start"),
    starter_end[] asm("_binary_starter_bin_end");
static void install_starter(void) {
  if (!filter_store_factory_needed())
    return;
  char digest[65];
  if (filter_store_digest("guard-starter", digest))
    return;
  unsigned char hash[32];
  guard_sha256(starter_start, starter_end - starter_start, hash);
  for (unsigned i = 0; i < 32; i++)
    snprintf(digest + 2 * i, 3, "%02x", hash[i]);
  FILE *f = fopen(GUARD_STORE "/starter.tmp", "wb");
  if (!f)
    return;
  bool ok = fwrite(starter_start, 1, starter_end - starter_start, f) ==
            (size_t)(starter_end - starter_start);
  if (fflush(f) || fsync(fileno(f)))
    ok = false;
  if (fclose(f))
    ok = false;
  if (ok)
    filter_store_install("guard-starter", GUARD_STORE "/starter.tmp", digest);
}
void app_main(void) {
  esp_err_t led = status_led_start();
  if (led != ESP_OK)
    ESP_LOGW("guard", "Status LED unavailable: %s", esp_err_to_name(led));
  esp_err_t e = nvs_flash_init();
  if (e != ESP_OK) {
    ESP_LOGE("guard", "NVS unavailable: %s; data preserved",
             esp_err_to_name(e));
    status_led_set(LED_FAULT, true);
    firmware_ota_confirm(false);
    return;
  }
  guard_settings_t settings;
  e = guard_settings_load(&settings);
  if (e != ESP_OK) {
    ESP_LOGE("guard", "Invalid settings; recovery defaults in RAM");
    guard_settings_defaults(&settings);
  }
  if (my_rules_init() != ESP_OK || web_auth_init() != ESP_OK) {
    ESP_LOGE("guard", "Persistent state invalid; refusing unsafe boot");
    status_led_set(LED_FAULT, true);
    firmware_ota_confirm(false);
    return;
  }
  ESP_LOGI("memory", "rules/auth heap=%lu",
           (unsigned long)esp_get_free_heap_size());
  e = filter_store_mount();
  if (e != ESP_OK)
    ESP_LOGE("guard", "Filter store recovery required: %s", esp_err_to_name(e));
  ESP_LOGI("memory", "filter mount heap=%lu",
           (unsigned long)esp_get_free_heap_size());
  bool healthy = e == ESP_OK;
  healthy = network_start(&settings) == ESP_OK && healthy;
  ESP_LOGI("memory", "network heap=%lu",
           (unsigned long)esp_get_free_heap_size());
  healthy = updater_start() == ESP_OK && healthy;
  ESP_LOGI("memory", "updater heap=%lu",
           (unsigned long)esp_get_free_heap_size());
  healthy = dns_start(&settings) == ESP_OK && healthy;
  ESP_LOGI("memory", "DNS heap=%lu", (unsigned long)esp_get_free_heap_size());
  if (filter_store_ready())
    install_starter();
  healthy = web_start() == ESP_OK && healthy;
  ESP_LOGI("guard", "Guard %s heap=%lu min=%lu", GUARD_VERSION,
           (unsigned long)esp_get_free_heap_size(),
           (unsigned long)esp_get_minimum_free_heap_size());
  status_led_set(LED_READY, healthy && filter_store_ready());
  status_led_set(LED_FAULT, !healthy || !filter_store_ready());
  firmware_ota_confirm(healthy && filter_store_ready());
  if (healthy && !strcmp(firmware_ota_state(), "valid") && updater_flash_lock()) {
    e = filter_store_prune_disabled();
    updater_flash_unlock();
    if (e != ESP_OK)
      ESP_LOGW("filters", "Legacy off-list cleanup deferred: %s", esp_err_to_name(e));
  }
}
