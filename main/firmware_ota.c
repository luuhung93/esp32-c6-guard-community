#include "firmware_ota.h"
#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "status_led.h"
#include "updater.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
static _Atomic bool reboot_pending;
bool firmware_ota_reboot_pending(void) { return atomic_load(&reboot_pending); }
static void reboot(void *unused) {
  (void)unused;
  esp_restart();
}
esp_err_t firmware_ota_activate(const esp_partition_t *part) {
  esp_timer_handle_t timer;
  esp_timer_create_args_t args = {.callback = reboot, .name = "ota-reboot"};
  esp_err_t e = esp_timer_create(&args, &timer);
  if (e != ESP_OK) return e;
  e = esp_ota_set_boot_partition(part);
  if (e == ESP_OK) {
    atomic_store(&reboot_pending, true);
    e = esp_timer_start_once(timer, 2000000);
    if (e != ESP_OK) {
      esp_err_t restored = esp_ota_set_boot_partition(esp_ota_get_running_partition());
      if (restored != ESP_OK)
        ESP_LOGE("ota", "Boot selection restore failed: %s", esp_err_to_name(restored));
      else atomic_store(&reboot_pending, false);
    }
  }
  if (e != ESP_OK) esp_timer_delete(timer);
  return e;
}
esp_err_t firmware_ota_upload(httpd_req_t *r) {
#ifndef CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT
  httpd_resp_send_err(r, HTTPD_403_FORBIDDEN,
                      "Signed OTA verification is required");
  return ESP_OK;
#else
  if (!updater_flash_lock()) {
    httpd_resp_set_status(r, "409 Conflict");
    return httpd_resp_sendstr(r, "Flash job busy");
  }
  const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
  esp_ota_handle_t handle = 0;
  esp_err_t e = ESP_FAIL;
  if (!part || r->content_len <= 0 || (size_t)r->content_len > part->size) {
    updater_flash_unlock();
    return httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST,
                               "Invalid image length");
  }
  status_led_set(LED_UPDATE_FAILED, false);
  status_led_set(LED_UPDATING, true);
  e = esp_ota_begin(part, r->content_len, &handle);
  uint8_t *buf = malloc(2048);
  if (!buf)
    e = ESP_ERR_NO_MEM;
  size_t remaining = r->content_len;
  while (e == ESP_OK && remaining) {
    int n = httpd_req_recv(r, (char *)buf, remaining > 2048 ? 2048 : remaining);
    if (n <= 0) {
      e = ESP_FAIL;
      break;
    }
    e = esp_ota_write(handle, buf, n);
    remaining -= n;
  }
  free(buf);
  if (e == ESP_OK) {
    e = esp_ota_end(handle);
    handle = 0;
  }
  if (handle)
    esp_ota_abort(handle);
  if (e == ESP_OK)
    e = firmware_ota_activate(part);
  status_led_set(LED_UPDATE_FAILED, e != ESP_OK);
  if (e != ESP_OK)
    status_led_set(LED_UPDATING, false);
  updater_flash_unlock();
  if (e != ESP_OK)
    return httpd_resp_send_err(
        r, HTTPD_400_BAD_REQUEST,
        "Image verification/write failed; active firmware retained");
  httpd_resp_set_status(r, "202 Accepted");
  httpd_resp_set_type(r, "application/json");
  esp_app_desc_t description;
  char build[65] = "";
  if (esp_ota_get_partition_description(part, &description) == ESP_OK)
    for (unsigned i = 0; i < 32; i++)
      snprintf(build + 2 * i, 3, "%02x", description.app_elf_sha256[i]);
  cJSON *response = cJSON_CreateObject();
  cJSON_AddStringToObject(response, "state", "rebooting");
  cJSON_AddStringToObject(response, "expectedBuild", build);
  char *encoded = cJSON_PrintUnformatted(response);
  cJSON_Delete(response);
  httpd_resp_sendstr(r, encoded ? encoded : "{}");
  free(encoded);
  return ESP_OK;
#endif
}
void firmware_ota_confirm(bool healthy) {
  esp_ota_img_states_t state;
  const esp_partition_t *p = esp_ota_get_running_partition();
  if (esp_ota_get_state_partition(p, &state) != ESP_OK ||
      state != ESP_OTA_IMG_PENDING_VERIFY)
    return;
  if (healthy) {
    esp_err_t e = esp_ota_mark_app_valid_cancel_rollback();
    ESP_LOGI("ota", "Health confirmation: %s", esp_err_to_name(e));
  } else {
    ESP_LOGE("ota", "Health failed, rolling back");
    esp_ota_mark_app_invalid_rollback_and_reboot();
  }
}

void firmware_ota_build(char out[65]) {
  const esp_app_desc_t *d = esp_app_get_description();
  for (unsigned i = 0; i < 32; i++)
    snprintf(out + 2 * i, 3, "%02x", d->app_elf_sha256[i]);
}

const char *firmware_ota_state(void) {
  esp_ota_img_states_t state;
  if (esp_ota_get_state_partition(esp_ota_get_running_partition(), &state) !=
      ESP_OK)
    return "undefined";
  switch (state) {
  case ESP_OTA_IMG_VALID:
    return "valid";
  case ESP_OTA_IMG_PENDING_VERIFY:
    return "pending";
  case ESP_OTA_IMG_NEW:
    return "new";
  case ESP_OTA_IMG_INVALID:
    return "invalid";
  case ESP_OTA_IMG_ABORTED:
    return "aborted";
  default:
    return "unknown";
  }
}
