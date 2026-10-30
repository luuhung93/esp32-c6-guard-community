#include "firmware_remote.h"
#include "firmware_ota.h"
#include "firmware_release.h"
#include "esp_app_desc.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_ota_ops.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "mbedtls/sha256.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RELEASE_URL "https://luuhung93.github.io/esp32-c6-guard-filters/firmware/latest.json"
typedef struct {
  char version[32], build[65], sha256[65], url[384];
  size_t bytes, received;
  bool checked;
} release_t;
static release_t release;
static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
static release_t snapshot(void) {
  release_t copy;
  portENTER_CRITICAL(&mux);
  copy = release;
  portEXIT_CRITICAL(&mux);
  return copy;
}
static void hex(const uint8_t bytes[32], char out[65]) {
  static const char chars[] = "0123456789abcdef";
  for (unsigned i = 0; i < 32; i++) {
    out[2*i] = chars[bytes[i] >> 4];
    out[2*i+1] = chars[bytes[i] & 15];
  }
  out[64] = 0;
}
static esp_http_client_handle_t open_url(const char *url) {
  if (time(NULL) < 1700000000)
    return NULL;
  esp_http_client_config_t config = {.url = url,
    .crt_bundle_attach = esp_crt_bundle_attach,
    .disable_auto_redirect = true, .timeout_ms = 10000, .buffer_size = 2048};
  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (client && (esp_http_client_open(client, 0) != ESP_OK ||
      esp_http_client_fetch_headers(client) < 0 ||
      esp_http_client_get_status_code(client) != 200)) {
    esp_http_client_cleanup(client);
    client = NULL;
  }
  return client;
}
static const char *string(cJSON *o, const char *key) {
  cJSON *item = cJSON_GetObjectItemCaseSensitive(o, key);
  return cJSON_IsString(item) ? item->valuestring : NULL;
}
esp_err_t firmware_remote_check(void) {
  esp_http_client_handle_t client = open_url(RELEASE_URL);
  if (!client)
    return ESP_FAIL;
  char raw[2049];
  size_t n = 0;
  int64_t deadline = esp_timer_get_time() + 30000000;
  int k = 0;
  while (n < sizeof(raw)-1 && esp_timer_get_time() < deadline &&
      (k = esp_http_client_read(client, raw+n, sizeof(raw)-1-n)) > 0)
    n += k;
  bool complete = k == 0 && esp_http_client_is_complete_data_received(client);
  esp_http_client_cleanup(client);
  raw[n] = 0;
  if (!complete || memchr(raw, 0, n) || strstr(raw, "\\u0000"))
    return ESP_ERR_INVALID_RESPONSE;
  cJSON *root = cJSON_ParseWithLengthOpts(raw, n+1, NULL, true);
  cJSON *schema = cJSON_GetObjectItemCaseSensitive(root, "schemaVersion");
  cJSON *bytes = cJSON_GetObjectItemCaseSensitive(root, "bytes");
  const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
  bool valid = part && cJSON_IsNumber(schema) && schema->valuedouble == 1 &&
    cJSON_IsNumber(bytes) && firmware_release_valid(string(root,"chip"),
      string(root,"version"), string(root,"build"), string(root,"sha256"),
      string(root,"binaryURL"), bytes->valuedouble, part->size);
  release_t next = {0};
  if (valid) {
    strlcpy(next.version, string(root,"version"), sizeof(next.version));
    strlcpy(next.build, string(root,"build"), sizeof(next.build));
    strlcpy(next.sha256, string(root,"sha256"), sizeof(next.sha256));
    strlcpy(next.url, string(root,"binaryURL"), sizeof(next.url));
    next.bytes = (size_t)bytes->valuedouble;
    next.checked = true;
  }
  cJSON_Delete(root);
  if (!valid)
    return ESP_ERR_INVALID_RESPONSE;
  portENTER_CRITICAL(&mux);
  release = next;
  portEXIT_CRITICAL(&mux);
  return ESP_OK;
}
static esp_err_t download(esp_http_client_handle_t client, esp_ota_handle_t ota,
                          const release_t *selected) {
  uint8_t *buffer = malloc(2048);
  if (!buffer)
    return ESP_ERR_NO_MEM;
  mbedtls_sha256_context hash;
  mbedtls_sha256_init(&hash);
  esp_err_t e = mbedtls_sha256_starts(&hash, 0) == 0 ? ESP_OK : ESP_FAIL;
  size_t received = 0;
  int64_t deadline = esp_timer_get_time() + 300000000;
  while (e == ESP_OK && received < selected->bytes) {
    if (esp_timer_get_time() >= deadline) { e = ESP_ERR_TIMEOUT; break; }
    size_t size = selected->bytes - received;
    int n = esp_http_client_read(client, (char *)buffer, size < 2048 ? size : 2048);
    if (n <= 0) { e = ESP_FAIL; break; }
    if (mbedtls_sha256_update(&hash, buffer, n) != 0) { e = ESP_FAIL; break; }
    e = esp_ota_write(ota, buffer, n);
    received += n;
    portENTER_CRITICAL(&mux);
    release.received = received;
    portEXIT_CRITICAL(&mux);
  }
  uint8_t digest[32];
  char actual[65], extra;
  if (e == ESP_OK && (esp_http_client_read(client, &extra, 1) != 0 ||
      !esp_http_client_is_complete_data_received(client)))
    e = ESP_ERR_INVALID_SIZE;
  if (e == ESP_OK && mbedtls_sha256_finish(&hash, digest) != 0)
    e = ESP_FAIL;
  if (e == ESP_OK) {
    hex(digest, actual);
    if (strcmp(actual, selected->sha256)) e = ESP_ERR_INVALID_CRC;
  }
  mbedtls_sha256_free(&hash);
  free(buffer);
  return e;
}
esp_err_t firmware_remote_apply(const char *expected_build) {
#ifndef CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT
  (void)expected_build;
  return ESP_ERR_NOT_SUPPORTED;
#else
  release_t selected = snapshot();
  char current[65];
  firmware_ota_build(current);
  if (!selected.checked || !expected_build || strcmp(expected_build, selected.build) ||
      !strcmp(current, selected.build))
    return ESP_ERR_INVALID_STATE;
  const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
  if (!part || selected.bytes > part->size)
    return ESP_ERR_INVALID_SIZE;
  portENTER_CRITICAL(&mux);
  release.received = 0;
  portEXIT_CRITICAL(&mux);
  esp_http_client_handle_t client = open_url(selected.url);
  if (!client)
    return ESP_FAIL;
  int64_t length = esp_http_client_get_content_length(client);
  esp_ota_handle_t ota = 0;
  esp_err_t e = length >= 0 && (size_t)length != selected.bytes
    ? ESP_ERR_INVALID_SIZE : esp_ota_begin(part, selected.bytes, &ota);
  if (e == ESP_OK) e = download(client, ota, &selected);
  esp_http_client_cleanup(client);
  if (e == ESP_OK) {
    e = esp_ota_end(ota); // Native chip and RSA signature verification.
    ota = 0;
  }
  if (ota) esp_ota_abort(ota);
  esp_app_desc_t description;
  char build[65];
  if (e == ESP_OK) e = esp_ota_get_partition_description(part, &description);
  if (e == ESP_OK) {
    hex(description.app_elf_sha256, build);
    if (strcmp(build, selected.build)) e = ESP_ERR_INVALID_RESPONSE;
  }
  return e == ESP_OK ? firmware_ota_activate(part) : e;
#endif
}
cJSON *firmware_remote_json(void) {
  release_t copy = snapshot();
  char current[65];
  firmware_ota_build(current);
  cJSON *o = cJSON_CreateObject();
  if (!o) return NULL;
  if (!cJSON_AddBoolToObject(o, "checked", copy.checked) ||
      !cJSON_AddBoolToObject(o, "available", copy.checked && strcmp(copy.build, current)) ||
      !cJSON_AddStringToObject(o, "version", copy.version) ||
      !cJSON_AddStringToObject(o, "build", copy.build) ||
      !cJSON_AddStringToObject(o, "currentBuild", current) ||
      !cJSON_AddStringToObject(o, "currentVersion", esp_app_get_description()->version) ||
      !cJSON_AddNumberToObject(o, "bytes", copy.bytes) ||
      !cJSON_AddNumberToObject(o, "receivedBytes", copy.received)) {
    cJSON_Delete(o);
    return NULL;
  }
  return o;
}
