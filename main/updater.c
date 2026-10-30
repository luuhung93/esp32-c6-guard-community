#include "updater.h"
#include "config.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_vfs_fat.h"
#include "filter_store.h"
#include "firmware_remote.h"
#include "firmware_ota.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "guard_hash.h"
#include "mbedtls/sha256.h"
#include "network.h"
#include "nvs.h"
#include "status_led.h"
#include "update_policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
typedef struct {
  char action[16], id[65];
} job_t;
static SemaphoreHandle_t mutex, flash;
static QueueHandle_t queue;
static cJSON *catalog;
static bool busy;
static uint32_t sequence;
static char state[24] = "idle", message[128] = "";
static char last_action[16] = "";
static time_t checked, synced, attempted;
static size_t received;
static esp_http_client_handle_t open_url(const char *url, int *status) {
  if (status)
    *status = 0;
  if (!updater_url_allowed(url) || time(NULL) < 1700000000)
    return NULL;
  esp_http_client_config_t c = {.url = url,
                                .crt_bundle_attach = esp_crt_bundle_attach,
                                .timeout_ms = 10000,
                                .disable_auto_redirect = true,
                                .buffer_size = 2048};
  esp_http_client_handle_t h = esp_http_client_init(&c);
  if (!h)
    return NULL;
  if (esp_http_client_open(h, 0) != ESP_OK ||
      esp_http_client_fetch_headers(h) < 0) {
    esp_http_client_cleanup(h);
    return NULL;
  }
  int code = esp_http_client_get_status_code(h);
  if (status)
    *status = code;
  if (code != 200) {
    esp_http_client_cleanup(h);
    return NULL;
  }
  return h;
}
static char *fetch(const char *url, size_t cap, size_t *size, int *status) {
  esp_http_client_handle_t h = open_url(url, status);
  if (!h)
    return NULL;
  int64_t announced = esp_http_client_get_content_length(h);
  if (announced > (int64_t)cap) {
    esp_http_client_cleanup(h);
    return NULL;
  }
  size_t capacity = announced > 0 ? (size_t)announced : cap;
  char *out = malloc(capacity + 1);
  if (!out) {
    esp_http_client_cleanup(h);
    return NULL;
  }
  size_t n = 0;
  int64_t deadline = esp_timer_get_time() + 30000000;
  while (n < capacity) {
    if (esp_timer_get_time() >= deadline) {
      free(out);
      out = NULL;
      break;
    }
    int k = esp_http_client_read(h, out + n, capacity - n);
    if (k < 0) {
      free(out);
      out = NULL;
      break;
    }
    if (!k)
      break;
    n += k;
  }
  if (out && esp_timer_get_time() >= deadline) {
    free(out);
    out = NULL;
  }
  char extra;
  bool complete =
      out && n < capacity && esp_http_client_is_complete_data_received(h);
  if (out && n == capacity)
    complete = esp_http_client_read(h, &extra, 1) == 0 &&
               esp_http_client_is_complete_data_received(h);
  esp_http_client_cleanup(h);
  if (!complete) {
    free(out);
    return NULL;
  }
  out[n] = 0;
  *size = n;
  return out;
}
static void hex(const uint8_t *d, char out[65]) {
  static const char chars[] = "0123456789abcdef";
  for (unsigned i = 0; i < 32; i++) {
    out[2 * i] = chars[d[i] >> 4];
    out[2 * i + 1] = chars[d[i] & 15];
  }
  out[64] = 0;
}
static const char *string(cJSON *o, const char *k) {
  cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
  return cJSON_IsString(v) ? v->valuestring : NULL;
}
static bool sha_valid(const char *s) {
  if (!s || strlen(s) != 64)
    return false;
  for (unsigned i = 0; i < 64; i++)
    if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
      return false;
  return true;
}
static void compact_catalog(cJSON *root) {
  const char *keys[] = {"id", "name", "region", "ruleCount", "binaryBytes",
                        "binaryURL", "sha256", "hashBits", "formatVersion"};
  cJSON *items = cJSON_GetObjectItemCaseSensitive(root, "filters"), *item;
  cJSON_ArrayForEach(item, items) {
    cJSON *field = item->child;
    while (field) {
      cJSON *next = field->next;
      bool keep = false;
      for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (!strcmp(field->string, keys[i]))
          keep = true;
      if (!keep)
        cJSON_Delete(cJSON_DetachItemViaPointer(item, field));
      field = next;
    }
  }
  /* Provenance stays on the publisher; the ESP only retains runtime fields. */
  cJSON *field = root->child;
  while (field) {
    cJSON *next = field->next;
    if (strcmp(field->string, "filters") && strcmp(field->string, "schemaVersion"))
      cJSON_Delete(cJSON_DetachItemViaPointer(root, field));
    field = next;
  }
}
static bool safe_id(const char *id) {
  if (!id || !id[0] || strlen(id) >= 64)
    return false;
  for (const char *p = id; *p; p++)
    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
          (*p >= '0' && *p <= '9') || *p == '_' || *p == '-'))
      return false;
  return true;
}
static bool descriptor_valid(cJSON *root, const char *id) {
  cJSON *schema = cJSON_GetObjectItemCaseSensitive(root, "schemaVersion");
  cJSON *items = cJSON_GetObjectItemCaseSensitive(root, "filters");
  if (!safe_id(id) || !cJSON_IsNumber(schema) || schema->valuedouble != 2 ||
      !cJSON_IsArray(items) || cJSON_GetArraySize(items) != 1)
    return false;
  cJSON *f = cJSON_GetArrayItem(items, 0);
  const char *actual = string(f, "id"), *url = string(f, "binaryURL");
  cJSON *bytes = cJSON_GetObjectItemCaseSensitive(f, "binaryBytes");
  cJSON *bits = cJSON_GetObjectItemCaseSensitive(f, "hashBits");
  cJSON *format = cJSON_GetObjectItemCaseSensitive(f, "formatVersion");
  return actual && !strcmp(actual, id) && updater_url_allowed(url) &&
         sha_valid(string(f, "sha256")) && cJSON_IsNumber(bytes) &&
         isfinite(bytes->valuedouble) && bytes->valuedouble >= 152 &&
         bytes->valuedouble <= 4000144 && floor(bytes->valuedouble) == bytes->valuedouble &&
         cJSON_IsNumber(bits) && bits->valuedouble == 64 &&
         cJSON_IsNumber(format) && format->valuedouble == 1;
}
static esp_err_t read_item(const char *id, cJSON **out) {
  *out = NULL;
  if (!safe_id(id))
    return ESP_ERR_INVALID_ARG;
  char url[384];
  snprintf(url, sizeof(url), GUARD_CATALOG_BASE "/items/%s.json", id);
  size_t n;
  int status;
  char *raw = fetch(url, 4096, &n, &status);
  if (!raw)
    return status == 404 ? ESP_ERR_NOT_FOUND : ESP_FAIL;
  cJSON *root = memchr(raw, 0, n) || strstr(raw, "\\u0000") ? NULL :
      cJSON_ParseWithLengthOpts(raw, n + 1, NULL, true);
  free(raw);
  if (!descriptor_valid(root, id)) {
    cJSON_Delete(root);
    return ESP_ERR_INVALID_RESPONSE;
  }
  compact_catalog(root);
  *out = root;
  return ESP_OK;
}
static esp_err_t check_catalog(void) {
  size_t n;
  char *raw = fetch(GUARD_CATALOG_BASE "/manifest.json", 512, &n, NULL);
  if (!raw)
    return ESP_FAIL;
  cJSON *manifest = cJSON_ParseWithLengthOpts(raw, n + 1, NULL, true);
  free(raw);
  cJSON *schema = cJSON_GetObjectItemCaseSensitive(manifest, "schemaVersion");
  bool valid = cJSON_IsNumber(schema) && schema->valuedouble == 2;
  cJSON_Delete(manifest);
  if (!valid)
    return ESP_ERR_INVALID_RESPONSE;
  cJSON *installed = filter_store_json(), *next = cJSON_CreateObject();
  cJSON *items = next ? cJSON_AddArrayToObject(next, "filters") : NULL;
  esp_err_t e = installed && items ? ESP_OK : ESP_ERR_NO_MEM;
  for (int i = 0; e == ESP_OK && i < cJSON_GetArraySize(installed); i++) {
    cJSON *root = NULL;
    e = read_item(string(cJSON_GetArrayItem(installed, i), "id"), &root);
    if (e == ESP_ERR_NOT_FOUND) {
      e = ESP_OK; /* Retired lists remain installed and removable. */
      continue;
    }
    if (e == ESP_OK) {
      cJSON *entry = cJSON_DetachItemFromArray(cJSON_GetObjectItemCaseSensitive(root, "filters"), 0);
      cJSON_AddItemToArray(items, entry);
    }
    cJSON_Delete(root);
  }
  cJSON_Delete(installed);
  if (e != ESP_OK) {
    cJSON_Delete(next);
    return e;
  }
  xSemaphoreTake(mutex, portMAX_DELAY);
  cJSON *old = catalog;
  catalog = next;
  checked = time(NULL);
  xSemaphoreGive(mutex);
  cJSON_Delete(old);
  return ESP_OK;
}
static esp_err_t download_filter(esp_http_client_handle_t h, FILE *f,
                                 size_t bytes, char digest[65]) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  esp_err_t e = mbedtls_sha256_starts(&ctx, 0) == 0 ? ESP_OK : ESP_FAIL;
  uint8_t buf[2048], hash[32];
  size_t done = 0;
  int64_t deadline = esp_timer_get_time() + 300000000;
  while (e == ESP_OK && done < bytes) {
    if (esp_timer_get_time() >= deadline) {
      e = ESP_ERR_TIMEOUT;
      break;
    }
    size_t want = bytes - done;
    if (want > sizeof(buf))
      want = sizeof(buf);
    int k = esp_http_client_read(h, (char *)buf, want);
    if (k <= 0 || fwrite(buf, 1, k, f) != (size_t)k ||
        mbedtls_sha256_update(&ctx, buf, k) != 0) {
      e = ESP_FAIL;
      break;
    }
    done += k;
    xSemaphoreTake(mutex, portMAX_DELAY);
    received = done;
    xSemaphoreGive(mutex);
    vTaskDelay(1);
  }
  if (e == ESP_OK && esp_timer_get_time() >= deadline)
    e = ESP_ERR_TIMEOUT;
  if (e == ESP_OK &&
      (esp_http_client_read(h, (char *)buf, 1) != 0 ||
       !esp_http_client_is_complete_data_received(h)))
    e = ESP_ERR_INVALID_SIZE;
  if (e == ESP_OK && mbedtls_sha256_finish(&ctx, hash) != 0)
    e = ESP_FAIL;
  if (e == ESP_OK)
    hex(hash, digest);
  mbedtls_sha256_free(&ctx);
  return e;
}
static esp_err_t install(cJSON *item) {
  const char *id = string(item, "id"), *expected = string(item, "sha256"),
             *url = string(item, "binaryURL");
  size_t bytes = (size_t)cJSON_GetObjectItemCaseSensitive(item, "binaryBytes")
                     ->valuedouble;
  char current[65];
  if (filter_store_digest(id, current) && !strcmp(current, expected))
    return ESP_OK;
  uint64_t total, free_bytes;
  if (esp_vfs_fat_info(GUARD_STORE, &total, &free_bytes) != ESP_OK ||
      free_bytes < bytes + 65536)
    return ESP_ERR_NO_MEM;
  esp_http_client_handle_t h = open_url(url, NULL);
  if (!h)
    return ESP_FAIL;
  FILE *f = fopen(GUARD_STORE "/download.tmp", "wb");
  if (!f) {
    esp_http_client_cleanup(h);
    return ESP_FAIL;
  }
  char digest[65];
  esp_err_t e = download_filter(h, f, bytes, digest);
  if (e == ESP_OK && strcmp(digest, expected))
    e = ESP_ERR_INVALID_CRC;
  if (e == ESP_OK && (fflush(f) || fsync(fileno(f))))
    e = ESP_FAIL;
  if (fclose(f))
    e = ESP_FAIL;
  esp_http_client_cleanup(h);
  if (e == ESP_OK)
    e = filter_store_install(id, GUARD_STORE "/download.tmp", digest);
  if (e != ESP_OK)
    unlink(GUARD_STORE "/download.tmp");
  else
    synced = time(NULL);
  return e;
}
static esp_err_t times_save(void) {
  nvs_handle_t h;
  esp_err_t e = nvs_open("updates", NVS_READWRITE, &h);
  if (e != ESP_OK)
    return e;
  e = nvs_set_i64(h, "checked", checked);
  if (e == ESP_OK)
    e = nvs_set_i64(h, "attempted", attempted);
  if (e == ESP_OK)
    e = nvs_set_i64(h, "synced", synced);
  if (e == ESP_OK)
    e = nvs_commit(h);
  nvs_close(h);
  return e;
}
static void finish_job(const job_t *job, esp_err_t e) {
  xSemaphoreTake(mutex, portMAX_DELAY);
  strlcpy(state, e == ESP_OK ? (!strcmp(job->action,"ota-install") ? "rebooting" : "succeeded") : "error", sizeof(state));
  strlcpy(message, esp_err_to_name(e), sizeof(message));
  busy = firmware_ota_reboot_pending();
  xSemaphoreGive(mutex);
  status_led_set(LED_UPDATE_FAILED, e != ESP_OK);
  status_led_set(LED_UPDATING, firmware_ota_reboot_pending());
  updater_flash_unlock();
}
static void worker(void *unused) {
  (void)unused;
  job_t job;
  for (;;)
    if (xQueueReceive(queue, &job, portMAX_DELAY)) {
      esp_err_t e = ESP_OK;
      bool firmware = !strncmp(job.action, "ota-", 4);
      if (!strcmp(job.action, "ota-check")) {
        e = firmware_remote_check();
      } else if (!strcmp(job.action, "ota-install")) {
        e = firmware_remote_apply(job.id);
      } else if (!strcmp(job.action, "check")) {
        attempted = time(NULL);
        e = check_catalog();
      } else {
        cJSON *selected = !strcmp(job.action, "apply") ? filter_store_json() : NULL;
        int count = selected ? cJSON_GetArraySize(selected) : 1;
        if (!strcmp(job.action, "apply") && !selected)
          e = ESP_ERR_NO_MEM;
        for (int i = 0; i < count && e == ESP_OK; i++) {
          const char *id = selected ? string(cJSON_GetArrayItem(selected, i), "id") : job.id;
          cJSON *root = NULL;
          e = read_item(id, &root);
          if (e == ESP_ERR_NOT_FOUND && selected) {
            e = ESP_OK;
            continue;
          }
          if (e == ESP_OK)
            e = install(cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(root, "filters"), 0));
          cJSON_Delete(root);
        }
        cJSON_Delete(selected);
        if (e == ESP_OK) {
          esp_err_t metadata = check_catalog();
          if (metadata != ESP_OK)
            ESP_LOGW("updates", "Policy saved; metadata refresh deferred: %s", esp_err_to_name(metadata));
        }
      }
      esp_err_t persisted = firmware ? ESP_OK : times_save();
      if (e == ESP_OK)
        e = persisted;
      finish_job(&job, e);
    }
}
static void scheduler(void *unused) {
  (void)unused;
  for (;;) {
    time_t now = time(NULL);
    if (network_ready() && updater_check_due(now, checked, attempted))
      updater_submit("check", NULL);
    vTaskDelay(pdMS_TO_TICKS(60000));
  }
}
bool updater_flash_lock(void) { return flash && xSemaphoreTake(flash, 0); }
void updater_flash_unlock(void) {
  if (!firmware_ota_reboot_pending()) xSemaphoreGive(flash);
}
bool updater_busy(void) {
  xSemaphoreTake(mutex, portMAX_DELAY);
  bool b = busy;
  xSemaphoreGive(mutex);
  return b;
}
esp_err_t updater_submit(const char *action, const char *id) {
  if (strcmp(action, "check") && strcmp(action, "install") &&
      strcmp(action, "apply") && strcmp(action, "ota-check") &&
      strcmp(action, "ota-install"))
    return ESP_ERR_INVALID_ARG;
  if (!strcmp(action, "install") && !safe_id(id))
    return ESP_ERR_INVALID_ARG;
  if (id && strlen(id) >= (!strcmp(action,"ota-install") ? 65 : 64))
    return ESP_ERR_INVALID_ARG;
  if (!strcmp(action,"ota-install") && (!id || strlen(id) != 64))
    return ESP_ERR_INVALID_ARG;
  if (!updater_flash_lock())
    return ESP_ERR_INVALID_STATE;
  job_t job = {0};
  strlcpy(job.action, action, 16);
  if (id)
    strlcpy(job.id, id, sizeof(job.id));
  xSemaphoreTake(mutex, portMAX_DELAY);
  busy = true;
  strlcpy(last_action, action, sizeof(last_action));
  received = 0;
  sequence++;
  strcpy(state, "running");
  message[0] = 0;
  xSemaphoreGive(mutex);
  status_led_set(LED_UPDATE_FAILED, false);
  status_led_set(LED_UPDATING, true);
  if (!xQueueSend(queue, &job, 0)) {
    xSemaphoreTake(mutex, portMAX_DELAY);
    busy = false;
    xSemaphoreGive(mutex);
    status_led_set(LED_UPDATING, false);
    status_led_set(LED_UPDATE_FAILED, true);
    updater_flash_unlock();
    return ESP_FAIL;
  }
  return ESP_OK;
}
cJSON *updater_catalog(void) {
  cJSON *o = cJSON_CreateObject();
  cJSON *items = o ? cJSON_AddArrayToObject(o, "filters") : NULL;
  if (!items) {
    cJSON_Delete(o);
    return NULL;
  }
  const char *keys[] = {"id", "name", "region", "ruleCount", "binaryBytes"};
  bool ok = true;
  xSemaphoreTake(mutex, portMAX_DELAY);
  cJSON *source = cJSON_GetObjectItemCaseSensitive(catalog, "filters"), *item;
  cJSON_ArrayForEach(item, source) {
    cJSON *copy = cJSON_CreateObject();
    if (!copy || !cJSON_AddItemToArray(items, copy)) {
      cJSON_Delete(copy);
      ok = false;
      break;
    }
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
      cJSON *value = cJSON_GetObjectItemCaseSensitive(item, keys[i]);
      if (!value)
        continue;
      cJSON *field = cJSON_Duplicate(value, true);
      if (!field || !cJSON_AddItemToObject(copy, keys[i], field)) {
        cJSON_Delete(field);
        ok = false;
        break;
      }
    }
    if (!ok)
      break;
  }
  xSemaphoreGive(mutex);
  if (!ok) {
    cJSON_Delete(o);
    return NULL;
  }
  return o;
}
cJSON *updater_json(void) {
  cJSON *o = cJSON_CreateObject();
  if (!o)
    return NULL;
  xSemaphoreTake(mutex, portMAX_DELAY);
  bool ok = cJSON_AddNumberToObject(o, "id", sequence) &&
            cJSON_AddBoolToObject(o, "busy", busy) &&
            cJSON_AddStringToObject(o, "state", state) &&
            cJSON_AddStringToObject(o, "action", last_action) &&
            cJSON_AddStringToObject(o, "message", message) &&
            cJSON_AddNumberToObject(o, "receivedBytes", received) &&
            cJSON_AddNumberToObject(o, "lastCatalogCheck", checked) &&
            cJSON_AddNumberToObject(o, "lastDeviceSync", synced) &&
            cJSON_AddNumberToObject(o, "lastAttempt", attempted);
  xSemaphoreGive(mutex);
  if (!ok) {
    cJSON_Delete(o);
    return NULL;
  }
  return o;
}
esp_err_t updater_start(void) {
  mutex = xSemaphoreCreateMutex();
  flash = xSemaphoreCreateBinary();
  if (flash)
    xSemaphoreGive(flash);
  queue = xQueueCreate(1, sizeof(job_t));
  if (!mutex || !flash || !queue)
    return ESP_ERR_NO_MEM;
  nvs_handle_t h;
  if (nvs_open("updates", NVS_READONLY, &h) == ESP_OK) {
    int64_t t;
    if (nvs_get_i64(h, "checked", &t) == ESP_OK)
      checked = t;
    if (nvs_get_i64(h, "attempted", &t) == ESP_OK)
      attempted = t;
    if (nvs_get_i64(h, "synced", &t) == ESP_OK)
      synced = t;
    nvs_close(h);
  }
  if (xTaskCreate(worker, "updates", 12288, NULL, 2, NULL) != pdPASS ||
      xTaskCreate(scheduler, "update-clock", 3072, NULL, 1, NULL) != pdPASS)
    return ESP_ERR_NO_MEM;
  return ESP_OK;
}
