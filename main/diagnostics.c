#include "diagnostics.h"
#include <string.h>

bool diagnostic_ring_valid(const diagnostic_ring_t *r) {
  if (!r || r->version != 1 || r->count > DIAGNOSTIC_MAX ||
      r->next >= DIAGNOSTIC_MAX ||
      (r->count < DIAGNOSTIC_MAX && r->next != r->count) ||
      !memchr(r->firmware, 0, sizeof(r->firmware)))
    return false;
  for (unsigned i = 0; i < r->count; i++)
    if (r->entries[i].code > DIAG_SAMPLE) return false;
  return true;
}
bool diagnostic_ring_append(diagnostic_ring_t *r, diagnostic_event_t e) {
  if (!diagnostic_ring_valid(r) || e.code > DIAG_SAMPLE) return false;
  r->entries[r->next] = e;
  r->next = (r->next + 1) % DIAGNOSTIC_MAX;
  if (r->count < DIAGNOSTIC_MAX) r->count++;
  return true;
}
bool diagnostic_save_due(bool dirty, unsigned attempts, uint32_t now, uint32_t last) {
  return dirty && attempts < 4 && (!attempts || now - last >= 900);
}
#ifdef ESP_PLATFORM
#include "config.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "nvs.h"
#include "updater.h"
#include <limits.h>

static diagnostic_ring_t current, saved, pending_incident;
static portMUX_TYPE lock = portMUX_INITIALIZER_UNLOCKED;
static bool started, dirty, writable, dns_failed, low_heap, errors_active;
static unsigned attempts;
static uint32_t last_attempt;
static uint64_t previous_errors;
static esp_err_t storage_error;

void diagnostics_record(diagnostic_code_t code, int32_t detail) {
  if (!started) return;
  diagnostic_event_t e = {.uptime = esp_timer_get_time() / 1000000,
      .heap = esp_get_free_heap_size(), .code = code, .detail = detail};
  portENTER_CRITICAL(&lock);
  if (diagnostic_ring_append(&current, e) &&
      (code == DIAG_WIFI_DOWN || code == DIAG_IP_LOST || code == DIAG_DNS_FAIL ||
       ((code == DIAG_DNS_ERRORS || code == DIAG_LOW_HEAP) && detail != 0))) {
    /* Healthy samples must not evict a fault while flash writes are throttled. */
    pending_incident = current;
    dirty = true;
  }
  portEXIT_CRITICAL(&lock);
}
void diagnostics_start(void) {
  if (started) return;
  current = (diagnostic_ring_t){.version = 1, .reset_reason = esp_reset_reason()};
  _Static_assert(sizeof(GUARD_VERSION) <= sizeof(current.firmware), "Version too long");
  memcpy(current.firmware, GUARD_VERSION, sizeof(GUARD_VERSION));
  nvs_handle_t h;
  storage_error = nvs_open("guard_diag", NVS_READONLY, &h);
  if (storage_error == ESP_OK) {
    size_t n = sizeof(saved);
    storage_error = nvs_get_blob(h, "incident", &saved, &n);
    if (storage_error == ESP_OK &&
        (n != sizeof(saved) || !diagnostic_ring_valid(&saved)))
      storage_error = ESP_ERR_INVALID_STATE;
    nvs_close(h);
  }
  if (storage_error == ESP_ERR_NVS_NOT_FOUND) {
    memset(&saved, 0, sizeof(saved));
    storage_error = ESP_OK;
  }
  writable = storage_error == ESP_OK;
  if (!writable) memset(&saved, 0, sizeof(saved));
  started = true;
  diagnostics_record(DIAG_BOOT, current.reset_reason);
}
void diagnostics_sample(bool network, bool eligible, bool udp, bool tcp,
                        uint64_t dns_errors) {
  bool failed = eligible && !(udp && tcp);
  if (eligible) {
    if (failed != dns_failed)
      diagnostics_record(failed ? DIAG_DNS_FAIL : DIAG_DNS_OK, udp | (tcp << 1));
    dns_failed = failed;
  }
  uint64_t delta = dns_errors >= previous_errors ? dns_errors - previous_errors : 0;
  if ((delta != 0) != errors_active)
    diagnostics_record(DIAG_DNS_ERRORS, delta > INT32_MAX ? INT32_MAX : (int32_t)delta);
  errors_active = delta != 0;
  previous_errors = dns_errors;
  bool low = esp_get_free_heap_size() < 16384;
  if (low != low_heap) diagnostics_record(DIAG_LOW_HEAP, low);
  low_heap = low;
  /* Sample flags: network=1, DNS probe eligible=2, UDP passed=4, TCP passed=8. */
  diagnostics_record(DIAG_SAMPLE, network | (eligible << 1) | (udp << 2) | (tcp << 3));
}
void diagnostics_flush(void) {
  uint32_t now = esp_timer_get_time() / 1000000;
  portENTER_CRITICAL(&lock);
  bool due = writable && diagnostic_save_due(dirty, attempts, now, last_attempt);
  portEXIT_CRITICAL(&lock);
  if (!due || !updater_flash_lock()) return;
  diagnostic_ring_t snapshot;
  portENTER_CRITICAL(&lock);
  snapshot = pending_incident;
  dirty = false;
  attempts++;
  last_attempt = now;
  portEXIT_CRITICAL(&lock);
  nvs_handle_t h;
  esp_err_t e = nvs_open("guard_diag", NVS_READWRITE, &h);
  if (e == ESP_OK) {
    e = nvs_set_blob(h, "incident", &snapshot, sizeof(snapshot));
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
  }
  portENTER_CRITICAL(&lock);
  storage_error = e;
  if (e == ESP_OK) saved = snapshot;
  else dirty = true;
  portEXIT_CRITICAL(&lock);
  updater_flash_unlock();
}
static cJSON *ring_json(const diagnostic_ring_t *r) {
  if (!r->version) return cJSON_CreateNull();
  cJSON *o = cJSON_CreateObject();
  cJSON *events = o ? cJSON_AddArrayToObject(o, "events") : NULL;
  if (!events || !cJSON_AddStringToObject(o, "firmware", r->firmware) ||
      !cJSON_AddNumberToObject(o, "resetReason", r->reset_reason)) goto failed;
  for (unsigned i = 0; i < r->count; i++) {
    const diagnostic_event_t *e = &r->entries[(r->next + DIAGNOSTIC_MAX - r->count + i) % DIAGNOSTIC_MAX];
    cJSON *v = cJSON_CreateObject();
    if (!v || !cJSON_AddNumberToObject(v, "uptimeSeconds", e->uptime) ||
        !cJSON_AddNumberToObject(v, "heap", e->heap) ||
        !cJSON_AddNumberToObject(v, "code", e->code) ||
        !cJSON_AddNumberToObject(v, "detail", e->detail) || !cJSON_AddItemToArray(events, v)) {
      cJSON_Delete(v);
      goto failed;
    }
  }
  return o;
failed:
  cJSON_Delete(o);
  return NULL;
}
cJSON *diagnostics_json(void) {
  diagnostic_ring_t live, incident;
  portENTER_CRITICAL(&lock);
  live = current; incident = saved;
  esp_err_t error = storage_error;
  unsigned used = attempts;
  bool pending = dirty;
  portEXIT_CRITICAL(&lock);
  const char *names[] = {"boot", "wifi-connected", "wifi-disconnected", "ip-acquired",
    "ip-lost", "dns-probe-failed", "dns-probe-recovered", "dns-errors", "low-heap", "sample"};
  cJSON *o = cJSON_CreateObject(), *a = ring_json(&live), *b = ring_json(&incident);
  cJSON *legend = cJSON_CreateStringArray(names, sizeof(names) / sizeof(*names));
  if (!o || !a || !b || !legend) goto failed;
  if (!cJSON_AddItemToObject(o, "current", a)) goto failed;
  a = NULL;
  if (!cJSON_AddItemToObject(o, "savedIncident", b)) goto failed;
  b = NULL;
  if (!cJSON_AddItemToObject(o, "codes", legend)) goto failed;
  legend = NULL;
  if (!cJSON_AddNumberToObject(o, "schemaVersion", 1) ||
      !cJSON_AddNumberToObject(o, "storageError", error) ||
      !cJSON_AddNumberToObject(o, "saveAttempts", used) ||
      !cJSON_AddBoolToObject(o, "pending", pending)) goto failed;
  return o;
failed:
  cJSON_Delete(a); cJSON_Delete(b); cJSON_Delete(legend); cJSON_Delete(o);
  return NULL;
}
#endif
