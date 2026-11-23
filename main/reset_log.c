#include "reset_log.h"
#include <string.h>

static bool entry_valid(const reset_entry_t *e) {
  return !(e->flags & ~RESET_HAS_SNAPSHOT) && e->trigger <= RESET_TRIGGER_OTA &&
         memchr(e->firmware, 0, sizeof(e->firmware));
}
bool reset_history_valid(const reset_history_t *h) {
  if (!h || h->version != 1 || h->count > RESET_HISTORY_MAX ||
      h->next >= RESET_HISTORY_MAX ||
      (h->count < RESET_HISTORY_MAX && h->next != h->count))
    return false;
  for (uint32_t i = 0; i < h->count; i++)
    if (!entry_valid(&h->entries[i]))
      return false;
  return true;
}
bool reset_history_append(reset_history_t *h, const reset_entry_t *entry) {
  if (!reset_history_valid(h) || !entry || !entry_valid(entry))
    return false;
  h->entries[h->next] = *entry;
  h->entries[h->next].sequence = h->next_sequence++;
  h->next = (h->next + 1) % RESET_HISTORY_MAX;
  if (h->count < RESET_HISTORY_MAX)
    h->count++;
  return true;
}
#ifdef ESP_PLATFORM
#include "config.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "nvs.h"
#include <stddef.h>

/* Alternate checksummed RTC copies so an interrupted update keeps the old one. */
typedef struct {
  uint32_t version, generation;
  reset_entry_t entry;
  uint32_t checksum;
} rtc_snapshot_t;
static RTC_NOINIT_ATTR rtc_snapshot_t rtc[2];
static portMUX_TYPE snapshot_lock = portMUX_INITIALIZER_UNLOCKED;
static reset_history_t history;
static unsigned active;
static uint32_t generation;
static unsigned last_dns_failures;
static reset_trigger_t reboot_trigger;
static bool started, persisted;
const reset_history_t *reset_log_history(void) { return &history; }
bool reset_log_persisted(void) { return persisted; }
static uint32_t checksum(const rtc_snapshot_t *s) {
  const unsigned char *p = (const unsigned char *)s;
  uint32_t hash = 2166136261u;
  for (size_t i = 0; i < offsetof(rtc_snapshot_t, checksum); i++)
    hash = (hash ^ p[i]) * 16777619u;
  return hash ? hash : 1;
}
static bool snapshot_valid(const rtc_snapshot_t *s) {
  return s->version == 1 && s->checksum && s->checksum == checksum(s) &&
         s->entry.flags == RESET_HAS_SNAPSHOT && entry_valid(&s->entry);
}
void reset_log_checkpoint(reset_trigger_t trigger, unsigned dns_failures) {
  if (!started)
    return;
  rtc_snapshot_t next = {.version = 1, .entry = {
      .flags = RESET_HAS_SNAPSHOT,
      .uptime_seconds = esp_timer_get_time() / 1000000,
      .heap = esp_get_free_heap_size(),
      .min_heap = esp_get_minimum_free_heap_size()}};
  _Static_assert(sizeof(GUARD_VERSION) <= sizeof(next.entry.firmware),
                 "Firmware version exceeds reset log field");
  memcpy(next.entry.firmware, GUARD_VERSION, sizeof(GUARD_VERSION));
  portENTER_CRITICAL(&snapshot_lock);
  if (dns_failures != RESET_KEEP_DNS_FAILURES)
    last_dns_failures = dns_failures;
  next.entry.dns_failures = last_dns_failures;
  if (trigger != RESET_TRIGGER_NONE)
    reboot_trigger = trigger;
  next.entry.trigger = reboot_trigger;
  next.generation = ++generation;
  next.checksum = checksum(&next);
  active ^= 1;
  rtc[active].checksum = 0;
  memcpy(&rtc[active], &next, offsetof(rtc_snapshot_t, checksum));
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
  rtc[active].checksum = next.checksum;
  portEXIT_CRITICAL(&snapshot_lock);
}
static bool rtc_retained(esp_reset_reason_t reason) {
  return reason == ESP_RST_SW || reason == ESP_RST_PANIC ||
         reason == ESP_RST_INT_WDT || reason == ESP_RST_TASK_WDT ||
         reason == ESP_RST_WDT;
}
void reset_log_start(void) {
  if (started)
    return;
  reset_entry_t entry = {.reset_reason = esp_reset_reason()};
  if (rtc_retained(entry.reset_reason)) {
    bool a = snapshot_valid(&rtc[0]), b = snapshot_valid(&rtc[1]);
    if (a || b) {
      active = b && (!a || (int32_t)(rtc[1].generation - rtc[0].generation) > 0);
      entry = rtc[active].entry;
      generation = rtc[active].generation;
      entry.reset_reason = esp_reset_reason();
      if (entry.reset_reason != ESP_RST_SW)
        entry.trigger = RESET_TRIGGER_NONE;
    }
  } else
    memset(rtc, 0, sizeof(rtc));
  started = true;
  reset_log_checkpoint(RESET_TRIGGER_NONE, 0);
  history = (reset_history_t){.version = 1, .next_sequence = 1};
  nvs_handle_t handle;
  esp_err_t e = nvs_open("guard_resets", NVS_READWRITE, &handle);
  if (e != ESP_OK) {
    reset_history_append(&history, &entry);
    ESP_LOGW("reset-log", "History storage unavailable: %s", esp_err_to_name(e));
    return;
  }
  size_t size = sizeof(history);
  e = nvs_get_blob(handle, "history", &history, &size);
  if (e == ESP_ERR_NVS_NOT_FOUND) {
    history = (reset_history_t){.version = 1, .next_sequence = 1};
    e = ESP_OK;
  } else if (e == ESP_OK && (size != sizeof(history) || !reset_history_valid(&history)))
    e = ESP_ERR_INVALID_STATE;
  if (e == ESP_OK && reset_history_append(&history, &entry)) {
    e = nvs_set_blob(handle, "history", &history, sizeof(history));
    if (e == ESP_OK)
      e = nvs_commit(handle);
    persisted = e == ESP_OK;
  } else {
    /* Preserve an unreadable/unknown stored format instead of overwriting it. */
    history = (reset_history_t){.version = 1, .next_sequence = 1};
    reset_history_append(&history, &entry);
  }
  nvs_close(handle);
  if (!persisted)
    ESP_LOGW("reset-log", "History not saved: %s", esp_err_to_name(e));
  ESP_LOGI("reset-log", "History entries=%lu persisted=%d reset=%d",
           (unsigned long)history.count, persisted, (int)entry.reset_reason);
}
#endif
