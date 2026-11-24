#include "health.h"
guard_health_action_t guard_health_step(guard_health_policy_t *p, bool ok,
                                       bool eligible) {
  if (!eligible) {
    p->failures = p->good = 0;
    return HEALTH_WAIT;
  }
  if (ok) {
    p->failures = 0;
    if (p->good < 30)
      p->good++;
    return p->good == 30 && p->reboots ? HEALTH_CLEAR_BUDGET : HEALTH_WAIT;
  }
  p->good = 0;
  if (p->failures < 3)
    p->failures++;
  return p->failures == 3 && p->reboots < 3 ? HEALTH_REBOOT : HEALTH_WAIT;
}
#ifdef ESP_PLATFORM
#include "dns.h"
#include "diagnostics.h"
#include "network.h"
#include "reset_log.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include "firmware_ota.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "nvs.h"
#include "updater.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static guard_health_record_t last_recovery;
const guard_health_record_t *guard_health_last_recovery(void) {
  return &last_recovery;
}
esp_err_t guard_watchdog_start(void) {
  esp_task_wdt_config_t config = {
      .timeout_ms = 120000, .idle_core_mask = 1, .trigger_panic = true};
  esp_err_t e = esp_task_wdt_reconfigure(&config);
  if (e == ESP_ERR_INVALID_STATE)
    e = esp_task_wdt_init(&config);
  return e == ESP_OK ? esp_task_wdt_add(NULL) : e;
}
void guard_watchdog_boot_complete(void) {
  ESP_ERROR_CHECK(esp_task_wdt_delete(NULL));
  esp_task_wdt_config_t config = {
      .timeout_ms = 30000, .idle_core_mask = 1, .trigger_panic = true};
  ESP_ERROR_CHECK(esp_task_wdt_reconfigure(&config));
}

static bool wait_socket(int fd, bool writing, int64_t deadline) {
  int64_t left = deadline - esp_timer_get_time();
  if (left <= 0)
    return false;
  fd_set set;
  FD_ZERO(&set);
  FD_SET(fd, &set);
  struct timeval tv = {.tv_sec = left / 1000000, .tv_usec = left % 1000000};
  return select(fd + 1, writing ? NULL : &set, writing ? &set : NULL, NULL,
                &tv) == 1;
}
static int probe_io(int fd, uint8_t *p, size_t size, bool writing, bool stream,
                    int64_t deadline) {
  size_t done = 0;
  while (done < size) {
    if (!wait_socket(fd, writing, deadline))
      return -1;
    int n = writing ? send(fd, p + done, size - done, 0)
                    : recv(fd, p + done, size - done, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
      continue;
    if (n <= 0)
      return -1;
    if (!stream)
      return n;
    done += n;
  }
  return (int)done;
}
static bool probe(bool tcp) {
  int fd = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
  if (fd < 0)
    return false;
  int64_t deadline = esp_timer_get_time() + 2000000;
  struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(53)};
  inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr);
  int flags = fcntl(fd, F_GETFL, 0);
  bool ok = flags >= 0 && !fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if (ok && connect(fd, (struct sockaddr *)&peer, sizeof(peer))) {
    int error = 0;
    socklen_t size = sizeof(error);
    ok = errno == EINPROGRESS && wait_socket(fd, true, deadline) &&
         !getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) && !error;
  }
  /* Zero questions deliberately elicit FORMERR without upstream or history. */
  uint8_t query[14] = {0, 12}, response[16] = {0};
  uint16_t id = (uint16_t)esp_random();
  query[2] = id >> 8;
  query[3] = id;
  unsigned offset = tcp ? 0 : 2;
  ok = ok && probe_io(fd, query + offset, 14 - offset, true, tcp, deadline) ==
                 (int)(14 - offset);
  if (tcp)
    ok = ok && probe_io(fd, response, 2, false, true, deadline) == 2 &&
         response[0] == 0 && response[1] == 12;
  ok = ok && probe_io(fd, response + 2, tcp ? 12 : 12 + offset,
                       false, tcp, deadline) == 12;
  close(fd);
  return ok && response[2] == query[2] && response[3] == query[3] &&
         response[4] == 0x80 && response[5] == 0x81 &&
         !memcmp(response + 6, query + 6, 8);
}

static esp_err_t save_record(const guard_health_record_t *record) {
  nvs_handle_t handle;
  esp_err_t e = nvs_open("guard_health", NVS_READWRITE, &handle);
  if (e != ESP_OK)
    return e;
  e = nvs_set_blob(handle, "recovery", record, sizeof(*record));
  if (e == ESP_OK)
    e = nvs_commit(handle);
  nvs_close(handle);
  return e;
}
static void monitor(void *unused) {
  (void)unused;
  ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
  guard_health_policy_t policy = {.reboots = last_recovery.reboots};
  guard_health_record_t record = last_recovery;
  for (unsigned ticks = 0;; ticks++) {
    ESP_ERROR_CHECK(esp_task_wdt_reset());
    if (ticks >= 6 && ticks % 3 == 0) {
      bool eligible = dns_is_ready() && updater_flash_lock();
      if (eligible)
        updater_flash_unlock();
      bool ok = false, udp = false, tcp = false;
      if (eligible) {
        udp = probe(false);
        tcp = probe(true);
        ok = udp && tcp;
        if (!ok)
          ESP_LOGW("health", "Local DNS probe failed: UDP=%d TCP=%d", udp, tcp);
      }
      dns_totals_t totals;
      dns_totals(&totals);
      diagnostics_sample(network_ready(), eligible, udp, tcp, totals.errors);
      diagnostics_flush();
      guard_health_action_t action = guard_health_step(&policy, ok, eligible);
      if (action != HEALTH_WAIT && updater_flash_lock()) {
        if (action == HEALTH_REBOOT) {
          record.reboots = policy.reboots + 1;
          record.uptime_seconds = esp_timer_get_time() / 1000000;
          record.heap = esp_get_free_heap_size();
          record.min_heap = esp_get_minimum_free_heap_size();
        } else
          record.reboots = 0;
        esp_err_t e = save_record(&record);
        if (e == ESP_OK && action == HEALTH_REBOOT) {
          ESP_LOGE("health", "DNS stalled; reboot %lu/3, heap=%lu",
                   (unsigned long)record.reboots, (unsigned long)record.heap);
          reset_log_checkpoint(RESET_TRIGGER_DNS, policy.failures);
          esp_restart();
        }
        updater_flash_unlock();
        if (e != ESP_OK) {
          /* Persist the budget before reboot; storage failure must not loop. */
          ESP_LOGE("health", "Recovery record failed: %s; reboot disabled",
                   esp_err_to_name(e));
          policy.reboots = 3;
          policy.good = 0;
        } else
          policy.reboots = record.reboots;
      }
    }
    reset_log_checkpoint(RESET_TRIGGER_NONE, policy.failures);
    vTaskDelay(pdMS_TO_TICKS(10000));
  }
}
esp_err_t guard_health_start(void) {
  nvs_handle_t handle;
  last_recovery = (guard_health_record_t){.version = 1};
  esp_err_t e = nvs_open("guard_health", NVS_READONLY, &handle);
  if (e == ESP_OK) {
    size_t size = sizeof(last_recovery);
    e = nvs_get_blob(handle, "recovery", &last_recovery, &size);
    nvs_close(handle);
    if (e == ESP_ERR_NVS_NOT_FOUND) {
      last_recovery = (guard_health_record_t){.version = 1};
      e = ESP_OK;
    } else if (e == ESP_OK && (size != sizeof(last_recovery) ||
                               last_recovery.version != 1 ||
                               last_recovery.reboots > 3))
      e = ESP_ERR_INVALID_STATE;
  } else if (e == ESP_ERR_NVS_NOT_FOUND)
    e = ESP_OK;
  if (e != ESP_OK) {
    ESP_LOGE("health", "Invalid recovery record: %s; reboot disabled",
             esp_err_to_name(e));
    last_recovery = (guard_health_record_t){.version = 1, .reboots = 3};
  }
  ESP_LOGI("health", "Reset=%d, DNS recovery budget used=%lu/3", esp_reset_reason(),
           (unsigned long)last_recovery.reboots);
  TaskHandle_t task;
  if (xTaskCreate(monitor, "guard-health", 3072, NULL, 1, &task) != pdPASS)
    return ESP_ERR_NO_MEM;
  e = esp_task_wdt_add(task);
  if (e != ESP_OK) {
    vTaskDelete(task);
    return e;
  }
  xTaskNotifyGive(task);
  return ESP_OK;
}
#endif
