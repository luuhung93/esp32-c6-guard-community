#pragma once
#include <stdbool.h>
#include <stdint.h>
typedef struct {
  unsigned failures, good, reboots;
} guard_health_policy_t;
typedef enum { HEALTH_WAIT, HEALTH_REBOOT, HEALTH_CLEAR_BUDGET } guard_health_action_t;
guard_health_action_t guard_health_step(guard_health_policy_t *, bool ok, bool eligible);
#ifdef ESP_PLATFORM
#include "esp_err.h"
typedef struct {
  uint32_t version, reboots, uptime_seconds, heap, min_heap;
} guard_health_record_t;
esp_err_t guard_watchdog_start(void);
esp_err_t guard_health_start(void);
void guard_watchdog_boot_complete(void);
const guard_health_record_t *guard_health_last_recovery(void);
#endif
