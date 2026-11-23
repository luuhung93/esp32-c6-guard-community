#pragma once
#include <stdbool.h>
#include <stdint.h>
#define RESET_HISTORY_MAX 8
#define RESET_HAS_SNAPSHOT 1u
/* Planned restarts must preserve the last sampled DNS failure streak. */
#define RESET_KEEP_DNS_FAILURES UINT32_MAX
typedef enum { RESET_TRIGGER_NONE, RESET_TRIGGER_DNS, RESET_TRIGGER_USER,
               RESET_TRIGGER_OTA } reset_trigger_t;
typedef struct {
  uint32_t sequence, reset_reason, flags, uptime_seconds, heap, min_heap,
      dns_failures, trigger;
  char firmware[32];
} reset_entry_t;
typedef struct {
  uint32_t version, count, next, next_sequence;
  reset_entry_t entries[RESET_HISTORY_MAX];
} reset_history_t;
bool reset_history_valid(const reset_history_t *);
bool reset_history_append(reset_history_t *, const reset_entry_t *);
#ifdef ESP_PLATFORM
void reset_log_start(void);
void reset_log_checkpoint(reset_trigger_t, unsigned dns_failures);
const reset_history_t *reset_log_history(void);
bool reset_log_persisted(void);
#endif
