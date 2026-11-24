#pragma once
#include <stdbool.h>
#include <stdint.h>
#define DIAGNOSTIC_MAX 32
/* Stable numeric codes are also included in the downloaded JSON legend. */
typedef enum {
  DIAG_BOOT, DIAG_WIFI_UP, DIAG_WIFI_DOWN, DIAG_IP_UP, DIAG_IP_LOST,
  DIAG_DNS_FAIL, DIAG_DNS_OK, DIAG_DNS_ERRORS, DIAG_LOW_HEAP, DIAG_SAMPLE
} diagnostic_code_t;
typedef struct { uint32_t uptime, heap, code; int32_t detail; } diagnostic_event_t;
typedef struct {
  uint32_t version, count, next, reset_reason;
  char firmware[32];
  diagnostic_event_t entries[DIAGNOSTIC_MAX];
} diagnostic_ring_t;
bool diagnostic_ring_valid(const diagnostic_ring_t *r);
bool diagnostic_ring_append(diagnostic_ring_t *r, diagnostic_event_t e);
bool diagnostic_save_due(bool dirty, unsigned attempts, uint32_t now, uint32_t last);
#ifdef ESP_PLATFORM
#include "cJSON.h"
void diagnostics_start(void);
void diagnostics_record(diagnostic_code_t code, int32_t detail);
void diagnostics_sample(bool network, bool eligible, bool udp, bool tcp,
                        uint64_t dns_errors);
void diagnostics_flush(void);
cJSON *diagnostics_json(void);
#endif
