#pragma once
#include "esp_err.h"
#include "settings.h"
#include "statistics.h"
esp_err_t dns_start(const guard_settings_t *);
void dns_policy_changed(void);
bool dns_is_ready(void);
typedef struct {
  uint64_t total, blocked, cached, errors;
} dns_totals_t;
void dns_totals(dns_totals_t *out);
size_t dns_recent(query_event_t *out, size_t offset, size_t cap);
void dns_history_enable(bool);
