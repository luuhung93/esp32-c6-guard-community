#pragma once
#include "cJSON.h"
#include "esp_err.h"
#include "filter.h"
esp_err_t filter_store_mount(void);
bool filter_store_ready(void);
bool filter_store_factory_needed(void);
bool filter_store_match(const char *canonical);
esp_err_t filter_store_install(const char *id, const char *path,
                               const char *sha256);
esp_err_t filter_store_toggle(const char *id, bool enabled);
esp_err_t filter_store_remove(const char *id);
esp_err_t filter_store_prune_disabled(void);
cJSON *filter_store_json(void);
bool filter_store_digest(const char *id, char digest[65]);
