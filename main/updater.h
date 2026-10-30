#pragma once
#include "cJSON.h"
#include "esp_err.h"
#include <stdbool.h>
esp_err_t updater_start(void);
esp_err_t updater_submit(const char *action, const char *id);
cJSON *updater_json(void);
cJSON *updater_catalog(void);
bool updater_busy(void);
bool updater_flash_lock(void);
void updater_flash_unlock(void);
