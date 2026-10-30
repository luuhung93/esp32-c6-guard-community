#pragma once
#include "cJSON.h"
#include "esp_err.h"
esp_err_t firmware_remote_check(void);
esp_err_t firmware_remote_apply(const char *expected_build);
cJSON *firmware_remote_json(void);
