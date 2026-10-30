#pragma once
#include "esp_http_server.h"
#include "esp_partition.h"
esp_err_t firmware_ota_activate(const esp_partition_t *part);
bool firmware_ota_reboot_pending(void);
esp_err_t firmware_ota_upload(httpd_req_t *);
void firmware_ota_confirm(bool healthy);
void firmware_ota_build(char out[65]);
const char *firmware_ota_state(void);
