#pragma once
#include "esp_err.h"
#include "settings.h"
esp_err_t network_start(const guard_settings_t *);
bool network_ready(void);
bool network_has_credentials(void);
esp_err_t network_connect(const guard_settings_t *);
bool network_upstream_safe(const char *ip);
bool network_setup_mode(void);
void network_ip(char out[16]);
bool network_addresses(char ip[16], char gateway[16], char netmask[16]);
void network_request_setup(void);
typedef struct {
  char ssid[33];
  int signal;
  bool secured;
} network_ap_t;
esp_err_t network_scan(network_ap_t *out, unsigned capacity, unsigned *count);
