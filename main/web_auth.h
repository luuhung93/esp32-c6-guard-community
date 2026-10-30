#pragma once
#include "esp_err.h"
#include "esp_http_server.h"
#include <stdbool.h>
esp_err_t web_auth_init(void);
bool web_auth_configured(void);
bool web_auth_origin(httpd_req_t *);
bool web_auth_require(httpd_req_t *, bool mutation);
esp_err_t web_auth_set_password(const char *);
esp_err_t web_auth_enroll(httpd_req_t *, const char *, char csrf[65]);
esp_err_t web_auth_login(httpd_req_t *, const char *, char csrf[65]);
void web_auth_logout(void);
