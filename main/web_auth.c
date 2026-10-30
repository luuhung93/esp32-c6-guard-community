#include "web_auth.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "network.h"
#include "nvs.h"
#include "web_policy.h"
#include <stdio.h>
#include <string.h>
static uint8_t salt[16], password_hash[32];
static bool configured;
static char session[65], token[65];
static int64_t expires, last_login;
static bool equal(const void *a, const void *b, size_t n) {
  const uint8_t *x = a, *y = b;
  unsigned v = 0;
  for (size_t i = 0; i < n; i++)
    v |= x[i] ^ y[i];
  return v == 0;
}
static void random_hex(char out[65]) {
  uint8_t bytes[32];
  esp_fill_random(bytes, sizeof(bytes));
  for (unsigned i = 0; i < 32; i++)
    snprintf(out + 2 * i, 3, "%02x", bytes[i]);
}
static bool derive(const char *password, const uint8_t *s, uint8_t out[32]) {
  return mbedtls_pkcs5_pbkdf2_hmac_ext(
             MBEDTLS_MD_SHA256, (const unsigned char *)password,
             strlen(password), s, 16, 60000, 32, out) == 0;
}
esp_err_t web_auth_init(void) {
  nvs_handle_t h;
  esp_err_t e = nvs_open("auth", NVS_READONLY, &h);
  if (e == ESP_ERR_NVS_NOT_FOUND)
    return ESP_OK;
  if (e != ESP_OK)
    return e;
  uint8_t record[48];
  size_t n = sizeof(record);
  e = nvs_get_blob(h, "password", record, &n);
  nvs_close(h);
  if (e == ESP_ERR_NVS_NOT_FOUND)
    return ESP_OK;
  if (e != ESP_OK || n != 48)
    return ESP_ERR_INVALID_STATE;
  memcpy(salt, record, 16);
  memcpy(password_hash, record + 16, 32);
  configured = true;
  return ESP_OK;
}
bool web_auth_configured(void) { return configured; }
esp_err_t web_auth_set_password(const char *p) {
  size_t n = strlen(p);
  if (n < 12 || n > 128)
    return ESP_ERR_INVALID_ARG;
  uint8_t record[48];
  esp_fill_random(record, 16);
  if (!derive(p, record, record + 16))
    return ESP_FAIL;
  nvs_handle_t h;
  esp_err_t e = nvs_open("auth", NVS_READWRITE, &h);
  if (e != ESP_OK)
    return e;
  e = nvs_set_blob(h, "password", record, 48);
  if (e == ESP_OK)
    e = nvs_commit(h);
  nvs_close(h);
  if (e == ESP_OK) {
    memcpy(salt, record, 16);
    memcpy(password_hash, record + 16, 32);
    configured = true;
    web_auth_logout();
  }
  return e;
}
bool web_auth_origin(httpd_req_t *r) {
  char host[64], origin[80], ip[16];
  if (httpd_req_get_hdr_value_str(r, "Host", host, sizeof(host)) != ESP_OK ||
      httpd_req_get_hdr_value_str(r, "Origin", origin, sizeof(origin)) !=
          ESP_OK)
    return false;
  network_ip(ip);
  return web_origin_allowed(host, origin, ip, network_setup_mode());
}
bool web_auth_require(httpd_req_t *r, bool mutation) {
  if (!configured || esp_timer_get_time() > expires || !session[0])
    return false;
  char cookie[160];
  if (httpd_req_get_hdr_value_str(r, "Cookie", cookie, sizeof(cookie)) !=
      ESP_OK)
    return false;
  char wanted[80];
  snprintf(wanted, sizeof(wanted), "guard_session=%s", session);
  char *start = strstr(cookie, wanted);
  if (!start || (start != cookie && start[-1] != ' ' && start[-1] != ';') ||
      (start[strlen(wanted)] && start[strlen(wanted)] != ';'))
    return false;
  if (mutation) {
    char csrf[65];
    if (!web_auth_origin(r) ||
        httpd_req_get_hdr_value_str(r, "X-CSRF-Token", csrf, sizeof(csrf)) !=
            ESP_OK ||
        strlen(csrf) != 64 || !equal(csrf, token, 64))
      return false;
  }
  return true;
}
static esp_err_t issue_session(httpd_req_t *r, char csrf[65]) {
  int64_t now = esp_timer_get_time();
  random_hex(session);
  random_hex(token);
  expires = now + 3600000000LL;
  strcpy(csrf, token);
  /* HTTPD retains this pointer until the handler sends its response. */
  static char cookie[160];
  snprintf(cookie, sizeof(cookie),
           "guard_session=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600",
           session);
  return httpd_resp_set_hdr(r, "Set-Cookie", cookie);
}
esp_err_t web_auth_enroll(httpd_req_t *r, const char *p, char csrf[65]) {
  if (configured)
    return ESP_ERR_INVALID_STATE;
  esp_err_t e = web_auth_set_password(p);
  return e == ESP_OK ? issue_session(r, csrf) : e;
}
esp_err_t web_auth_login(httpd_req_t *r, const char *p, char csrf[65]) {
  int64_t now = esp_timer_get_time();
  if (now - last_login < 2000000)
    return ESP_ERR_TIMEOUT;
  last_login = now;
  if (!configured)
    return ESP_ERR_INVALID_STATE;
  if (strlen(p) > 128)
    return ESP_ERR_INVALID_ARG;
  uint8_t h[32];
  if (!derive(p, salt, h))
    return ESP_FAIL;
  if (!equal(h, password_hash, 32))
    return ESP_ERR_INVALID_ARG;
  return issue_session(r, csrf);
}

void web_auth_logout(void) {
  session[0] = token[0] = 0;
  expires = 0;
}
