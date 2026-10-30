#include "web.h"
#include "cJSON.h"
#include "config.h"
#include "dns.h"
#include "esp_http_server.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "filter_store.h"
#include "firmware_ota.h"
#include "firmware_remote.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "my_rules.h"
#include "network.h"
#include "rule_text.h"
#include "settings.h"
#include "updater.h"
#include "web_auth.h"
#include "web_policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern const char index_start[] asm("_binary_index_html_start"),
    index_end[] asm("_binary_index_html_end");
extern const char css_start[] asm("_binary_styles_css_start"),
    css_end[] asm("_binary_styles_css_end");
extern const char js_start[] asm("_binary_app_js_start"),
    js_end[] asm("_binary_app_js_end");
static uint32_t boot_id;
static esp_err_t json(httpd_req_t *r, cJSON *o) {
  if (!o)
    return httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR,
                               "Allocation failure");
  char *s = cJSON_PrintUnformatted(o);
  cJSON_Delete(o);
  if (!s)
    return httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR,
                               "Allocation failure");
  httpd_resp_set_type(r, "application/json");
  esp_err_t e = httpd_resp_sendstr(r, s);
  free(s);
  return e;
}
static esp_err_t error(httpd_req_t *r, const char *status, const char *code,
                       const char *message) {
  httpd_resp_set_status(r, status);
  cJSON *o = cJSON_CreateObject(), *e = cJSON_AddObjectToObject(o, "error");
  cJSON_AddStringToObject(e, "code", code);
  cJSON_AddStringToObject(e, "message", message);
  return json(r, o);
}
static cJSON *body(httpd_req_t *r) {
  if (r->content_len <= 0 || r->content_len > GUARD_BODY_MAX)
    return NULL;
  char *b = malloc(r->content_len + 1);
  if (!b)
    return NULL;
  size_t pos = 0;
  while (pos < (size_t)r->content_len) {
    int n = httpd_req_recv(r, b + pos, r->content_len - pos);
    if (n <= 0) {
      free(b);
      return NULL;
    }
    pos += n;
  }
  b[pos] = 0;
  if (memchr(b, 0, pos) || strstr(b, "\\u0000")) {
    free(b);
    return NULL;
  }
  cJSON *o = cJSON_ParseWithLengthOpts(b, pos + 1, NULL, true);
  free(b);
  if (!cJSON_IsObject(o)) {
    cJSON_Delete(o);
    return NULL;
  }
  return o;
}
static const char *str(cJSON *o, const char *key) {
  cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
  return cJSON_IsString(v) ? v->valuestring : NULL;
}
static bool copystr(cJSON *o, const char *key, char *out, size_t cap) {
  const char *v = str(o, key);
  if (!v)
    return !cJSON_HasObjectItem(o, key);
  if (strlen(v) >= cap)
    return false;
  strlcpy(out, v, cap);
  return true;
}
static cJSON *ok(void) {
  cJSON *o = cJSON_CreateObject();
  cJSON_AddBoolToObject(o, "ok", true);
  return o;
}
static esp_err_t result(httpd_req_t *r, esp_err_t e) {
  if (e == ESP_OK)
    return json(r, ok());
  return error(r,
               e == ESP_ERR_NO_MEM          ? "507 Insufficient Storage"
               : e == ESP_ERR_INVALID_STATE ? "409 Conflict"
               : e == ESP_ERR_NOT_FOUND     ? "404 Not Found"
                                            : "400 Bad Request",
               esp_err_to_name(e), "Request was not applied");
}
static void reboot(void *unused) {
  (void)unused;
  esp_restart();
}
static void later_reboot(void) {
  esp_timer_handle_t t;
  esp_timer_create_args_t a = {.callback = reboot, .name = "reboot"};
  if (esp_timer_create(&a, &t) == ESP_OK)
    esp_timer_start_once(t, 2000000);
}
static bool setup_request(httpd_req_t *r) {
  struct sockaddr_storage local;
  socklen_t length = sizeof(local);
  uint32_t ap_ip = inet_addr(GUARD_AP_IP);
  if (!network_setup_mode() ||
      getsockname(httpd_req_to_sockfd(r), (struct sockaddr *)&local, &length))
    return false;
  if (local.ss_family == AF_INET)
    return web_setup_address_matches(&((struct sockaddr_in *)&local)->sin_addr,
                                     4, &ap_ip);
  if (local.ss_family == AF_INET6)
    return web_setup_address_matches(
        &((struct sockaddr_in6 *)&local)->sin6_addr, 16, &ap_ip);
  return false;
}
static esp_err_t settings_request(httpd_req_t *r, cJSON *b, bool setup) {
  guard_settings_t s;
  esp_err_t e = guard_settings_load(&s);
  if (e != ESP_OK) {
    if (setup_request(r))
      guard_settings_defaults(&s);
    else
      return result(r, e);
  }
  bool valid =
      copystr(b, "ssid", s.ssid, 33) && copystr(b, "password", s.password, 65);
  if (!setup)
    valid = valid && copystr(b, "ip", s.ip, 16) &&
            copystr(b, "gateway", s.gateway, 16) &&
            copystr(b, "netmask", s.netmask, 16) &&
            copystr(b, "upstream", s.upstream, 16);
  cJSON *v = cJSON_GetObjectItemCaseSensitive(b, "dhcp");
  if (v) {
    if (!cJSON_IsBool(v))
      valid = false;
    else
      s.dhcp = cJSON_IsTrue(v);
  }
  v = cJSON_GetObjectItemCaseSensitive(b, "history");
  if (v) {
    if (!cJSON_IsBool(v))
      valid = false;
    else
      s.history = cJSON_IsTrue(v);
  }
  if (!valid || !guard_settings_validate(&s, false))
    return error(r, "400 Bad Request", "INVALID_SETTINGS",
                 "Invalid network, public upstream, or password");
  e = guard_settings_save(&s);
  if (e != ESP_OK)
    return result(r, e);
  if (setup) {
    e = network_connect(&s);
    if (e != ESP_OK)
      return result(r, e);
  }
  dns_history_enable(s.history);
  httpd_resp_set_status(r, "202 Accepted");
  esp_err_t response = json(r, ok());
  if (!setup)
    later_reboot();
  return response;
}
static bool import_emit(const char *domain, bool allow, void *ctx) {
  esp_err_t *result = ctx;
  *result = my_rules_stage_add(domain, allow);
  return *result == ESP_OK;
}
static esp_err_t import_line(char *line, bool allow) {
  esp_err_t result = ESP_OK;
  if (!rule_text_parse(line, allow, import_emit, &result) && result == ESP_OK)
    return ESP_ERR_INVALID_ARG;
  return result;
}
static esp_err_t import_rules(httpd_req_t *r) {
  if (r->content_len <= 0 || r->content_len > 256000)
    return error(r, "413 Content Too Large", "PAYLOAD_LIMIT",
                 "Rule import is at most 256000 bytes");
  esp_err_t e = my_rules_stage_begin();
  if (e != ESP_OK)
    return result(r, e);
  char buf[512], line[512];
  size_t used = 0, remaining = r->content_len;
  bool allow = false;
  char query[32];
  if (httpd_req_get_url_query_str(r, query, sizeof(query)) == ESP_OK &&
      strstr(query, "action=allow"))
    allow = true;
  while (remaining && e == ESP_OK) {
    int n = httpd_req_recv(r, buf,
                           remaining > sizeof(buf) ? sizeof(buf) : remaining);
    if (n <= 0) {
      e = ESP_FAIL;
      break;
    }
    remaining -= n;
    for (int i = 0; i < n && e == ESP_OK; i++) {
      char c = buf[i];
      if (c == '\r')
        continue;
      if (c != '\n') {
        if (!c || used == sizeof(line) - 1) {
          e = ESP_ERR_INVALID_ARG;
          break;
        }
        line[used++] = c;
        continue;
      }
      line[used] = 0;
      if (used)
        e = import_line(line, allow);
      used = 0;
    }
  }
  if (e == ESP_OK && used) {
    line[used] = 0;
    e = import_line(line, allow);
  }
  if (e == ESP_OK)
    e = my_rules_stage_commit();
  else
    my_rules_stage_abort();
  if (e == ESP_ERR_NO_MEM)
    return error(r, "422 Unprocessable Content", "LIMIT_REACHED",
                 "Maximum 1000 distinct rules; import unchanged");
  return result(r, e);
}
static esp_err_t rules_get(httpd_req_t *r, bool export) {
  size_t count = my_rules_count();
  if (export) {
    httpd_resp_set_type(r, "text/plain");
    httpd_resp_set_hdr(r, "Content-Disposition",
                       "attachment; filename=my-rules.txt");
    for (size_t i = 0; i < count; i++) {
      char name[254], line[280];
      bool allow;
      if (!my_rules_get(i, name, &allow))
        return ESP_FAIL;
      snprintf(line, sizeof(line), "%s %s\n", allow ? "allow" : "block", name);
      if (httpd_resp_sendstr_chunk(r, line) != ESP_OK)
        return ESP_FAIL;
    }
    return httpd_resp_sendstr_chunk(r, NULL);
  }
  char query[64], value[16];
  size_t offset = 0, limit = 100;
  if (httpd_req_get_url_query_str(r, query, sizeof(query)) == ESP_OK) {
    if (httpd_query_key_value(query, "offset", value, sizeof(value)) == ESP_OK)
      offset = strtoul(value, NULL, 10);
    if (httpd_query_key_value(query, "limit", value, sizeof(value)) == ESP_OK)
      limit = strtoul(value, NULL, 10);
  }
  if (limit > 100)
    limit = 100;
  cJSON *o = cJSON_CreateObject(), *items = cJSON_AddArrayToObject(o, "rules");
  cJSON_AddNumberToObject(o, "total", count);
  for (size_t i = offset; i < count && i - offset < limit; i++) {
    char name[254];
    bool allow;
    if (!my_rules_get(i, name, &allow)) {
      cJSON_Delete(o);
      return result(r, ESP_FAIL);
    }
    cJSON *v = cJSON_CreateObject();
    cJSON_AddStringToObject(v, "domain", name);
    cJSON_AddStringToObject(v, "action", allow ? "allow" : "block");
    cJSON_AddItemToArray(items, v);
  }
  return json(r, o);
}
static esp_err_t route(httpd_req_t *r) {
  httpd_resp_set_hdr(r, "Cache-Control", "no-store");
  httpd_resp_set_hdr(r, "X-Content-Type-Options", "nosniff");
  httpd_resp_set_hdr(r, "Content-Security-Policy",
                     "default-src 'self'; connect-src 'self' "
                     GUARD_CATALOG_BASE "/; object-src 'none'; frame-ancestors "
                     "'none'; base-uri 'none'");
  char path[512];
  if (strlen(r->uri) >= sizeof(path))
    return error(r, "414 URI Too Long", "URI_LIMIT", "URI too long");
  strlcpy(path, r->uri, sizeof(path));
  char *query = strchr(path, '?');
  if (query)
    *query = 0;
  if (r->method == HTTP_GET &&
      (!strcmp(path, "/") || !strcmp(path, "/styles.css") ||
       !strcmp(path, "/app.js"))) {
    const char *start = index_start, *end = index_end;
    httpd_resp_set_type(r, "text/html");
    if (!strcmp(path, "/styles.css")) {
      start = css_start;
      end = css_end;
      httpd_resp_set_type(r, "text/css");
    }
    if (!strcmp(path, "/app.js")) {
      start = js_start;
      end = js_end;
      httpd_resp_set_type(r, "application/javascript");
    }
    return httpd_resp_send(r, start, end - start - 1);
  }
  bool mutation = r->method != HTTP_GET;
  if (!strcmp(path, "/api/auth/session") && r->method == HTTP_GET) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddBoolToObject(o, "authenticated", web_auth_require(r, false));
    cJSON_AddBoolToObject(o, "setup", setup_request(r));
    cJSON_AddBoolToObject(o, "configured", web_auth_configured());
    if (web_auth_require(r, false)) {
      char ip[16];
      network_ip(ip);
      cJSON_AddBoolToObject(o, "wifi", network_ready());
      cJSON_AddBoolToObject(o, "wifiConfigured", network_has_credentials());
      cJSON_AddStringToObject(o, "ip", ip);
    }
    return json(r, o);
  }
  if (!strcmp(path, "/api/auth/login") && r->method == HTTP_POST) {
    if (!web_auth_origin(r))
      return error(r, "403 Forbidden", "ORIGIN", "Same-origin login required");
    cJSON *b = body(r);
    const char *p = str(b, "password");
    char token[65];
    esp_err_t e = p ? web_auth_login(r, p, token) : ESP_ERR_INVALID_ARG;
    cJSON_Delete(b);
    if (e == ESP_ERR_TIMEOUT) {
      httpd_resp_set_hdr(r, "Retry-After", "2");
      return error(r, "429 Too Many Requests", "LOGIN_THROTTLED",
                   "Vui lòng chờ 2 giây rồi thử đăng nhập lại.");
    }
    if (e == ESP_ERR_INVALID_STATE)
      return error(r, "409 Conflict", "ADMIN_NOT_CONFIGURED",
                   "Chưa thiết lập admin. Kết nối AP để thiết lập lần đầu.");
    if (e != ESP_OK && e != ESP_ERR_INVALID_ARG)
      return error(r, "500 Internal Server Error", "LOGIN_ERROR",
                   "Thiết bị không xử lý được đăng nhập. Vui lòng thử lại.");
    if (e != ESP_OK)
      return error(r, "401 Unauthorized", "LOGIN_FAILED",
                   "Mật khẩu admin không đúng.");
    cJSON *o = ok();
    cJSON_AddStringToObject(o, "csrf", token);
    return json(r, o);
  }
  if (!strcmp(path, "/api/setup/admin") && r->method == HTTP_POST) {
    if (!setup_request(r) || !web_auth_origin(r) || web_auth_configured())
      return error(r, "403 Forbidden", "SETUP_LOCKED",
                   "Admin enrollment is only available once on the setup AP");
    cJSON *b = body(r);
    const char *password = str(b, "password");
    char token[65];
    esp_err_t e =
        password ? web_auth_enroll(r, password, token) : ESP_ERR_INVALID_ARG;
    cJSON_Delete(b);
    if (e != ESP_OK)
      return result(r, e);
    cJSON *o = ok();
    cJSON_AddStringToObject(o, "csrf", token);
    return json(r, o);
  }
  if (!strcmp(path, "/api/setup/scan") && r->method == HTTP_POST) {
    if (!setup_request(r) || !web_auth_require(r, true))
      return error(r, "403 Forbidden", "SETUP_LOCKED",
                   "Log in on the setup AP to scan Wi-Fi");
    network_ap_t networks[16];
    unsigned count;
    esp_err_t e = network_scan(networks, 16, &count);
    if (e != ESP_OK)
      return result(r, e);
    cJSON *o = cJSON_CreateObject(),
          *items = cJSON_AddArrayToObject(o, "networks");
    for (unsigned i = 0; i < count; i++) {
      cJSON *item = cJSON_CreateObject();
      cJSON_AddStringToObject(item, "ssid", networks[i].ssid);
      cJSON_AddNumberToObject(item, "signal", networks[i].signal);
      cJSON_AddBoolToObject(item, "secured", networks[i].secured);
      cJSON_AddItemToArray(items, item);
    }
    return json(r, o);
  }
  if (!strcmp(path, "/api/setup") && r->method == HTTP_POST) {
    if (!setup_request(r) || !web_auth_require(r, true))
      return error(r, "403 Forbidden", "SETUP_LOCKED",
                   "Log in on the setup AP before connecting router Wi-Fi");
    cJSON *b = body(r);
    if (!cJSON_IsObject(b)) {
      cJSON_Delete(b);
      return error(r, "400 Bad Request", "INVALID_BODY",
                   "JSON object required");
    }
    for (cJSON *item = b->child; item; item = item->next) {
      if (strcmp(item->string, "ssid") && strcmp(item->string, "password") &&
          strcmp(item->string, "dhcp")) {
        cJSON_Delete(b);
        return error(r, "400 Bad Request", "WIFI_FIELDS_ONLY",
                     "Use Settings for IP, upstream or other configuration");
      }
    }
    cJSON *dhcp = cJSON_GetObjectItemCaseSensitive(b, "dhcp");
    if (!cJSON_IsTrue(dhcp)) {
      cJSON_Delete(b);
      return error(r, "400 Bad Request", "DHCP_REQUIRED",
                   "Initial setup uses router DHCP");
    }
    esp_err_t e = settings_request(r, b, true);
    cJSON_Delete(b);
    return e;
  }
  if (!web_auth_require(r, mutation))
    return error(r, mutation ? "403 Forbidden" : "401 Unauthorized",
                 "AUTH_REQUIRED", "Login and same-origin CSRF token required");
  if (!strcmp(path, "/api/auth/logout") && r->method == HTTP_POST) {
    web_auth_logout();
    httpd_resp_set_hdr(
        r, "Set-Cookie",
        "guard_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    return json(r, ok());
  }
  if (!strcmp(path, "/api/status") && r->method == HTTP_GET) {
    cJSON *o = cJSON_CreateObject();
    char ip[16];
    network_ip(ip);
    cJSON_AddStringToObject(o, "firmware", GUARD_VERSION);
    cJSON_AddStringToObject(o, "otaState", firmware_ota_state());
    char build[65];
    firmware_ota_build(build);
    cJSON_AddStringToObject(o, "build", build);
    cJSON_AddNumberToObject(o, "bootId", boot_id);
    cJSON_AddStringToObject(o, "ip", ip);
    cJSON_AddNumberToObject(o, "uptimeSeconds", esp_timer_get_time() / 1000000);
    cJSON_AddNumberToObject(o, "heap", esp_get_free_heap_size());
    cJSON_AddNumberToObject(o, "minHeap", esp_get_minimum_free_heap_size());
    cJSON_AddBoolToObject(o, "wifi", network_ready());
    cJSON_AddBoolToObject(o, "dns", dns_is_ready());
    cJSON_AddBoolToObject(o, "store", filter_store_ready());
    return json(r, o);
  }
  if (!strcmp(path, "/api/stats") && r->method == HTTP_GET) {
    dns_totals_t totals;
    dns_totals(&totals);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "total", totals.total);
    cJSON_AddNumberToObject(o, "blocked", totals.blocked);
    cJSON_AddNumberToObject(o, "cacheHits", totals.cached);
    cJSON_AddNumberToObject(o, "errors", totals.errors);
    return json(r, o);
  }
  if (!strcmp(path, "/api/queries") && r->method == HTTP_GET) {
    unsigned limit = 100;
    char query[64], value[16];
    if (httpd_req_get_url_query_str(r, query, sizeof(query)) == ESP_OK &&
        httpd_query_key_value(query, "limit", value, sizeof(value)) == ESP_OK)
      limit = strtoul(value, NULL, 10);
    if (limit > GUARD_QUERY_MAX)
      limit = GUARD_QUERY_MAX;
    httpd_resp_set_type(r, "application/json");
    if (httpd_resp_sendstr_chunk(r, "{\"queries\":[") != ESP_OK)
      return ESP_FAIL;
    for (unsigned i = 0; i < limit; i++) {
      query_event_t event;
      if (!dns_recent(&event, i, 1))
        break;
      cJSON *o = cJSON_CreateObject();
      if (!o)
        return ESP_FAIL;
      cJSON_AddStringToObject(o, "domain", event.domain);
      cJSON_AddStringToObject(o, "client", event.client);
      cJSON_AddNumberToObject(o, "type", event.qtype);
      cJSON_AddNumberToObject(o, "outcome", event.outcome);
      cJSON_AddNumberToObject(o, "whenMs", event.when_ms);
      char *encoded = cJSON_PrintUnformatted(o);
      cJSON_Delete(o);
      if (!encoded)
        return ESP_FAIL;
      esp_err_t e = i ? httpd_resp_sendstr_chunk(r, ",") : ESP_OK;
      if (e == ESP_OK)
        e = httpd_resp_sendstr_chunk(r, encoded);
      free(encoded);
      if (e != ESP_OK)
        return e;
    }
    if (httpd_resp_sendstr_chunk(r, "]}") != ESP_OK)
      return ESP_FAIL;
    return httpd_resp_sendstr_chunk(r, NULL);
  }
  if (!strcmp(path, "/api/settings") && r->method == HTTP_GET) {
    guard_settings_t s;
    esp_err_t e = guard_settings_load(&s);
    if (e != ESP_OK)
      return result(r, e);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "ssid", s.ssid);
    cJSON_AddStringToObject(o, "ip", s.ip);
    cJSON_AddStringToObject(o, "gateway", s.gateway);
    cJSON_AddStringToObject(o, "netmask", s.netmask);
    cJSON_AddStringToObject(o, "upstream", s.upstream);
    cJSON_AddBoolToObject(o, "dhcp", s.dhcp);
    cJSON_AddBoolToObject(o, "history", s.history);
    char ip[16], gateway[16], netmask[16];
    if (network_addresses(ip, gateway, netmask)) {
      cJSON *current = cJSON_AddObjectToObject(o, "currentNetwork");
      if (!current || !cJSON_AddStringToObject(current, "ip", ip) ||
          !cJSON_AddStringToObject(current, "gateway", gateway) ||
          !cJSON_AddStringToObject(current, "netmask", netmask)) {
        cJSON_Delete(o);
        return json(r, NULL);
      }
    }
    return json(r, o);
  }
  if (!strcmp(path, "/api/settings") && r->method == HTTP_PUT) {
    cJSON *b = body(r);
    if (!b)
      return result(r, ESP_ERR_INVALID_ARG);
    esp_err_t e = settings_request(r, b, false);
    cJSON_Delete(b);
    return e;
  }
  if (!strcmp(path, "/api/my-rules") && r->method == HTTP_GET)
    return rules_get(r, false);
  if (!strcmp(path, "/api/my-rules/export") && r->method == HTTP_GET)
    return rules_get(r, true);
  if (!strcmp(path, "/api/my-rules/import") && r->method == HTTP_POST)
    return import_rules(r);
  if (!strcmp(path, "/api/my-rules") && r->method == HTTP_POST) {
    cJSON *b = body(r);
    const char *d = str(b, "domain"), *a = str(b, "action");
    esp_err_t e = d && a && (!strcmp(a, "allow") || !strcmp(a, "block"))
                      ? my_rules_mutate(NULL, d, !strcmp(a, "allow"))
                      : ESP_ERR_INVALID_ARG;
    cJSON_Delete(b);
    if (e == ESP_ERR_NO_MEM)
      return error(r, "422 Unprocessable Content", "LIMIT_REACHED",
                   "Maximum 1000 distinct rules");
    return result(r, e);
  }
  if (!strncmp(path, "/api/my-rules/", 14) &&
      (r->method == HTTP_DELETE || r->method == HTTP_PUT)) {
    const char *old = path + 14;
    if (r->method == HTTP_DELETE)
      return result(r, my_rules_mutate(old, NULL, false));
    cJSON *b = body(r);
    const char *d = str(b, "domain"), *a = str(b, "action");
    esp_err_t e = d && a && (!strcmp(a, "allow") || !strcmp(a, "block"))
                      ? my_rules_mutate(old, d, !strcmp(a, "allow"))
                      : ESP_ERR_INVALID_ARG;
    cJSON_Delete(b);
    return result(r, e);
  }
  if (!strcmp(path, "/api/filters") && r->method == HTTP_GET) {
    cJSON *o = updater_catalog();
    if (!o)
      return json(r, NULL);
    cJSON *installed = filter_store_json();
    if (!installed || !cJSON_AddItemToObject(o, "installed", installed)) {
      cJSON_Delete(installed);
      cJSON_Delete(o);
      return json(r, NULL);
    }
    cJSON *job = updater_json();
    if (!job || !cJSON_AddItemToObject(o, "job", job)) {
      cJSON_Delete(job);
      cJSON_Delete(o);
      return json(r, NULL);
    }
    if (!cJSON_AddNumberToObject(o, "maxInstalled", GUARD_FILTER_INSTALLED_MAX)) {
      cJSON_Delete(o);
      return json(r, NULL);
    }
    return json(r, o);
  }
  if (!strncmp(path, "/api/jobs/", 10) && r->method == HTTP_GET)
    return json(r, updater_json());
  if (!strcmp(path, "/api/filters/check-updates") && r->method == HTTP_POST) {
    esp_err_t e = updater_submit("check", NULL);
    if (e == ESP_OK) {
      httpd_resp_set_status(r, "202 Accepted");
      return json(r, updater_json());
    }
    return result(r, e);
  }
  if (!strcmp(path, "/api/filters/apply-updates") && r->method == HTTP_POST) {
    esp_err_t e = updater_submit("apply", NULL);
    if (e == ESP_OK) {
      httpd_resp_set_status(r, "202 Accepted");
      return json(r, updater_json());
    }
    return result(r, e);
  }
  if (!strcmp(path, "/api/filters/install") && r->method == HTTP_POST) {
    cJSON *b = body(r);
    const char *id = str(b, "id");
    esp_err_t e = id ? updater_submit("install", id) : ESP_ERR_INVALID_ARG;
    cJSON_Delete(b);
    if (e == ESP_OK) {
      httpd_resp_set_status(r, "202 Accepted");
      return json(r, updater_json());
    }
    return result(r, e);
  }
  if (!strncmp(path, "/api/filters/", 13) &&
      (r->method == HTTP_PUT || r->method == HTTP_DELETE)) {
    if (!updater_flash_lock())
      return result(r, ESP_ERR_INVALID_STATE);
    esp_err_t e;
    if (r->method == HTTP_DELETE)
      e = filter_store_remove(path + 13);
    else {
      cJSON *b = body(r), *v = cJSON_GetObjectItemCaseSensitive(b, "enabled");
      e = cJSON_IsBool(v) ? filter_store_toggle(path + 13, cJSON_IsTrue(v))
                          : ESP_ERR_INVALID_ARG;
      cJSON_Delete(b);
    }
    updater_flash_unlock();
    return result(r, e);
  }
  if (!strcmp(path, "/api/ota/release") && r->method == HTTP_GET) {
    cJSON *o = firmware_remote_json();
    cJSON *job = o ? updater_json() : NULL;
    if (!job || !cJSON_AddItemToObject(o, "job", job)) {
      cJSON_Delete(job);
      cJSON_Delete(o);
      return json(r, NULL);
    }
    return json(r, o);
  }
  if (!strcmp(path, "/api/ota/check") && r->method == HTTP_POST)
    return result(r, updater_submit("ota-check", NULL));
  if (!strcmp(path, "/api/ota/install") && r->method == HTTP_POST) {
    cJSON *b = body(r);
    const char *build = str(b, "build");
    esp_err_t e = build ? updater_submit("ota-install", build) : ESP_ERR_INVALID_ARG;
    cJSON_Delete(b);
    return result(r, e);
  }
  if (!strcmp(path, "/api/ota/firmware") && r->method == HTTP_POST)
    return firmware_ota_upload(r);
  if (!strcmp(path, "/api/system/reboot") && r->method == HTTP_POST) {
    esp_err_t e = json(r, ok());
    later_reboot();
    return e;
  }
  return error(r, "404 Not Found", "NOT_FOUND", "Unknown API route");
}
esp_err_t web_start(void) {
  boot_id = esp_random();
  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  config.stack_size = 12288;
  config.max_uri_handlers = 8;
  config.max_open_sockets = 3;
  config.uri_match_fn = httpd_uri_match_wildcard;
  config.lru_purge_enable = true;
  httpd_handle_t server;
  esp_err_t e = httpd_start(&server, &config);
  if (e != ESP_OK)
    return e;
  httpd_method_t methods[] = {HTTP_GET, HTTP_POST, HTTP_PUT, HTTP_DELETE};
  for (unsigned i = 0; i < 4; i++) {
    httpd_uri_t uri = {.uri = "/*", .method = methods[i], .handler = route};
    e = httpd_register_uri_handler(server, &uri);
    if (e != ESP_OK) {
      httpd_stop(server);
      return e;
    }
  }
  return ESP_OK;
}
