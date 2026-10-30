#include "network.h"
#include "config.h"
#include "driver/gpio.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "status_led.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
static esp_netif_t *station;
static _Atomic bool ready, setup, has_credentials;
static esp_timer_handle_t setup_timer;
static char address[16] = "0.0.0.0";
static unsigned retry;
static char resolver[16];
static wifi_config_t station_config(const guard_settings_t *s) {
  wifi_config_t config = {0};
  /* Fast scan can stop at a distant AP before finding the nearby same-SSID AP. */
  config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
  config.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
  memcpy(config.sta.ssid, s->ssid, strlen(s->ssid));
  strlcpy((char *)config.sta.password, s->password, sizeof(config.sta.password));
  return config;
}
static void set_resolver(void) {
  esp_netif_dns_info_t dns = {0};
  dns.ip.type = ESP_IPADDR_TYPE_V4;
  dns.ip.u_addr.ip4.addr = inet_addr(resolver);
  esp_err_t e = esp_netif_set_dns_info(station, ESP_NETIF_DNS_MAIN, &dns);
  if (e != ESP_OK)
    ESP_LOGE("network", "Resolver setup failed: %s", esp_err_to_name(e));
}
static esp_err_t configure_address(const guard_settings_t *s) {
  if (s->dhcp) {
    esp_err_t e = esp_netif_dhcpc_start(station);
    return e == ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED ? ESP_OK : e;
  }
  esp_netif_ip_info_t info = {0};
  if (inet_pton(AF_INET, s->ip, &info.ip) != 1 ||
      inet_pton(AF_INET, s->gateway, &info.gw) != 1 ||
      inet_pton(AF_INET, s->netmask, &info.netmask) != 1)
    return ESP_ERR_INVALID_ARG;
  esp_err_t e = esp_netif_dhcpc_stop(station);
  if (e != ESP_OK && e != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED)
    return e;
  return esp_netif_set_ip_info(station, &info);
}
bool network_upstream_safe(const char *ip) {
  if (!guard_public_ipv4(ip))
    return false;
  esp_netif_ip_info_t info;
  if (!station || esp_netif_get_ip_info(station, &info) != ESP_OK)
    return false;
  uint32_t target = inet_addr(ip);
  return target != info.ip.addr && target != info.gw.addr &&
         (!info.netmask.addr ||
          (target & info.netmask.addr) != (info.ip.addr & info.netmask.addr));
}
static void reconnect(void *unused) {
  (void)unused;
  if (has_credentials)
    esp_wifi_connect();
}
static esp_timer_handle_t retry_timer;
static void events(void *arg, esp_event_base_t base, int32_t id, void *data) {
  (void)arg;
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START && has_credentials)
    esp_wifi_connect();
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
    wifi_event_sta_disconnected_t *event = data;
    ESP_LOGW("network", "Station disconnected: reason=%u", event->reason);
    ready = false;
    status_led_set(LED_CONNECTED, false);
    unsigned delay = 1u << (retry < 5 ? retry++ : 5);
    esp_timer_stop(retry_timer);
    if (has_credentials)
      esp_timer_start_once(retry_timer, (uint64_t)delay * 1000000);
  }
  if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t *e = data;
    snprintf(address, 16, IPSTR, IP2STR(&e->ip_info.ip));
    set_resolver();
    ready = true;
    status_led_set(LED_CONNECTED, true);
    esp_timer_stop(retry_timer);
    if (setup && setup_timer) {
      esp_timer_stop(setup_timer);
      esp_timer_start_once(setup_timer, 120000000);
    }
    retry = 0;
    ESP_LOGI("network", "DNS/admin IP %s", address);
  }
}
static void recovery_button(void *unused) {
  (void)unused;
  unsigned held = 0, offline = 0;
  for (;;) {
    held = gpio_get_level(GUARD_BOOT_GPIO) ? 0 : held + 1;
    if (held == 30)
      network_request_setup();
    offline = ready ? 0 : offline + 1;
    if (offline >= 300 && !setup)
      network_request_setup();
    vTaskDelay(pdMS_TO_TICKS(100));
  }
}
static esp_err_t start_ap(void) {
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
  wifi_config_t ap = {0};
  snprintf((char *)ap.ap.ssid, 32, "C6-Guard-%02X%02X%02X", mac[3], mac[4],
           mac[5]);
  const char *join_key = CONFIG_GUARD_SETUP_AP_PASSWORD;
  if (strlen(join_key) < 8 || strlen(join_key) > 63)
    return ESP_ERR_INVALID_ARG;
  strlcpy((char *)ap.ap.password, join_key, sizeof(ap.ap.password));
  ap.ap.ssid_len = strlen((char *)ap.ap.ssid);
  ap.ap.max_connection = 2;
  ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
  ap.ap.channel = 1;
  esp_err_t e = esp_wifi_set_mode(WIFI_MODE_APSTA);
  if (e != ESP_OK)
    return e;
  e = esp_wifi_set_config(WIFI_IF_AP, &ap);
  if (e == ESP_OK) {
    setup = true;
    status_led_set(LED_SETUP, true);
    ESP_LOGI("setup",
             "Setup at http://" GUARD_AP_IP "; waiting for router Wi-Fi");
  }
  return e;
}
static void ap_timeout(void *unused) {
  (void)unused;
  if (!ready)
    return;
  if (esp_wifi_set_mode(WIFI_MODE_STA) == ESP_OK) {
    setup = false;
    status_led_set(LED_SETUP, false);
  }
}
void network_request_setup(void) {
  if (start_ap() != ESP_OK)
    return;
  esp_timer_stop(setup_timer);
  if (ready)
    esp_timer_start_once(setup_timer, 120000000);
}
bool network_has_credentials(void) { return has_credentials; }
esp_err_t network_connect(const guard_settings_t *s) {
  if (!guard_settings_validate(s, false) || !s->dhcp)
    return ESP_ERR_INVALID_ARG;
  wifi_config_t sta = station_config(s);
  has_credentials = false;
  ready = false;
  status_led_set(LED_CONNECTED, false);
  esp_timer_stop(retry_timer);
  esp_wifi_disconnect();
  esp_err_t e = configure_address(s);
  if (e != ESP_OK)
    return e;
  e = esp_wifi_set_config(WIFI_IF_STA, &sta);
  if (e == ESP_OK) {
    strlcpy(resolver, s->upstream, sizeof(resolver));
    has_credentials = true;
    retry = 0;
    e = esp_wifi_connect();
  }
  return e;
}
esp_err_t network_scan(network_ap_t *out, unsigned capacity, unsigned *count) {
  if (!setup || !out || !count || !capacity || capacity > 16)
    return ESP_ERR_INVALID_ARG;
  *count = 0;
  wifi_ap_record_t *records = calloc(capacity, sizeof(*records));
  if (!records)
    return ESP_ERR_NO_MEM;
  bool paused = has_credentials && !ready;
  if (paused) {
    has_credentials = false;
    esp_timer_stop(retry_timer);
    esp_wifi_disconnect();
  }
  wifi_scan_config_t cfg = {.show_hidden = false};
  esp_err_t e = esp_wifi_scan_start(&cfg, true);
  uint16_t found = capacity;
  if (e == ESP_OK)
    e = esp_wifi_scan_get_ap_records(&found, records);
  if (e == ESP_OK)
    for (unsigned i = 0; i < found; i++) {
      if (!records[i].ssid[0])
        continue;
      bool duplicate = false;
      for (unsigned j = 0; j < *count; j++)
        duplicate |= !strcmp(out[j].ssid, (char *)records[i].ssid);
      if (duplicate)
        continue;
      network_ap_t *ap = &out[(*count)++];
      memcpy(ap->ssid, records[i].ssid, 32);
      ap->ssid[32] = 0;
      ap->signal = records[i].rssi;
      ap->secured = records[i].authmode != WIFI_AUTH_OPEN;
    }
  free(records);
  if (paused) {
    has_credentials = true;
    esp_err_t retry_error = esp_wifi_connect();
    if (retry_error != ESP_OK)
      ESP_LOGW("network", "Reconnect after scan: %s",
               esp_err_to_name(retry_error));
  }
  return e;
}
esp_err_t network_start(const guard_settings_t *s) {
  strlcpy(resolver, s->upstream, sizeof(resolver));
  has_credentials = s->ssid[0] != 0;
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  station = esp_netif_create_default_wifi_sta();
  esp_netif_t *ap = esp_netif_create_default_wifi_ap();
  if (!station || !ap)
    return ESP_ERR_NO_MEM;
  ESP_ERROR_CHECK(esp_netif_set_hostname(station, "c6-guard"));
  esp_netif_dhcps_stop(ap);
  esp_netif_ip_info_t ap_ip = {0};
  inet_pton(AF_INET, GUARD_AP_IP, &ap_ip.ip);
  ap_ip.gw = ap_ip.ip;
  inet_pton(AF_INET, "255.255.255.0", &ap_ip.netmask);
  ESP_ERROR_CHECK(esp_netif_set_ip_info(ap, &ap_ip));
  esp_netif_dns_info_t ap_dns = {.ip.type = ESP_IPADDR_TYPE_V4};
  ap_dns.ip.u_addr.ip4 = ap_ip.ip;
  ESP_ERROR_CHECK(esp_netif_set_dns_info(ap, ESP_NETIF_DNS_MAIN, &ap_dns));
  esp_timer_create_args_t ap_clock = {.callback = ap_timeout,
                                      .name = "setup-timeout"};
  ESP_ERROR_CHECK(esp_timer_create(&ap_clock, &setup_timer));
  esp_timer_create_args_t t = {.callback = reconnect, .name = "wifi-retry"};
  ESP_ERROR_CHECK(esp_timer_create(&t, &retry_timer));
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(
      esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, events, NULL));
  ESP_ERROR_CHECK(
      esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, events, NULL));
  wifi_config_t sta = station_config(s);
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta));
  esp_err_t e = configure_address(s);
  if (e != ESP_OK)
    return e;
  set_resolver();
  ESP_ERROR_CHECK(esp_wifi_start());
  /* A mains-powered DNS server must receive packets between DTIM beacons. */
  ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
  gpio_config_t g = {.pin_bit_mask = 1ULL << GUARD_BOOT_GPIO,
                     .mode = GPIO_MODE_INPUT,
                     .pull_up_en = GPIO_PULLUP_ENABLE};
  ESP_ERROR_CHECK(gpio_config(&g));
  xTaskCreate(recovery_button, "recovery", 2048, NULL, 2, NULL);
  if (!s->ssid[0] || !gpio_get_level(GUARD_BOOT_GPIO))
    network_request_setup();
  esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
  esp_sntp_setservername(0, "pool.ntp.org");
  esp_sntp_init();
  return ESP_OK;
}
bool network_ready(void) { return ready; }
bool network_setup_mode(void) { return setup; }
void network_ip(char out[16]) { strlcpy(out, address, 16); }

bool network_addresses(char ip[16], char gateway[16], char netmask[16]) {
  esp_netif_ip_info_t info;
  if (!ready || !station || esp_netif_get_ip_info(station, &info) != ESP_OK ||
      !info.ip.addr)
    return false;
  snprintf(ip, 16, IPSTR, IP2STR(&info.ip));
  snprintf(gateway, 16, IPSTR, IP2STR(&info.gw));
  snprintf(netmask, 16, IPSTR, IP2STR(&info.netmask));
  return true;
}
