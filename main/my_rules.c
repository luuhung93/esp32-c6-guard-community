#include "my_rules.h"
#include "domain.h"
#include "guard_hash.h"
#include <string.h>
#ifdef ESP_PLATFORM
#include "dns.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include <stdio.h>
#include <stdlib.h>
static rule_index_t *active, *staged;
static size_t count, staged_count;
static unsigned generation;
static bool staging;
static nvs_handle_t target;
static SemaphoreHandle_t mutex, writer;
static void key(char out[16], size_t n) {
  snprintf(out, 16, "r%u", (unsigned)n);
}
static esp_err_t open_gen(unsigned gen, nvs_open_mode_t mode, nvs_handle_t *h) {
  return nvs_open(gen ? "rules1" : "rules0", mode, h);
}
static bool record_valid(const char *buf, size_t len) {
  char canonical[254];
  return len >= 3 && len <= 255 && !buf[len - 1] &&
         (unsigned char)buf[0] <= 1 &&
         guard_domain_normalize(buf + 1, len - 2, canonical) == DOMAIN_OK &&
         !strcmp(canonical, buf + 1);
}
esp_err_t my_rules_init(void) {
  mutex = xSemaphoreCreateMutex();
  writer = xSemaphoreCreateMutex();
  active = calloc(GUARD_RULE_MAX, sizeof(*active));
  if (!mutex || !writer || !active)
    return ESP_ERR_NO_MEM;
  nvs_handle_t h;
  bool selector_present = false;
  esp_err_t e = nvs_open("guard", NVS_READONLY, &h);
  uint8_t g = 0;
  if (e == ESP_OK) {
    e = nvs_get_u8(h, "rulesgen", &g);
    nvs_close(h);
    if (e != ESP_OK && e != ESP_ERR_NVS_NOT_FOUND)
      return e;
    if (g > 1)
      return ESP_ERR_INVALID_STATE;
    selector_present = e == ESP_OK;
  } else if (e != ESP_ERR_NVS_NOT_FOUND)
    return e;
  generation = g ? 1 : 0;
  e = open_gen(generation, NVS_READONLY, &h);
  if (e == ESP_ERR_NVS_NOT_FOUND)
    return selector_present ? ESP_ERR_INVALID_STATE : ESP_OK;
  if (e != ESP_OK)
    return e;
  uint16_t n = 0;
  e = nvs_get_u16(h, "count", &n);
  if (e == ESP_ERR_NVS_NOT_FOUND) {
    nvs_close(h);
    return selector_present ? ESP_ERR_INVALID_STATE : ESP_OK;
  }
  if (e != ESP_OK || n > GUARD_RULE_MAX) {
    nvs_close(h);
    return ESP_ERR_INVALID_STATE;
  }
  for (unsigned i = 0; i < n; i++) {
    char k[16], buf[256];
    size_t len = sizeof(buf);
    key(k, i);
    e = nvs_get_blob(h, k, buf, &len);
    if (e != ESP_OK || !record_valid(buf, len)) {
      nvs_close(h);
      return ESP_ERR_INVALID_STATE;
    }
    active[i] = (rule_index_t){.hash = guard_domain_hash(buf + 1, len - 2),
                               .slot = i,
                               .allow = buf[0]};
  }
  count = n;
  nvs_close(h);
  return ESP_OK;
}
size_t my_rules_count(void) {
  xSemaphoreTake(mutex, portMAX_DELAY);
  size_t n = count;
  xSemaphoreGive(mutex);
  return n;
}
bool my_rules_get(size_t i, char domain[254], bool *allow) {
  xSemaphoreTake(mutex, portMAX_DELAY);
  bool ok = false;
  if (i < count) {
    nvs_handle_t h;
    if (open_gen(generation, NVS_READONLY, &h) == ESP_OK) {
      char k[16], buf[256];
      size_t len = sizeof(buf);
      key(k, i);
      if (nvs_get_blob(h, k, buf, &len) == ESP_OK && record_valid(buf, len)) {
        strcpy(domain, buf + 1);
        *allow = buf[0];
        ok = true;
      }
      nvs_close(h);
    }
  }
  xSemaphoreGive(mutex);
  return ok;
}
rule_result_t my_rules_lookup(const char *name) {
  xSemaphoreTake(mutex, portMAX_DELAY);
  rule_result_t result = RULE_NONE;
  for (const char *s = name; *s;) {
    uint64_t hash = guard_domain_hash(s, strlen(s));
    for (size_t i = 0; i < count; i++)
      if (active[i].hash == hash) {
        nvs_handle_t h;
        if (open_gen(generation, NVS_READONLY, &h) == ESP_OK) {
          char k[16], buf[256];
          size_t n = sizeof(buf);
          key(k, active[i].slot);
          if (nvs_get_blob(h, k, buf, &n) == ESP_OK && record_valid(buf, n) &&
              !strcmp(buf + 1, s))
            result = active[i].allow ? RULE_ALLOW : RULE_BLOCK;
          nvs_close(h);
        }
        if (result != RULE_NONE)
          break;
      }
    if (result != RULE_NONE)
      break;
    const char *d = strchr(s, '.');
    if (!d)
      break;
    s = d + 1;
  }
  xSemaphoreGive(mutex);
  return result;
}
esp_err_t my_rules_stage_begin(void) {
  if (!xSemaphoreTake(writer, 0))
    return ESP_ERR_INVALID_STATE;
  staged = calloc(GUARD_RULE_MAX, sizeof(*staged));
  if (!staged) {
    xSemaphoreGive(writer);
    return ESP_ERR_NO_MEM;
  }
  target = 0;
  esp_err_t e = open_gen(!generation, NVS_READWRITE, &target);
  if (e == ESP_OK)
    e = nvs_erase_all(target);
  if (e != ESP_OK) {
    if (target)
      nvs_close(target);
    free(staged);
    staged = NULL;
    xSemaphoreGive(writer);
    return e;
  }
  staged_count = 0;
  staging = true;
  return ESP_OK;
}
esp_err_t my_rules_stage_add(const char *domain, bool allow) {
  char name[254];
  if (!staging ||
      guard_domain_normalize(domain, strlen(domain), name) != DOMAIN_OK)
    return ESP_ERR_INVALID_ARG;
  uint64_t hash = guard_domain_hash(name, strlen(name));
  size_t slot = staged_count;
  for (size_t i = 0; i < staged_count; i++)
    if (staged[i].hash == hash) {
      char k[16], buf[256];
      size_t n = sizeof(buf);
      key(k, i);
      esp_err_t e = nvs_get_blob(target, k, buf, &n);
      if (e != ESP_OK)
        return e;
      if (!record_valid(buf, n))
        return ESP_ERR_INVALID_STATE;
      if (!strcmp(buf + 1, name)) {
        slot = i;
        break;
      }
    }
  if (slot == staged_count && staged_count == GUARD_RULE_MAX)
    return ESP_ERR_NO_MEM;
  char k[16], buf[256];
  key(k, slot);
  buf[0] = allow;
  strcpy(buf + 1, name);
  esp_err_t e = nvs_set_blob(target, k, buf, strlen(name) + 2);
  if (e == ESP_OK) {
    staged[slot] = (rule_index_t){hash, slot, allow};
    if (slot == staged_count)
      staged_count++;
  }
  if (staged_count % 32 == 0)
    vTaskDelay(1);
  return e;
}
void my_rules_stage_abort(void) {
  if (!staging)
    return;
  nvs_close(target);
  target = 0;
  free(staged);
  staged = NULL;
  staging = false;
  xSemaphoreGive(writer);
}
esp_err_t my_rules_stage_commit(void) {
  if (!staging)
    return ESP_ERR_INVALID_STATE;
  esp_err_t e = nvs_set_u16(target, "count", staged_count);
  if (e == ESP_OK)
    e = nvs_commit(target);
  nvs_handle_t h;
  if (e == ESP_OK) {
    e = nvs_open("guard", NVS_READWRITE, &h);
    if (e == ESP_OK) {
      e = nvs_set_u8(h, "rulesgen", !generation);
      if (e == ESP_OK)
        e = nvs_commit(h);
      nvs_close(h);
    }
  }
  if (e == ESP_OK) {
    xSemaphoreTake(mutex, portMAX_DELAY);
    rule_index_t *old = active;
    active = staged;
    staged = old;
    count = staged_count;
    generation = !generation;
    dns_policy_changed();
    xSemaphoreGive(mutex);
  }
  my_rules_stage_abort();
  return e;
}
esp_err_t my_rules_mutate(const char *old, const char *name, bool allow) {
  esp_err_t e = my_rules_stage_begin();
  if (e != ESP_OK)
    return e;
  size_t n = my_rules_count();
  for (size_t i = 0; i < n && e == ESP_OK; i++) {
    char d[254];
    bool a;
    if (!my_rules_get(i, d, &a)) {
      e = ESP_FAIL;
      break;
    }
    if (old && !strcmp(old, d))
      continue;
    if (name && !strcmp(name, d))
      continue;
    e = my_rules_stage_add(d, a);
  }
  if (e == ESP_OK && name)
    e = my_rules_stage_add(name, allow);
  if (e == ESP_OK)
    return my_rules_stage_commit();
  my_rules_stage_abort();
  return e;
}
#endif
