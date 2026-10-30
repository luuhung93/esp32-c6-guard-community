#include "filter_store.h"
#include "config.h"
#include "dns.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "guard_hash.h"
#include "nvs.h"
#include "wear_levelling.h"
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef struct {
  char id[64], digest[65];
  bool enabled;
} entry_t;
typedef struct {
  entry_t entry;
  filter_meta_t meta;
  FILE *file;
} loaded_t;
static loaded_t lists[GUARD_FILTER_MAX];
static size_t count;
static bool mounted;
static bool has_state;
static bool recovered;
static SemaphoreHandle_t mutex;
static wl_handle_t wl = WL_INVALID_HANDLE;
#define MATCH_CACHE_MAX 64
static struct {
  char name[254];
  bool hit;
} matches[MATCH_CACHE_MAX];
static unsigned match_next;
static void filename(char out[192], const char *digest) {
  snprintf(out, 192, GUARD_STORE "/%s.bin", digest);
}
static bool digest_valid(const char *s) {
  if (strlen(s) != 64)
    return false;
  for (unsigned i = 0; i < 64; i++)
    if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
      return false;
  return true;
}
typedef struct {
  uint32_t count;
  entry_t entries[GUARD_FILTER_MAX];
} manifest_t;
static bool manifest_valid(const manifest_t *m, size_t bytes) {
  if (bytes < sizeof(m->count) || m->count > GUARD_FILTER_MAX ||
      bytes != sizeof(m->count) + m->count * sizeof(entry_t))
    return false;
  for (size_t i = 0; i < m->count; i++) {
    const entry_t *v = &m->entries[i];
    if (*(const unsigned char *)&v->enabled > 1 ||
        !memchr(v->id, 0, 64) || !v->id[0] || !memchr(v->digest, 0, 65) ||
        !digest_valid(v->digest))
      return false;
    for (size_t j = 0; j < i; j++)
      if (!strcmp(v->id, m->entries[j].id))
        return false;
  }
  return true;
}
typedef enum { KEEP_PREVIOUS, BACKUP_ACTIVE, REPLACE_PREVIOUS } save_mode_t;
static esp_err_t save(const entry_t *entries, size_t n, save_mode_t mode) {
  manifest_t *m = calloc(1, sizeof(*m));
  if (!m)
    return ESP_ERR_NO_MEM;
  m->count = n;
  memcpy(m->entries, entries, n * sizeof(entry_t));
  nvs_handle_t h;
  esp_err_t e = nvs_open("filters", NVS_READWRITE, &h);
  if (e == ESP_OK) {
    if (mode == BACKUP_ACTIVE) {
      manifest_t *old = calloc(1, sizeof(*old));
      if (!old)
        e = ESP_ERR_NO_MEM;
      else {
        old->count = count;
        for (size_t i = 0; i < count; i++)
          old->entries[i] = lists[i].entry;
        e = nvs_set_blob(h, "previous", old,
                         sizeof(old->count) + count * sizeof(entry_t));
        free(old);
      }
    } else if (mode == REPLACE_PREVIOUS)
      e = nvs_set_blob(h, "previous", m, sizeof(m->count) + n * sizeof(entry_t));
    if (e == ESP_OK)
      e = nvs_set_blob(h, "active", m, sizeof(m->count) + n * sizeof(entry_t));
    if (e == ESP_OK)
      e = nvs_commit(h);
    nvs_close(h);
  }
  free(m);
  if (e == ESP_OK) {
    has_state = true;
    memset(matches, 0, sizeof(matches));
    match_next = 0;
  }
  return e;
}
static void close_lists(void) {
  for (size_t i = 0; i < count; i++)
    if (lists[i].file)
      fclose(lists[i].file);
  memset(lists, 0, sizeof(lists));
  count = 0;
  memset(matches, 0, sizeof(matches));
  match_next = 0;
}
static esp_err_t load(nvs_handle_t h, const char *key) {
  manifest_t *m = malloc(sizeof(*m));
  if (!m)
    return ESP_ERR_NO_MEM;
  size_t bytes = sizeof(*m);
  esp_err_t e = nvs_get_blob(h, key, m, &bytes);
  if (e != ESP_OK) {
    free(m);
    return e;
  }
  if (!manifest_valid(m, bytes)) {
    free(m);
    return ESP_ERR_INVALID_STATE;
  }
  for (size_t i = 0; i < m->count; i++) {
    char path[192];
    filename(path, m->entries[i].digest);
    FILE *f = fopen(path, "rb");
    filter_meta_t meta;
    if (!f || !filter_validate(f, m->entries[i].id, &meta)) {
      if (f)
        fclose(f);
      close_lists();
      free(m);
      return ESP_ERR_INVALID_STATE;
    }
    lists[count++] = (loaded_t){m->entries[i], meta, f};
  }
  free(m);
  return ESP_OK;
}
static esp_err_t collect(void) {
  char retained[GUARD_FILTER_MAX * 2][65];
  size_t n = 0;
  xSemaphoreTake(mutex, portMAX_DELAY);
  for (size_t i = 0; i < count; i++)
    strcpy(retained[n++], lists[i].entry.digest);
  xSemaphoreGive(mutex);
  nvs_handle_t h;
  if (nvs_open("filters", NVS_READONLY, &h) != ESP_OK) {
    ESP_LOGW("store", "Fallback metadata unavailable; collection skipped");
    return ESP_FAIL;
  }
  manifest_t *m = malloc(sizeof(*m));
  if (!m) {
    nvs_close(h);
    ESP_LOGW("store", "Fallback metadata allocation failed; collection skipped");
    return ESP_FAIL;
  }
  size_t bytes = sizeof(*m);
  esp_err_t e = nvs_get_blob(h, "previous", m, &bytes);
  bool known = e == ESP_OK && manifest_valid(m, bytes);
  if (known)
    for (size_t i = 0; i < m->count; i++)
      strcpy(retained[n++], m->entries[i].digest);
  free(m);
  nvs_close(h);
  if (!known) {
    ESP_LOGW("store", "Fallback metadata invalid; collection skipped");
    return ESP_FAIL;
  }
  DIR *dir = opendir(GUARD_STORE);
  if (!dir)
    return ESP_FAIL;
  struct dirent *item;
  esp_err_t result = ESP_OK;
  for (;;) {
    errno = 0;
    item = readdir(dir);
    if (!item) {
      if (errno)
        result = ESP_FAIL;
      break;
    }
    if (strlen(item->d_name) != 68 || strcmp(item->d_name + 64, ".bin"))
      continue;
    char digest[65];
    memcpy(digest, item->d_name, 64);
    digest[64] = 0;
    if (!digest_valid(digest))
      continue;
    bool used = false;
    for (size_t i = 0; i < n; i++)
      if (!strcmp(retained[i], digest))
        used = true;
    if (!used) {
      char path[192];
      filename(path, digest);
      if (unlink(path) && errno != ENOENT)
        result = ESP_FAIL;
    }
  }
  if (closedir(dir))
    result = ESP_FAIL;
  return result;
}
esp_err_t filter_store_mount(void) {
  mutex = xSemaphoreCreateMutex();
  if (!mutex)
    return ESP_ERR_NO_MEM;
  esp_vfs_fat_mount_config_t cfg = {.format_if_mount_failed = false,
                                    .max_files = GUARD_FILTER_MAX + 4,
                                    .allocation_unit_size = 4096};
  esp_err_t e =
      esp_vfs_fat_spiflash_mount_rw_wl(GUARD_STORE, "filters", &cfg, &wl);
  if (e != ESP_OK)
    return e;
  nvs_handle_t h;
  e = nvs_open("filters", NVS_READONLY, &h);
  if (e == ESP_ERR_NVS_NOT_FOUND) {
    mounted = true;
    return ESP_OK;
  }
  if (e != ESP_OK)
    return e;
  e = load(h, "active");
  bool active_missing = e == ESP_ERR_NVS_NOT_FOUND;
  bool used_fallback = e != ESP_OK;
  recovered = used_fallback;
  if (used_fallback) {
    ESP_LOGW("filters",
             "Active generation unavailable; trying previous generation");
    e = load(h, "previous");
    if (active_missing && e == ESP_ERR_NVS_NOT_FOUND) {
      nvs_close(h);
      mounted = true;
      return ESP_OK;
    }
  }
  has_state = true;
  nvs_close(h);
  if (e != ESP_OK) {
    close_lists();
    return e;
  }
  mounted = true;
  /* Active loading may have failed transiently; preserve its blobs for recovery. */
  if (!used_fallback)
    collect();
  return ESP_OK;
}
bool filter_store_ready(void) { return mounted; }
bool filter_store_factory_needed(void) { return mounted && !has_state; }
bool filter_store_match(const char *name) {
  if (!mutex)
    return false;
  bool hit = false;
  xSemaphoreTake(mutex, portMAX_DELAY);
  for (unsigned i = 0; i < MATCH_CACHE_MAX; i++)
    if (matches[i].name[0] && !strcmp(matches[i].name, name)) {
      hit = matches[i].hit;
      xSemaphoreGive(mutex);
      return hit;
    }
  bool readable = true;
  for (const char *s = name; *s && !hit;) {
    uint64_t hash = guard_domain_hash(s, strlen(s));
    for (size_t i = 0; i < count && !hit; i++)
      if (lists[i].entry.enabled) {
        filter_result_t result =
            filter_lookup(lists[i].file, &lists[i].meta, hash);
        hit = result == FILTER_HIT;
        readable = readable && result != FILTER_READ_ERROR;
      }
    const char *d = strchr(s, '.');
    if (!d)
      break;
    s = d + 1;
  }
  /* A transient read failure must not become a remembered allow decision. */
  if (hit || readable) {
    unsigned slot = match_next++ % MATCH_CACHE_MAX;
    strcpy(matches[slot].name, name);
    matches[slot].hit = hit;
  }
  xSemaphoreGive(mutex);
  return hit;
}
bool filter_store_digest(const char *id, char out[65]) {
  if (!mutex)
    return false;
  bool found = false;
  xSemaphoreTake(mutex, portMAX_DELAY);
  for (size_t i = 0; i < count; i++)
    if (!strcmp(id, lists[i].entry.id)) {
      strcpy(out, lists[i].entry.digest);
      found = true;
      break;
    }
  xSemaphoreGive(mutex);
  return found;
}
static bool same_contents(FILE *a, FILE *b) {
  unsigned char left[512], right[512];
  rewind(a);
  rewind(b);
  for (;;) {
    size_t n = fread(left, 1, sizeof(left), a);
    if (fread(right, 1, sizeof(right), b) != n || memcmp(left, right, n))
      return false;
    if (n < sizeof(left))
      return !ferror(a) && !ferror(b);
    vTaskDelay(1);
  }
}
static esp_err_t install_file(const char *id, const char *temp,
                               const char *digest) {
  if (!mounted || !digest_valid(digest))
    return ESP_ERR_INVALID_STATE;
  FILE *f = fopen(temp, "rb");
  filter_meta_t m;
  if (!f || !filter_validate(f, id, &m)) {
    if (f)
      fclose(f);
    return ESP_ERR_INVALID_ARG;
  }
  char path[192];
  filename(path, digest);
  bool ok = true;
  if (strcmp(temp, path)) {
    FILE *existing = fopen(path, "rb");
    if (existing) {
      ok = same_contents(f, existing);
      fclose(existing);
      if (ok)
        ok = unlink(temp) == 0;
    } else {
      fclose(f);
      f = NULL;
      ok = rename(temp, path) == 0;
    }
  }
  if (f)
    fclose(f);
  if (!ok)
    return ESP_FAIL;
  f = fopen(path, "rb");
  if (!f)
    return ESP_FAIL;
  xSemaphoreTake(mutex, portMAX_DELAY);
  size_t slot = count;
  entry_t entries[GUARD_FILTER_MAX];
  for (size_t i = 0; i < count; i++) {
    entries[i] = lists[i].entry;
    if (!strcmp(id, entries[i].id))
      slot = i;
  }
  if (slot == count && count >= GUARD_FILTER_INSTALLED_MAX) {
    xSemaphoreGive(mutex);
    fclose(f);
    return ESP_ERR_NO_MEM;
  }
  memset(&entries[slot], 0, sizeof(entries[slot]));
  strlcpy(entries[slot].id, id, 64);
  strcpy(entries[slot].digest, digest);
  entries[slot].enabled = true;
  size_t n = count + (slot == count);
  esp_err_t e = save(entries, n, BACKUP_ACTIVE);
  if (e == ESP_OK) {
    if (slot < count)
      fclose(lists[slot].file);
    lists[slot] = (loaded_t){entries[slot], m, f};
    count = n;
    dns_policy_changed();
  } else
    fclose(f);
  xSemaphoreGive(mutex);
  return e;
}
esp_err_t filter_store_install(const char *id, const char *temp,
                               const char *digest) {
  /* Release the install frame before the collector's filesystem buffers. */
  esp_err_t e = install_file(id, temp, digest);
  if (e == ESP_OK)
    collect();
  return e;
}
esp_err_t filter_store_toggle(const char *id, bool enabled) {
  if (!enabled)
    return filter_store_remove(id);
  if (!mutex)
    return ESP_ERR_INVALID_STATE;
  xSemaphoreTake(mutex, portMAX_DELAY);
  entry_t entries[GUARD_FILTER_MAX];
  size_t slot = count;
  for (size_t i = 0; i < count; i++) {
    entries[i] = lists[i].entry;
    if (!strcmp(id, entries[i].id))
      slot = i;
  }
  esp_err_t e = ESP_ERR_NOT_FOUND;
  if (slot < count) {
    entries[slot].enabled = enabled;
    e = save(entries, count, KEEP_PREVIOUS);
    if (e == ESP_OK) {
      lists[slot].entry.enabled = enabled;
      dns_policy_changed();
    }
  }
  xSemaphoreGive(mutex);
  return e;
}
esp_err_t filter_store_remove(const char *id) {
  if (!mutex)
    return ESP_ERR_INVALID_STATE;
  xSemaphoreTake(mutex, portMAX_DELAY);
  entry_t entries[GUARD_FILTER_MAX];
  char path[192] = {0};
  size_t slot = count, n = 0;
  for (size_t i = 0; i < count; i++)
    if (strcmp(id, lists[i].entry.id))
      entries[n++] = lists[i].entry;
    else
      slot = i;
  esp_err_t e = ESP_ERR_NOT_FOUND;
  if (slot < count) {
    bool shared = false;
    for (size_t i = 0; i < n; i++)
      if (!strcmp(entries[i].digest, lists[slot].entry.digest))
        shared = true;
    if (!shared)
      filename(path, lists[slot].entry.digest);
    /* Save post-removal fallback first; unlink only after both writes succeed. */
    e = save(entries, n, REPLACE_PREVIOUS);
    if (e == ESP_OK) {
      fclose(lists[slot].file);
      memmove(lists + slot, lists + slot + 1,
              (count - slot - 1) * sizeof(*lists));
      count--;
      dns_policy_changed();
    }
  }
  xSemaphoreGive(mutex);
  if (e == ESP_OK && path[0] && unlink(path) && errno != ENOENT)
    return ESP_FAIL;
  return e == ESP_OK ? collect() : e;
}
esp_err_t filter_store_prune_disabled(void) {
  if (!mounted || recovered)
    return ESP_ERR_INVALID_STATE;
  for (;;) {
    char id[64] = {0};
    xSemaphoreTake(mutex, portMAX_DELAY);
    for (size_t i = 0; i < count; i++)
      if (!lists[i].entry.enabled) {
        strcpy(id, lists[i].entry.id);
        break;
      }
    xSemaphoreGive(mutex);
    if (!id[0])
      return ESP_OK;
    esp_err_t e = filter_store_remove(id);
    if (e != ESP_OK)
      return e;
  }
}
cJSON *filter_store_json(void) {
  cJSON *a = cJSON_CreateArray();
  if (!a || !mutex)
    return a;
  bool ok = true;
  xSemaphoreTake(mutex, portMAX_DELAY);
  for (size_t i = 0; i < count; i++) {
    cJSON *o = cJSON_CreateObject();
    if (!o || !cJSON_AddStringToObject(o, "id", lists[i].entry.id) ||
        !cJSON_AddStringToObject(o, "sha256", lists[i].entry.digest) ||
        !cJSON_AddBoolToObject(o, "enabled", lists[i].entry.enabled) ||
        !cJSON_AddNumberToObject(o, "ruleCount", lists[i].meta.count) ||
        !cJSON_AddItemToArray(a, o)) {
      cJSON_Delete(o);
      ok = false;
      break;
    }
  }
  xSemaphoreGive(mutex);
  if (!ok) {
    cJSON_Delete(a);
    return NULL;
  }
  return a;
}
