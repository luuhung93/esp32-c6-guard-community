#pragma once
#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct {
  uint64_t hash;
  uint16_t slot;
  bool allow;
} rule_index_t;
typedef enum { RULE_NONE, RULE_ALLOW, RULE_BLOCK } rule_result_t;
#ifdef ESP_PLATFORM
#include "esp_err.h"
esp_err_t my_rules_init(void);
rule_result_t my_rules_lookup(const char *);
size_t my_rules_count(void);
bool my_rules_get(size_t, char domain[254], bool *allow);
esp_err_t my_rules_stage_begin(void);
esp_err_t my_rules_stage_add(const char *, bool);
esp_err_t my_rules_stage_commit(void);
void my_rules_stage_abort(void);
esp_err_t my_rules_mutate(const char *old_domain, const char *new_domain,
                          bool allow);
#endif
