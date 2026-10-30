#pragma once
#include <stdbool.h>
typedef bool (*rule_text_emit_t)(const char *, bool, void *);
bool rule_text_parse(char *line, bool default_allow, rule_text_emit_t, void *);
