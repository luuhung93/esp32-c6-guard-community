#include "rule_text.h"
#include "domain.h"
#include <string.h>
bool rule_text_parse(char *line, bool allow, rule_text_emit_t emit, void *ctx) {
  char *comment = strchr(line, '#');
  if (comment)
    *comment = 0;
  char *save = NULL, *word = strtok_r(line, " \t", &save);
  if (!word)
    return true;
  bool hosts = false;
  if (!strcmp(word, "allow") || !strcmp(word, "block")) {
    allow = !strcmp(word, "allow");
    word = strtok_r(NULL, " \t", &save);
    if (!word)
      return false;
  } else if (!strcmp(word, "0.0.0.0") || !strcmp(word, "127.0.0.1") ||
             !strcmp(word, "::") || !strcmp(word, "::1")) {
    hosts = true;
    word = strtok_r(NULL, " \t", &save);
    if (!word)
      return false;
  }
  do {
    char domain[254];
    if (guard_domain_normalize(word, strlen(word), domain) != DOMAIN_OK ||
        !emit(domain, allow, ctx))
      return false;
    word = strtok_r(NULL, " \t", &save);
    if (word && !hosts)
      return false;
  } while (word);
  return true;
}
