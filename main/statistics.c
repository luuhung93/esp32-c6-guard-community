#include "statistics.h"
void statistics_record(statistics_t *s, const query_event_t *e) {
  s->total++;
  if (e->outcome == 1)
    s->blocked++;
  if (e->outcome == 2)
    s->cached++;
  if (e->outcome == 3)
    s->errors++;
  if (s->disabled)
    return;
  s->history[s->head] = *e;
  s->head = (s->head + 1) % GUARD_QUERY_MAX;
  if (s->count < GUARD_QUERY_MAX)
    s->count++;
}
size_t statistics_recent(const statistics_t *s, query_event_t *out,
                         size_t cap) {
  size_t n = s->count < cap ? s->count : cap;
  for (size_t i = 0; i < n; i++)
    out[i] = s->history[(s->head + GUARD_QUERY_MAX - 1 - i) % GUARD_QUERY_MAX];
  return n;
}
void statistics_history(statistics_t *s, bool enabled) {
  s->disabled = !enabled;
  if (!enabled) {
    s->count = 0;
    s->head = 0;
  }
}
