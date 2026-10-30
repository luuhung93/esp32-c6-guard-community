#pragma once
#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct {
  uint64_t when_ms;
  char domain[64], client[16];
  uint16_t qtype;
  uint8_t outcome;
} query_event_t;
typedef struct {
  uint64_t total, blocked, cached, errors;
  size_t head, count;
  bool disabled;
  query_event_t history[GUARD_QUERY_MAX];
} statistics_t;
void statistics_record(statistics_t *, const query_event_t *);
size_t statistics_recent(const statistics_t *, query_event_t *, size_t);
void statistics_history(statistics_t *, bool);
