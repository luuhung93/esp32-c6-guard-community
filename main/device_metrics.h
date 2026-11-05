#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct {
  size_t heap_total;
  uint32_t cpu_mhz;
  float temperature_c;
  bool temperature_valid;
} device_metrics_t;
void device_metrics_start(void);
device_metrics_t device_metrics_read(void);
