#include "dns.h"
#include "dns_cache.h"
#include "dns_packet.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "filter_store.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "my_rules.h"
#include "network.h"
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static statistics_t stats;
static SemaphoreHandle_t lock;
static dns_cache_t *cache;
static _Atomic uint32_t generation = 1;
static bool ready;
static guard_settings_t settings;
typedef struct {
  struct sockaddr_in peer;
  size_t len;
  uint8_t packet[GUARD_DNS_MAX + 1];
} udp_job_t;
typedef struct {
  udp_job_t job;
  uint8_t response[GUARD_DNS_MAX];
} udp_buffers_t;
typedef struct {
  uint8_t packet[GUARD_DNS_MAX], response[GUARD_DNS_MAX];
} tcp_buffers_t;
static QueueHandle_t jobs, tcp_jobs;
static int udp_fd = -1, tcp_fd = -1;
static SemaphoreHandle_t tcp_slots;
static uint64_t now_ms(void) { return esp_timer_get_time() / 1000; }
void dns_policy_changed(void) { atomic_fetch_add(&generation, 1); }
bool dns_is_ready(void) { return ready; }
void dns_totals(dns_totals_t *out) {
  *out = (dns_totals_t){0};
  if (!lock)
    return;
  xSemaphoreTake(lock, portMAX_DELAY);
  *out = (dns_totals_t){stats.total, stats.blocked, stats.cached, stats.errors};
  xSemaphoreGive(lock);
}
size_t dns_recent(query_event_t *out, size_t offset, size_t cap) {
  if (!lock)
    return 0;
  xSemaphoreTake(lock, portMAX_DELAY);
  size_t n = 0;
  while (offset + n < stats.count && n < cap) {
    out[n] = stats.history[(stats.head + GUARD_QUERY_MAX - 1 - offset - n) %
                           GUARD_QUERY_MAX];
    n++;
  }
  xSemaphoreGive(lock);
  return n;
}
void dns_history_enable(bool enabled) {
  if (!lock)
    return;
  xSemaphoreTake(lock, portMAX_DELAY);
  statistics_history(&stats, enabled);
  xSemaphoreGive(lock);
}
static void timeout(int fd, bool tcp) {
  struct timeval tv = {.tv_sec = 2};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  if (tcp) {
    /* Separate DNS length/payload writes must not wait for delayed ACKs. */
    int enabled = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
  }
}
static bool io_budget(int fd, int option, int64_t deadline) {
  int64_t remaining = deadline - esp_timer_get_time();
  if (remaining <= 0)
    return false;
  /* lwIP rounds timeval down to milliseconds; zero would disable the timeout. */
  int64_t milliseconds = (remaining + 999) / 1000;
  struct timeval tv = {.tv_sec = milliseconds / 1000,
                       .tv_usec = (milliseconds % 1000) * 1000};
  return setsockopt(fd, SOL_SOCKET, option, &tv, sizeof(tv)) == 0;
}
static bool read_all(int fd, uint8_t *p, size_t n) {
  int64_t deadline = esp_timer_get_time() + 2000000;
  while (n) {
    if (!io_budget(fd, SO_RCVTIMEO, deadline))
      return false;
    int k = recv(fd, p, n, 0);
    if (k <= 0)
      return false;
    p += k;
    n -= k;
  }
  return true;
}
static bool write_all(int fd, const uint8_t *p, size_t n) {
  int64_t deadline = esp_timer_get_time() + 2000000;
  while (n) {
    if (!io_budget(fd, SO_SNDTIMEO, deadline))
      return false;
    int k = send(fd, p, n, 0);
    if (k <= 0) {
      ESP_LOGW("dns", "TCP write failed: errno=%d", errno);
      return false;
    }
    p += k;
    n -= k;
  }
  return true;
}
static bool connect_upstream(int fd, const struct sockaddr_in *upstream) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return false;
  bool connected =
      connect(fd, (const struct sockaddr *)upstream, sizeof(*upstream)) == 0;
  if (!connected && errno == EINPROGRESS) {
    fd_set writable;
    FD_ZERO(&writable);
    FD_SET(fd, &writable);
    struct timeval budget = {.tv_sec = 2};
    if (select(fd + 1, NULL, &writable, NULL, &budget) > 0) {
      int error = 0;
      socklen_t size = sizeof(error);
      connected = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 &&
                  error == 0;
    }
  }
  return fcntl(fd, F_SETFL, flags) == 0 && connected;
}
static bool forward(uint8_t *query, size_t len, const dns_question_t *q,
                    uint8_t *out, size_t *n, bool tcp) {
  if (!network_ready() || !network_upstream_safe(settings.upstream))
    return false;
  struct sockaddr_in upstream = {.sin_family = AF_INET, .sin_port = htons(53)};
  inet_pton(AF_INET, settings.upstream, &upstream.sin_addr);
  int fd = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, IPPROTO_IP);
  if (fd < 0)
    return false;
  timeout(fd, tcp);
  uint16_t id = (uint16_t)esp_random();
  /* The worker owns this buffer; restore its ID before fallback or return. */
  dns_put16(query, id);
  bool ok = tcp ? connect_upstream(fd, &upstream)
                : connect(fd, (struct sockaddr *)&upstream, sizeof(upstream)) == 0;
  if (tcp) {
    uint8_t prefix[2];
    dns_put16(prefix, len);
    ok = ok && write_all(fd, prefix, 2) && write_all(fd, query, len) &&
         read_all(fd, prefix, 2);
    size_t bytes = ok ? dns_u16(prefix) : 0;
    ok =
        ok && bytes >= 12 && bytes <= GUARD_DNS_MAX && read_all(fd, out, bytes);
    *n = bytes;
  } else {
    ok = ok && send(fd, query, len, 0) == (int)len;
    int bytes = ok ? recv(fd, out, GUARD_DNS_MAX, 0) : -1;
    ok = bytes >= 12;
    *n = bytes > 0 ? (size_t)bytes : 0;
  }
  dns_put16(query, q->id);
  close(fd);
  ok = ok && dns_u16(out) == id && dns_packet_reply_valid(out, *n, q);
  if (ok && !tcp && (dns_u16(out + 2) & 0x0200))
    return forward(query, len, q, out, n, true);
  if (ok)
    dns_put16(out, q->id);
  return ok;
}
static size_t resolve(uint8_t *p, size_t len, uint8_t *out,
                      const char *client, bool tcp) {
  dns_question_t q;
  size_t n = 0;
  unsigned outcome = 0;
  dns_parse_result_t parsed = dns_packet_parse(p, len, &q);
  if (parsed != DNS_PARSE_OK) {
    if (len < 12)
      return 0;
    memset(out, 0, 12);
    memcpy(out, p, 2);
    dns_put16(out + 2, 0x8080 | (parsed == DNS_PARSE_NOTIMP ? 4 : 1));
    return 12;
  }
  uint32_t gen = atomic_load(&generation);
  rule_result_t rule = q.filterable ? my_rules_lookup(q.name) : RULE_NONE;
  bool blocked = rule == RULE_BLOCK || (rule == RULE_NONE && q.filterable &&
                                        filter_store_match(q.name));
  if (blocked) {
    dns_packet_answer(p, len, &q, 0, out, GUARD_DNS_MAX, &n);
    outcome = 1;
  } else {
    xSemaphoreTake(lock, portMAX_DELAY);
    bool hit =
        dns_cache_get(cache, &q, q.id, now_ms(), gen, out, GUARD_DNS_MAX, &n);
    xSemaphoreGive(lock);
    if (hit)
      outcome = 2;
    else if (!forward(p, len, &q, out, &n, tcp)) {
      dns_packet_answer(p, len, &q, 2, out, GUARD_DNS_MAX, &n);
      outcome = 3;
    } else if (gen == atomic_load(&generation)) {
      xSemaphoreTake(lock, portMAX_DELAY);
      dns_cache_put(cache, &q, out, n, now_ms(), gen);
      xSemaphoreGive(lock);
    }
  }
  if (gen != atomic_load(&generation)) {
    rule = q.filterable ? my_rules_lookup(q.name) : RULE_NONE;
    blocked = rule == RULE_BLOCK ||
              (rule == RULE_NONE && q.filterable && filter_store_match(q.name));
    if (blocked) {
      dns_packet_answer(p, len, &q, 0, out, GUARD_DNS_MAX, &n);
      outcome = 1;
    } else if (outcome == 1 || outcome == 2) {
      if (!forward(p, len, &q, out, &n, tcp)) {
        dns_packet_answer(p, len, &q, 2, out, GUARD_DNS_MAX, &n);
        outcome = 3;
      } else
        outcome = 0;
    }
  }
  if (!tcp && n > q.udp_limit) {
    dns_packet_answer(p, len, &q, 2, out, GUARD_DNS_MAX, &n);
    dns_put16(out + 2, 0x8280 | (q.flags & 0x100));
    dns_put16(out + 6, 0);
    n = q.question_end;
  }
  query_event_t event = {
      .when_ms = now_ms(), .qtype = q.qtype, .outcome = outcome};
  strlcpy(event.domain, q.name, sizeof(event.domain));
  strlcpy(event.client, client, 16);
  xSemaphoreTake(lock, portMAX_DELAY);
  statistics_record(&stats, &event);
  xSemaphoreGive(lock);
  return n;
}
static bool udp_reply(const uint8_t *packet, size_t length,
                      const struct sockaddr_in *peer) {
  int64_t deadline = esp_timer_get_time() + 2000000;
  for (;;) {
    if (sendto(udp_fd, packet, length, 0, (const struct sockaddr *)peer,
                sizeof(*peer)) >= 0) {
      return true;
    }
    int error = errno;
    if (esp_timer_get_time() >= deadline ||
        (error != ENOMEM && error != ENOBUFS && error != EAGAIN)) {
      ESP_LOGW("dns", "UDP send failed: errno=%d", error);
      return false;
    }
    /* Cold ARP queues can stay full beyond a few ticks; wait within I/O budget. */
    vTaskDelay(1);
  }
  return false;
}
static void udp_worker(void *arg) {
  ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
  udp_buffers_t *buffers = arg;
  udp_job_t *job = &buffers->job;
  for (;;)
    if (xQueueReceive(jobs, job, portMAX_DELAY)) {
      char client[16];
      inet_ntop(AF_INET, &job->peer.sin_addr, client, 16);
      size_t n = resolve(job->packet, job->len, buffers->response, client, false);
      if (n)
        udp_reply(buffers->response, n, &job->peer);
    }
}
static void udp_server(void *arg) {
  ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
  udp_job_t *job = arg;
  for (;;) {
    socklen_t peerlen = sizeof(job->peer);
    int n = recvfrom(udp_fd, job->packet, sizeof(job->packet), 0,
                     (struct sockaddr *)&job->peer, &peerlen);
    if (n > 0) {
      job->len = n;
      /* Let workers drain a short burst without blocking receive indefinitely. */
      if (!xQueueSend(jobs, job, pdMS_TO_TICKS(20)) && n >= 12) {
        dns_question_t question;
        uint8_t error[512];
        size_t length;
        if (dns_packet_parse(job->packet, n, &question) == DNS_PARSE_OK &&
            dns_packet_answer(job->packet, n, &question, 2, error,
                              sizeof(error), &length))
          udp_reply(error, length, &job->peer);
      }
    }
  }
}
static void tcp_worker(void *arg) {
  ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
  tcp_buffers_t *buffers = arg;
  int fd;
  for (;;) {
    if (!xQueueReceive(tcp_jobs, &fd, portMAX_DELAY))
      continue;
    timeout(fd, true);
    struct sockaddr_in peer;
    socklen_t z = sizeof(peer);
    char client[16] = "unknown";
    if (!getpeername(fd, (struct sockaddr *)&peer, &z))
      inet_ntop(AF_INET, &peer.sin_addr, client, 16);
    for (unsigned frames = 0; frames < 32; frames++) {
      uint8_t prefix[2];
      if (!read_all(fd, prefix, 2))
        break;
      size_t len = dns_u16(prefix);
      if (len < 12 || len > GUARD_DNS_MAX ||
          !read_all(fd, buffers->packet, len))
        break;
      size_t n = resolve(buffers->packet, len, buffers->response, client, true);
      dns_put16(prefix, n);
      if (!n || !write_all(fd, prefix, 2) ||
          !write_all(fd, buffers->response, n))
        break;
    }
    close(fd);
    xSemaphoreGive(tcp_slots);
  }
}
static void tcp_server(void *unused) {
  (void)unused;
  ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
  for (;;) {
    /* Leave connections in the bounded listener backlog until a worker is free. */
    if (!xSemaphoreTake(tcp_slots, portMAX_DELAY))
      continue;
    int fd = accept(tcp_fd, NULL, NULL);
    if (fd < 0) {
      ESP_LOGW("dns", "TCP accept failed: errno=%d", errno);
      xSemaphoreGive(tcp_slots);
      vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }
    if (!xQueueSend(tcp_jobs, &fd, portMAX_DELAY)) {
      close(fd);
      xSemaphoreGive(tcp_slots);
    }
  }
}
esp_err_t dns_start(const guard_settings_t *s) {
  if (ready)
    return ESP_ERR_INVALID_STATE;
  esp_err_t error = ESP_ERR_NO_MEM;
  tcp_buffers_t *tcp[GUARD_TCP_MAX] = {0};
  udp_buffers_t *udp[2] = {0};
  udp_job_t *receiver = NULL;
  TaskHandle_t tasks[6] = {0};
  unsigned created = 0;
  settings = *s;
  lock = xSemaphoreCreateMutex();
  tcp_slots = xSemaphoreCreateCounting(GUARD_TCP_MAX, GUARD_TCP_MAX);
  jobs = xQueueCreate(GUARD_PENDING_MAX, sizeof(udp_job_t));
  tcp_jobs = xQueueCreate(GUARD_TCP_MAX, sizeof(int));
  cache = dns_cache_create();
  if (!lock || !tcp_slots || !jobs || !tcp_jobs || !cache)
    goto fail;
  for (unsigned i = 0; i < GUARD_TCP_MAX; i++)
    if (!(tcp[i] = malloc(sizeof(*tcp[i]))))
      goto fail;
  for (unsigned i = 0; i < 2; i++)
    if (!(udp[i] = malloc(sizeof(*udp[i]))))
      goto fail;
  if (!(receiver = malloc(sizeof(*receiver))))
    goto fail;
  stats.disabled = !s->history;
  struct sockaddr_in addr = {.sin_family = AF_INET,
                             .sin_port = htons(53),
                             .sin_addr.s_addr = INADDR_ANY};
  udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
  tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
  int reuse = 1;
  error = ESP_FAIL;
  if (udp_fd < 0 || tcp_fd < 0 ||
      setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ||
      bind(udp_fd, (struct sockaddr *)&addr, sizeof(addr)) ||
      bind(tcp_fd, (struct sockaddr *)&addr, sizeof(addr)) || listen(tcp_fd, 2))
    goto fail;
  void (*functions[])(void *) = {tcp_worker, tcp_worker, udp_worker,
                                  udp_worker, udp_server, tcp_server};
  void *arguments[] = {tcp[0], tcp[1], udp[0], udp[1], receiver, NULL};
  const char *names[] = {"dns-tcp0", "dns-tcp1", "dns-udp0", "dns-udp1",
                         "dns-rx", "dns-accept"};
  unsigned stacks[] = {6144, 6144, 6144, 6144, 3072, 3072};
  error = ESP_ERR_NO_MEM;
  for (; created < 6; created++)
    if (xTaskCreate(functions[created], names[created], stacks[created],
                    arguments[created], 5, &tasks[created]) != pdPASS)
      goto fail;
  /* No worker may access resources until every allocation/task has succeeded. */
  ready = true;
  for (unsigned i = 0; i < created; i++)
    xTaskNotifyGive(tasks[i]);
  return ESP_OK;
fail:
  while (created)
    vTaskDelete(tasks[--created]);
  if (udp_fd >= 0)
    close(udp_fd);
  if (tcp_fd >= 0)
    close(tcp_fd);
  udp_fd = tcp_fd = -1;
  for (unsigned i = 0; i < GUARD_TCP_MAX; i++)
    free(tcp[i]);
  for (unsigned i = 0; i < 2; i++)
    free(udp[i]);
  free(receiver);
  dns_cache_destroy(cache);
  cache = NULL;
  if (jobs)
    vQueueDelete(jobs);
  if (tcp_jobs)
    vQueueDelete(tcp_jobs);
  jobs = tcp_jobs = NULL;
  if (tcp_slots)
    vSemaphoreDelete(tcp_slots);
  if (lock)
    vSemaphoreDelete(lock);
  tcp_slots = lock = NULL;
  return error;
}
