#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef enum {
  DNS_PARSE_OK,
  DNS_PARSE_FORMERR,
  DNS_PARSE_NOTIMP,
  DNS_PARSE_TOO_LARGE
} dns_parse_result_t;
typedef struct {
  uint16_t id, qtype, qclass, flags, udp_limit;
  size_t question_end;
  char name[254];
  bool filterable, cache_unsafe;
} dns_question_t;
uint16_t dns_u16(const uint8_t *p);
void dns_put16(uint8_t *p, uint16_t v);
bool dns_name_read(const uint8_t *p, size_t n, size_t *offset, char out[254]);
dns_parse_result_t dns_packet_parse(const uint8_t *, size_t, dns_question_t *);
bool dns_packet_answer(const uint8_t *, size_t, const dns_question_t *,
                       unsigned rcode, uint8_t *, size_t, size_t *);
bool dns_packet_reply_valid(const uint8_t *, size_t, const dns_question_t *);
