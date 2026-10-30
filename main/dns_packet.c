#include "dns_packet.h"
#include "config.h"
#include "domain.h"
#include <string.h>
uint16_t dns_u16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
void dns_put16(uint8_t *p, uint16_t v) {
  p[0] = v >> 8;
  p[1] = v;
}
bool dns_name_read(const uint8_t *p, size_t n, size_t *offset, char out[254]) {
  size_t pos = *offset, used = 0, end = 0;
  unsigned hops = 0;
  while (pos < n && ++hops <= 128) {
    unsigned len = p[pos++];
    if ((len & 0xc0) == 0xc0) {
      if (pos >= n)
        return false;
      size_t target = ((len & 63) << 8) | p[pos++];
      if (target >= pos - 2 || target < 12)
        return false;
      if (!end)
        end = pos;
      pos = target;
      continue;
    }
    if (len & 0xc0 || len > 63 || pos + len > n)
      return false;
    if (!len) {
      out[used] = 0;
      *offset = end ? end : pos;
      return true;
    }
    if (used && used < 253)
      out[used++] = '.';
    if (used + len > 253)
      return false;
    for (unsigned i = 0; i < len; i++) {
      unsigned char c = p[pos++];
      if (c < 33 || c > 126 || c == '.' || c == '\\')
        return false;
      out[used++] = (char)(c >= 'A' && c <= 'Z' ? c + 32 : c);
    }
  }
  return false;
}
dns_parse_result_t dns_packet_parse(const uint8_t *p, size_t n,
                                    dns_question_t *q) {
  if (!p || !q || n < 12)
    return DNS_PARSE_FORMERR;
  if (n > GUARD_DNS_MAX)
    return DNS_PARSE_TOO_LARGE;
  memset(q, 0, sizeof(*q));
  q->id = dns_u16(p);
  q->flags = dns_u16(p + 2);
  q->udp_limit = 512;
  if (q->flags & 0x8000)
    return DNS_PARSE_FORMERR;
  if (q->flags & 0x7800)
    return DNS_PARSE_NOTIMP;
  if (dns_u16(p + 4) != 1 || dns_u16(p + 6) || dns_u16(p + 8) ||
      dns_u16(p + 10) > 1)
    return DNS_PARSE_FORMERR;
  size_t pos = 12;
  if (!dns_name_read(p, n, &pos, q->name) || pos + 4 > n)
    return DNS_PARSE_FORMERR;
  q->qtype = dns_u16(p + pos);
  q->qclass = dns_u16(p + pos + 2);
  q->question_end = pos + 4;
  for (size_t i = 12; i < pos; i++)
    if (p[i] >= 'A' && p[i] <= 'Z')
      q->cache_unsafe = true;
  char canonical[254];
  q->filterable =
      q->qclass == 1 &&
      guard_domain_normalize(q->name, strlen(q->name), canonical) == DOMAIN_OK;
  pos += 4;
  if (dns_u16(p + 10)) {
    char name[254];
    if (!dns_name_read(p, n, &pos, name) || name[0] || pos + 10 > n ||
        dns_u16(p + pos) != 41)
      return DNS_PARSE_FORMERR;
    q->udp_limit = dns_u16(p + pos + 2);
    if (q->udp_limit < 512)
      q->udp_limit = 512;
    if (q->udp_limit > GUARD_DNS_MAX)
      q->udp_limit = GUARD_DNS_MAX;
    size_t rdlen = dns_u16(p + pos + 8);
    if (rdlen || (dns_u16(p + pos + 6) & 0x8000))
      q->cache_unsafe = true;
    pos += 10;
    if (pos + rdlen > n)
      return DNS_PARSE_FORMERR;
    size_t end = pos + rdlen;
    while (pos < end) {
      if (pos + 4 > end)
        return DNS_PARSE_FORMERR;
      size_t z = dns_u16(p + pos + 2);
      pos += 4;
      if (pos + z > end)
        return DNS_PARSE_FORMERR;
      pos += z;
    }
  }
  return pos == n ? DNS_PARSE_OK : DNS_PARSE_FORMERR;
}
bool dns_packet_answer(const uint8_t *p, size_t n, const dns_question_t *q,
                       unsigned rcode, uint8_t *out, size_t cap, size_t *olen) {
  if (q->question_end > n || q->question_end < 12 || q->question_end > cap)
    return false;
  size_t len = q->question_end;
  unsigned bytes = (!rcode && q->qclass == 1) ? (q->qtype == 1    ? 4
                                                 : q->qtype == 28 ? 16
                                                                  : 0)
                                              : 0;
  if (bytes && cap - len < 12 + bytes)
    return false;
  memcpy(out, p, len);
  dns_put16(out + 2, (uint16_t)(0x8080 | (q->flags & 0x0100) | (rcode & 15)));
  dns_put16(out + 4, 1);
  dns_put16(out + 6, bytes ? 1 : 0);
  memset(out + 8, 0, 4);
  if (bytes) {
    out[len++] = 0xc0;
    out[len++] = 0x0c;
    dns_put16(out + len, q->qtype);
    len += 2;
    dns_put16(out + len, 1);
    len += 2;
    out[len++] = 0;
    out[len++] = 0;
    out[len++] = 0;
    out[len++] = 60;
    dns_put16(out + len, bytes);
    len += 2;
    memset(out + len, 0, bytes);
    len += bytes;
  }
  *olen = len;
  return true;
}
bool dns_packet_reply_valid(const uint8_t *p, size_t n,
                            const dns_question_t *q) {
  if (n < 12 || !(dns_u16(p + 2) & 0x8000) || (dns_u16(p + 2) & 0x7800) ||
      dns_u16(p + 4) != 1)
    return false;
  char name[254];
  size_t pos = 12;
  if (!dns_name_read(p, n, &pos, name) || pos + 4 > n ||
      strcmp(name, q->name) || dns_u16(p + pos) != q->qtype ||
      dns_u16(p + pos + 2) != q->qclass)
    return false;
  pos += 4;
  if (dns_u16(p + 2) & 0x0200)
    return true;
  unsigned records =
      (unsigned)dns_u16(p + 6) + dns_u16(p + 8) + dns_u16(p + 10);
  if (records > 128)
    return false;
  for (unsigned i = 0; i < records; i++) {
    if (!dns_name_read(p, n, &pos, name) || pos + 10 > n)
      return false;
    uint16_t type = dns_u16(p + pos), length = dns_u16(p + pos + 8);
    pos += 10;
    if (pos + length > n)
      return false;
    if (type == 1 && length != 4)
      return false;
    if (type == 28 && length != 16)
      return false;
    if (type == 5 || type == 2 || type == 12) {
      size_t end = pos;
      if (!dns_name_read(p, n, &end, name) || end != pos + length)
        return false;
    }
    pos += length;
  }
  return pos == n;
}
