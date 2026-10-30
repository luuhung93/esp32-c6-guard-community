#include "web_policy.h"
#include "config.h"
#include <stdio.h>
#include <string.h>
bool web_origin_allowed(const char *host, const char *origin, const char *ip,
                        bool setup) {
  if (!host || !origin || !ip || strlen(host) > 63)
    return false;
  char authority[64], expected[80];
  bool allowed = !strcmp(host, ip) || (setup && !strcmp(host, GUARD_AP_IP));
  snprintf(authority, sizeof(authority), "%s:80", ip);
  allowed = allowed || !strcmp(host, authority) ||
            (setup && !strcmp(host, GUARD_AP_IP ":80"));
  snprintf(expected, sizeof(expected), "http://%s", host);
  return allowed && !strcmp(origin, expected);
}

bool web_setup_address_matches(const void *address, size_t length,
                               const void *ap_ipv4) {
  if (!address || !ap_ipv4)
    return false;
  if (length == 4)
    return !memcmp(address, ap_ipv4, 4);
  const unsigned char prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
  return length == 16 && !memcmp(address, prefix, sizeof(prefix)) &&
         !memcmp((const unsigned char *)address + 12, ap_ipv4, 4);
}
