#pragma once
#include <stdbool.h>
#include <stddef.h>
bool web_origin_allowed(const char *host, const char *origin,
                        const char *lan_ip, bool setup);
bool web_setup_address_matches(const void *address, size_t length,
                               const void *ap_ipv4);
