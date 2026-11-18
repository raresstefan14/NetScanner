#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../include/cidr.h"

int cidr_to_ips(const char *cidr, char ***ips_out, int *count_out) {
    char cidr_copy[64] = {0};
    strncpy(cidr_copy, cidr, sizeof(cidr_copy) - 1);

    char *slash = strchr(cidr_copy, '/');
    if (!slash) {
        fprintf(stderr, "[-] Not a CIDR range: %s\n", cidr);
        return 0;
    }

    *slash = '\0';
    char *end;
    long prefix = strtol(slash + 1, &end, 10);
    if (*end != '\0' || end == slash + 1 || prefix < 16 || prefix > 32) {
        fprintf(stderr, "[-] Invalid prefix: /%s (allowed /16 to /32)\n", slash + 1);
        return 0;
    }

    struct in_addr base_addr;
    if (inet_pton(AF_INET, cidr_copy, &base_addr) != 1) {
        fprintf(stderr, "[-] Invalid IP: %s\n", cidr_copy);
        return 0;
    }

    uint32_t mask = prefix == 32 ? ~0u : ~(~0u >> prefix);
    uint32_t network = ntohl(base_addr.s_addr) & mask;
    uint32_t first = network, count = 1u << (32 - prefix);
    // /31 and /32 have no network/broadcast address; everything else skips both.
    if (prefix < 31) { first++; count -= 2; }

    char **ips = malloc(sizeof(char *) * count);
    for (uint32_t i = 0; i < count; i++) {
        ips[i] = malloc(INET_ADDRSTRLEN);
        struct in_addr addr = { htonl(first + i) };
        inet_ntop(AF_INET, &addr, ips[i], INET_ADDRSTRLEN);
    }

    *ips_out = ips;
    *count_out = (int)count;
    return 1;
}
