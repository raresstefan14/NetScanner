#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../include/cidr.h"

int cidr_to_ips(const char *cidr, char **ips_out, int *count_out) {
    char cidr_copy[64];
    strncpy(cidr_copy, cidr, sizeof(cidr_copy) - 1);

    char *slash = strchr(cidr_copy, '/');
    if (!slash) {
        *ips_out = malloc(64);
        strncpy(*ips_out, cidr, 63);
        *count_out = 1;
        return 1;
    }

    *slash = '\0';
    int prefix = atoi(slash + 1);

    if (prefix < 0 || prefix > 32) {
        fprintf(stderr, "[-] Invalid prefix: /%d\n", prefix);
        return 0;
    }

    struct in_addr base_addr;
    if (inet_pton(AF_INET, cidr_copy, &base_addr) != 1) {
        fprintf(stderr, "[-] Invalid IP: %s\n", cidr_copy);
        return 0;
    }

    uint32_t base = ntohl(base_addr.s_addr);
    uint32_t mask = prefix == 0 ? 0 : (~0u << (32 - prefix));
    uint32_t network = base & mask;
    uint32_t count = 1u << (32 - prefix);

    if (count > 65536) {
        fprintf(stderr, "[-] Range too large (max /16)\n");
        return 0;
    }

    char **ips = malloc(sizeof(char *) * count);
    for (uint32_t i = 0; i < count; i++) {
        ips[i] = malloc(16);
        struct in_addr addr;
        addr.s_addr = htonl(network + i);
        inet_ntop(AF_INET, &addr, ips[i], 16);
    }

    *ips_out = (char *)ips;
    *count_out = (int)count;
    return 1;
}
