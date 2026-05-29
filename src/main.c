#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/scanner.h"
#include "../include/utils.h"

void usage(const char *prog) {
    printf("Utilizare: %s -h <host> [-p <start-end>] [-t <timeout_ms>]\n", prog);
    printf("  -h  host sau IP (ex: scanme.nmap.org)\n");
    printf("  -p  range porturi (ex: 1-1000, default: 1-1024)\n");
    printf("  -t  timeout in ms (default: 1000)\n");
    printf("  -v  verbose\n\n");
    printf("Exemple:\n");
    printf("  %s -h scanme.nmap.org\n", prog);
    printf("  %s -h 192.168.1.1 -p 1-500 -t 500\n\n", prog);
}

int main(int argc, char *argv[]) {
    ScanConfig config;
    memset(&config, 0, sizeof(config));

    // valori default
    config.port_start = 1;
    config.port_end   = 1024;
    config.timeout_ms = DEFAULT_TIMEOUT;
    config.verbose    = 0;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    // parsam argumentele
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 && i+1 < argc) {
            strncpy(config.host, argv[++i], MAX_HOST_LEN - 1);
        } else if (strcmp(argv[i], "-p") == 0 && i+1 < argc) {
            sscanf(argv[++i], "%d-%d", &config.port_start, &config.port_end);
        } else if (strcmp(argv[i], "-t") == 0 && i+1 < argc) {
            config.timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0) {
            config.verbose = 1;
        }
    }

    if (strlen(config.host) == 0) {
        fprintf(stderr, "[-] Trebuie sa specifici un host cu -h\n\n");
        usage(argv[0]);
        return 1;
    }

    // rezolvam hostname -> IP
    char ip[64];
    if (!resolve_host(config.host, ip)) {
        return 1;
    }

    print_banner();
    printf("  [*] Target:  %s (%s)\n", config.host, ip);
    printf("  [*] Porturi: %d - %d\n", config.port_start, config.port_end);
    printf("  [*] Timeout: %d ms\n\n", config.timeout_ms);
    printf("  Scanare in curs...\n\n");

    int open_count = 0;
    PortResult *results = scan_range(ip, &config, &open_count);

    print_result(results, open_count, config.host);

    free(results);
    return 0;
}