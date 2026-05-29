#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/scanner.h"
#include "../include/utils.h"

void usage(const char *prog) {
    printf("Utilizare: %s -h <host> [-p <start-end>] [-t <timeout_ms>] [-o <fisier>]\n", prog);
    printf("  -h  host sau IP (ex: scanme.nmap.org)\n");
    printf("  -p  range porturi (ex: 1-1000, default: 1-1024)\n");
    printf("  -t  timeout in ms (default: 1000)\n");
    printf("  -v  verbose\n");
    printf("  -o  salveaza rezultatele intr-un fisier\n\n");
    printf("Exemple:\n");
    printf("  %s -h scanme.nmap.org\n", prog);
    printf("  ./netscanner -h 192.168.1.1 -p 1-500 -t 500\n");
    printf("  %s -h scanme.nmap.org -o results.txt\n\n", prog);
}

int main(int argc, char *argv[]) {
    ScanConfig config;
    memset(&config, 0, sizeof(config));

    config.port_start = 1;
    config.port_end   = 1024;
    config.timeout_ms = DEFAULT_TIMEOUT;
    config.verbose    = 0;
    config.output_file[0] = '\0';

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 && i+1 < argc) {
            strncpy(config.host, argv[++i], MAX_HOST_LEN - 1);
        } else if (strcmp(argv[i], "-p") == 0 && i+1 < argc) {
            sscanf(argv[++i], "%d-%d", &config.port_start, &config.port_end);
        } else if (strcmp(argv[i], "-t") == 0 && i+1 < argc) {
            config.timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0) {
            config.verbose = 1;
        } else if (strcmp(argv[i], "-o") == 0 && i+1 < argc) {
            strncpy(config.output_file, argv[++i], 255);
        }
    }

    if (strlen(config.host) == 0) {
        fprintf(stderr, "[-] Trebuie sa specifici un host cu -h\n\n");
        usage(argv[0]);
        return 1;
    }

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

    if (strlen(config.output_file) > 0) {
        FILE *f = fopen(config.output_file, "w");
        if (f) {
            fprintf(f, "NetScanner Results\n");
            fprintf(f, "Host: %s (%s)\n", config.host, ip);
            fprintf(f, "Ports: %d-%d\n", config.port_start, config.port_end);
            fprintf(f, "Open ports: %d\n\n", open_count);
            fprintf(f, "%-8s %-15s %-10s %s\n", "PORT", "SERVICE", "TIME(ms)", "BANNER");
            fprintf(f, "------------------------------------------------\n");
            for (int i = 0; i < open_count; i++) {
                fprintf(f, "%-8d %-15s %-10.1f %s\n",
                        results[i].port,
                        results[i].service,
                        results[i].response_time_ms,
                        results[i].banner[0] ? results[i].banner : "");
            }
            fclose(f);
            printf("  [*] Rezultate salvate in: %s\n\n", config.output_file);
        } else {
            printf("  [-] Nu pot deschide fisierul: %s\n\n", config.output_file);
        }
    }

    free(results);
    return 0;
}
