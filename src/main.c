#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/scanner.h"
#include "../include/utils.h"
#include "../include/cidr.h"
#include "../include/udp_scanner.h"

void usage(const char *prog) {
    printf("Usage: %s -h <host/CIDR> [-p <start-end>] [-t <timeout_ms>] [-o <file>] [-u]\n", prog);
    printf("  -h  host, IP or CIDR (ex: 192.168.1.0/24)\n");
    printf("  -p  port range (ex: 1-1000, default: 1-1024)\n");
    printf("  -t  timeout in ms (default: 1000)\n");
    printf("  -u  UDP scan mode\n");
    printf("  -v  verbose\n");
    printf("  -o  save results to file\n\n");
    printf("Examples:\n");
    printf("  ./netscanner -h scanme.nmap.org\n");
    printf("  ./netscanner -h scanme.nmap.org -u -p 1-200\n");
    printf("  ./netscanner -h 192.168.1.0/24 -p 22-443 -t 500\n\n");
}

int main(int argc, char *argv[]) {
    ScanConfig config;
    memset(&config, 0, sizeof(config));

    config.port_start = 1;
    config.port_end   = 1024;
    config.timeout_ms = DEFAULT_TIMEOUT;
    config.verbose    = 0;
    config.output_file[0] = '\0';
    int udp_mode = 0;

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
        } else if (strcmp(argv[i], "-u") == 0) {
            udp_mode = 1;
        } else if (strcmp(argv[i], "-o") == 0 && i+1 < argc) {
            strncpy(config.output_file, argv[++i], 255);
        }
    }

    if (strlen(config.host) == 0) {
        fprintf(stderr, "[-] You must specify a host with -h\n\n");
        usage(argv[0]);
        return 1;
    }

    print_banner();

    int is_cidr = strchr(config.host, '/') != NULL;

    if (is_cidr) {
        char **ips = NULL;
        int ip_count = 0;

        if (!cidr_to_ips(config.host, (char **)&ips, &ip_count)) {
            return 1;
        }

        printf("  [*] CIDR:    %s (%d hosts)\n", config.host, ip_count);
        printf("  [*] Ports:   %d - %d\n", config.port_start, config.port_end);
        printf("  [*] Timeout: %d ms\n\n", config.timeout_ms);

        for (int i = 0; i < ip_count; i++) {
            char *ip = ((char **)ips)[i];
            printf("  [*] Scanning: %s\n", ip);

            int open_count = 0;
            PortResult *results = udp_mode
                ? scan_udp_range(ip, &config, &open_count)
                : scan_range(ip, &config, &open_count);

            if (open_count > 0)
                print_result(results, open_count, ip);

            free(results);
            free(ip);
        }

        free(ips);

    } else {
        char ip[64];
        if (!resolve_host(config.host, ip)) {
            return 1;
        }

        printf("  [*] Target:  %s (%s)\n", config.host, ip);
        printf("  [*] Ports:   %d - %d\n", config.port_start, config.port_end);
        printf("  [*] Timeout: %d ms\n", config.timeout_ms);
        printf("  [*] Mode:    %s\n\n", udp_mode ? "UDP" : "TCP");
        printf("  Scanning...\n\n");

        int open_count = 0;
        PortResult *results = udp_mode
            ? scan_udp_range(ip, &config, &open_count)
            : scan_range(ip, &config, &open_count);

        print_result(results, open_count, config.host);

        if (strlen(config.output_file) > 0) {
            FILE *f = fopen(config.output_file, "w");
            if (f) {
                fprintf(f, "NetScanner Results\n");
                fprintf(f, "Host: %s (%s)\n", config.host, ip);
                fprintf(f, "Mode: %s\n", udp_mode ? "UDP" : "TCP");
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
                printf("  [*] Results saved to: %s\n\n", config.output_file);
            }
        }

        free(results);
    }

    return 0;
}
