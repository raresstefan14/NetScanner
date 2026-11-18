#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/scanner.h"
#include "../include/utils.h"
#include "../include/cidr.h"
#include "../include/udp_scanner.h"
#include "../include/os_detect.h"

void usage(const char *prog) {
    printf("Usage: %s -h <host/CIDR> [-p <start-end>] [-t <timeout_ms>] [-o <file>] [-u]\n", prog);
    printf("  -h  host, IP or CIDR (ex: 192.168.1.0/24)\n");
    printf("  -p  port or port range (ex: 80 or 1-1000, default: 1-1024)\n");
    printf("  -t  timeout in ms (default: 1000)\n");
    printf("  -u  UDP scan mode\n");
    printf("  -v  verbose\n");
    printf("  -o  save results to file\n\n");
    printf("Examples:\n");
    printf("  ./netscanner -h scanme.nmap.org\n");
    printf("  ./netscanner -h scanme.nmap.org -u -p 1-200\n");
    printf("  ./netscanner -h 192.168.1.0/24 -p 22-443 -t 500\n\n");
}

static void write_host(FILE *f, const char *label, const char *ip, int udp,
                       ScanConfig *config, PortResult *results, int open_count) {
    fprintf(f, "Host: %s (%s)\n", label, ip);
    fprintf(f, "Mode: %s\n", udp ? "UDP" : "TCP");
    fprintf(f, "Ports: %d-%d\n", config->port_start, config->port_end);
    fprintf(f, "Open ports: %d\n\n", open_count);
    fprintf(f, "%-8s %-15s %-10s %s\n", "PORT", "SERVICE", "TIME(ms)", "BANNER");
    fprintf(f, "------------------------------------------------\n");
    for (int i = 0; i < open_count; i++)
        fprintf(f, "%-8d %-15s %-10.1f %s\n", results[i].port, results[i].service,
                results[i].response_time_ms, results[i].banner);
    fprintf(f, "\n");
}

int main(int argc, char *argv[]) {
    ScanConfig config;
    memset(&config, 0, sizeof(config));

    config.port_start = 1;
    config.port_end   = 1024;
    config.timeout_ms = DEFAULT_TIMEOUT;
    int udp_mode = 0;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 && i+1 < argc) {
            strncpy(config.host, argv[++i], MAX_HOST_LEN - 1);
        } else if (strcmp(argv[i], "-p") == 0 && i+1 < argc) {
            int a, b, n = sscanf(argv[++i], "%d-%d", &a, &b);
            if (n == 1) b = a;  // "-p 80" means just port 80
            if (n < 1 || a < 1 || b > 65535 || a > b) {
                fprintf(stderr, "[-] Invalid port range: %s (use e.g. 80 or 1-1000, max 65535)\n", argv[i]);
                return 1;
            }
            config.port_start = a;
            config.port_end   = b;
        } else if (strcmp(argv[i], "-t") == 0 && i+1 < argc) {
            config.timeout_ms = atoi(argv[++i]);
            if (config.timeout_ms <= 0) {
                fprintf(stderr, "[-] Timeout must be a positive number of ms\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-v") == 0) {
            config.verbose = 1;
        } else if (strcmp(argv[i], "-u") == 0) {
            udp_mode = 1;
        } else if (strcmp(argv[i], "-o") == 0 && i+1 < argc) {
            strncpy(config.output_file, argv[++i], sizeof(config.output_file) - 1);
        } else {
            fprintf(stderr, "[-] Unknown or incomplete option: %s\n\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (strlen(config.host) == 0) {
        fprintf(stderr, "[-] You must specify a host with -h\n\n");
        usage(argv[0]);
        return 1;
    }

    int is_cidr = strchr(config.host, '/') != NULL;
    char **ips = NULL;
    int ip_count = 0;

    if (is_cidr) {
        if (!cidr_to_ips(config.host, &ips, &ip_count)) return 1;
    } else {
        ips = malloc(sizeof(char *));
        ips[0] = malloc(64);
        if (!resolve_host(config.host, ips[0])) return 1;
        ip_count = 1;
    }

    FILE *out = NULL;
    if (config.output_file[0]) {
        out = fopen(config.output_file, "w");
        if (!out) { perror("[-] Cannot open output file"); return 1; }
        fprintf(out, "NetScanner Results\n\n");
    }

    print_banner();
    if (is_cidr) printf("  [*] CIDR:    %s (%d hosts)\n", config.host, ip_count);
    else         printf("  [*] Target:  %s (%s)\n", config.host, ips[0]);
    printf("  [*] Ports:   %d - %d\n", config.port_start, config.port_end);
    printf("  [*] Timeout: %d ms\n", config.timeout_ms);
    printf("  [*] Mode:    %s\n\n", udp_mode ? "UDP" : "TCP");
    printf("  Scanning...\n\n");

    // Scan several hosts at once, but cap results memory (~30 MB) for big port ranges.
    int ports = config.port_end - config.port_start + 1;
    int group = 100000 / ports;
    if (group < 1) group = 1;
    int *counts = malloc(sizeof(int) * group);

    for (int g = 0; g < ip_count; g += group) {
        int n = ip_count - g < group ? ip_count - g : group;
        PortResult **results = scan_hosts(ips + g, n, &config, udp_mode, counts);

        for (int h = 0; h < n; h++) {
            const char *ip = ips[g + h];
            // In a subnet scan, hosts with nothing open are just noise.
            if (is_cidr && counts[h] == 0) { free(results[h]); continue; }

            const char *best_banner = "";
            for (int j = 0; j < counts[h]; j++)
                if (results[h][j].banner[0]) { best_banner = results[h][j].banner; break; }
            OsResult os = detect_os(ip, best_banner);

            const char *label = is_cidr ? ip : config.host;
            print_result(results[h], counts[h], label);
            print_os_result(&os);
            if (out) write_host(out, label, ip, udp_mode, &config, results[h], counts[h]);
            free(results[h]);
        }
        free(results);
    }

    if (out) {
        fclose(out);
        printf("  [*] Results saved to: %s\n\n", config.output_file);
    }

    for (int i = 0; i < ip_count; i++) free(ips[i]);
    free(ips);
    free(counts);
    return 0;
}
