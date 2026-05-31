#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "../include/utils.h"

int resolve_host(const char *hostname, char *ip_out) {
    struct hostent *he;
    struct in_addr **addr_list;

    if (inet_addr(hostname) != INADDR_NONE) {
        strcpy(ip_out, hostname);
        return 1;
    }

    he = gethostbyname(hostname);
    if (he == NULL) {
        fprintf(stderr, "[-] Cannot resolve host: %s\n", hostname);
        return 0;
    }

    addr_list = (struct in_addr **)he->h_addr_list;
    strcpy(ip_out, inet_ntoa(*addr_list[0]));
    return 1;
}

void print_banner() {
    printf("\n");
    printf("  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ \n");
    printf("  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗\n");
    printf("  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝\n");
    printf("  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗\n");
    printf("  ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║\n");
    printf("  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝\n");
    printf("                              NetScanner v1.0\n\n");
}

void print_progress(int current, int total) {
    int bar_width = 40;
    float percent = (float)current / total;
    int filled = (int)(percent * bar_width);

    printf("  [");
    for (int i = 0; i < bar_width; i++) {
        if (i < filled)
            printf("#");
        else
            printf(".");
    }
    printf("] %d/%d (%.0f%%)\n", current, total, percent * 100);
    fflush(stdout);
}

void print_result(PortResult *results, int count, const char *host) {
    printf("\n  ┌─────────────────────────────────────────┐\n");
    printf("  │  Host: %-32s │\n", host);
    printf("  │  Open ports: %-27d │\n", count);
    printf("  └─────────────────────────────────────────┘\n\n");

    if (count == 0) {
        printf("  [-] No open ports found.\n");
        return;
    }

    printf("  %-8s %-15s %-10s %s\n", "PORT", "SERVICE", "TIME", "BANNER");
    printf("  ──────────────────────────────────────────────────────\n");
    for (int i = 0; i < count; i++) {
        printf("  %-8d %-15s %-10.1f %s\n",
               results[i].port,
               results[i].service,
               results[i].response_time_ms,
               results[i].banner[0] ? results[i].banner : "");
    }
    printf("\n");
}
