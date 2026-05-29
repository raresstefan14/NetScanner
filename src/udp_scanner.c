#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "../include/udp_scanner.h"
#include "../include/scanner.h"

typedef struct {
    const char *ip;
    int port;
    int timeout_ms;
    PortResult *result;
} UDPArg;

const char* get_udp_probe(int port, int *len) {
    static const char dns_probe[] = {
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 'v','e','r','s','i','o','n',
        0x04, 'b','i','n','d', 0x00, 0x00, 0x10, 0x00, 0x03
    };
    static const char snmp_probe[] = {
        0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06,
        'p','u','b','l','i','c',
        0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b,
        0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02,
        0x01, 0x05, 0x00
    };
    switch (port) {
        case 53:  *len = sizeof(dns_probe);  return dns_probe;
        case 161: *len = sizeof(snmp_probe); return snmp_probe;
        default:  *len = 0; return NULL;
    }
}

int scan_udp_port(const char *ip, int port, int timeout_ms) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return 0;

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    int probe_len = 0;
    const char *probe = get_udp_probe(port, &probe_len);

    if (probe && probe_len > 0)
        sendto(sockfd, probe, probe_len, 0, (struct sockaddr*)&addr, sizeof(addr));
    else {
        char empty = 0;
        sendto(sockfd, &empty, 1, 0, (struct sockaddr*)&addr, sizeof(addr));
    }

    char buf[1024];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    int n = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&from, &from_len);

    close(sockfd);
    return n > 0 ? 1 : 0;
}

static void *udp_thread(void *arg) {
    UDPArg *a = (UDPArg *)arg;

    struct timeval t1, t2;
    gettimeofday(&t1, NULL);
    int open = scan_udp_port(a->ip, a->port, a->timeout_ms);
    gettimeofday(&t2, NULL);

    double elapsed = (t2.tv_sec - t1.tv_sec) * 1000.0 +
                     (t2.tv_usec - t1.tv_usec) / 1000.0;

    a->result->port = a->port;
    a->result->open = open;
    a->result->response_time_ms = elapsed;
    a->result->banner[0] = '\0';
    strncpy(a->result->service, get_service_name(a->port), 31);

    if (open) {
        printf("  [+] UDP Port %-6d %-12s %.1f ms\n",
               a->port, a->result->service, elapsed);
        fflush(stdout);
    }

    return NULL;
}

PortResult* scan_udp_range(const char *ip, ScanConfig *config, int *open_count) {
    int total = config->port_end - config->port_start + 1;
    PortResult *all_results = malloc(sizeof(PortResult) * total);
    PortResult *open_results = malloc(sizeof(PortResult) * total);
    memset(all_results, 0, sizeof(PortResult) * total);
    *open_count = 0;

    pthread_t threads[100];
    UDPArg args[100];
    int i = 0;

    while (i < total) {
        int batch = (total - i < 100) ? total - i : 100;

        for (int j = 0; j < batch; j++) {
            args[j].ip         = ip;
            args[j].port       = config->port_start + i + j;
            args[j].timeout_ms = config->timeout_ms;
            args[j].result     = &all_results[i + j];
            pthread_create(&threads[j], NULL, udp_thread, &args[j]);
        }

        for (int j = 0; j < batch; j++)
            pthread_join(threads[j], NULL);

        i += batch;
    }

    for (int j = 0; j < total; j++) {
        if (all_results[j].open)
            open_results[(*open_count)++] = all_results[j];
    }

    free(all_results);
    return open_results;
}
