#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../include/udp_scanner.h"
#include "../include/scanner.h"

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
