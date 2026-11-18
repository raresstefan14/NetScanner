#ifndef UDP_SCANNER_H
#define UDP_SCANNER_H

#include "scanner.h"

typedef struct {
    unsigned char *payload;
    int payload_len;
} UDPProbe;

int scan_udp_port(const char *ip, int port, int timeout_ms);
const char* get_udp_probe(int port, int *len);

#endif
