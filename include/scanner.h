#ifndef SCANNER_H
#define SCANNER_H

#define MAX_PORTS 65535
#define DEFAULT_TIMEOUT 1000
#define MAX_HOST_LEN 256

typedef struct {
    char host[MAX_HOST_LEN];
    int port_start;
    int port_end;
    int timeout_ms;
    int verbose;
    int explain;
    char output_file[256];
} ScanConfig;

typedef struct {
    int port;
    int open;
    char service[32];
    char banner[256];
    double response_time_ms;
} PortResult;

int scan_port(const char *ip, int port, int timeout_ms);
PortResult **scan_hosts(char **ips, int n, ScanConfig *config, int udp, int *open_counts);
const char* get_service_name(int port);
void grab_banner(const char *ip, int port, int timeout_ms, char *banner_out, int banner_len);

#endif
