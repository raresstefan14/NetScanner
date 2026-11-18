#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include "../include/scanner.h"
#include "../include/threadpool.h"
#define MAX_THREADS 100

// Returneaza numele serviciului pentru porturile comune
const char* get_service_name(int port) {
    switch(port) {
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 80:   return "HTTP";
        case 110:  return "POP3";
        case 143:  return "IMAP";
        case 443:  return "HTTPS";
        case 445:  return "SMB";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 6379: return "Redis";
        case 8080: return "HTTP-Alt";
        default:   return "unknown";
    }
}

int scan_port(const char *ip, int port, int timeout_ms) {
    int sockfd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return 0;

    // non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    int ret = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));

    int open = 0;

    if (ret == 0) {
        // conexiune imediata (localhost)
        open = 1;
    } else if (errno == EINPROGRESS) {
        // asteptam cu select()
        fd_set wset, eset;
        FD_ZERO(&wset);
        FD_ZERO(&eset);
        FD_SET(sockfd, &wset);
        FD_SET(sockfd, &eset);

        struct timeval tv;
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        ret = select(sockfd + 1, NULL, &wset, &eset, &tv);
if (ret > 0 && FD_ISSET(sockfd, &wset) && !FD_ISSET(sockfd, &eset)) {
    int so_error = 0;
    socklen_t len = sizeof(so_error);
    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
    
    if (so_error == 0) {
        char buf[1];
        int s = send(sockfd, buf, 0, 0);
        open = (s == 0) ? 1 : 0;
    }
}
    }
    // errno == ECONNREFUSED -> port inchis imediat

    close(sockfd);
    return open;
}
void grab_banner(const char *ip, int port, int timeout_ms, char *banner_out, int banner_len) {
    int sockfd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return;

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        // pentru HTTP trimitem un request ca sa primim raspuns
        if (port == 80 || port == 8080) {
            send(sockfd, "HEAD / HTTP/1.0\r\n\r\n", 19, 0);
        }
        
        char buf[256] = {0};
        int n = recv(sockfd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            // curatam newline-urile
            for (int i = 0; i < n; i++) {
                if (buf[i] == '\n' || buf[i] == '\r') {
                    buf[i] = '\0';
                    break;
                }
            }
            strncpy(banner_out, buf, banner_len - 1);
        }
    }

    close(sockfd);
}
// Scans every port of n hosts through one shared pool, so a slow port never blocks the others.
// Returns one array of open ports per host; open_counts[h] is its length.
PortResult **scan_hosts(char **ips, int n, ScanConfig *config, int udp, int *open_counts) {
    int ports = config->port_end - config->port_start + 1;
    PortResult **res = malloc(sizeof(PortResult *) * n);
    ThreadPool *pool = threadpool_create(MAX_THREADS);

    for (int h = 0; h < n; h++) {
        res[h] = calloc(ports, sizeof(PortResult));
        for (int p = 0; p < ports; p++)
            threadpool_add(pool, ips[h], config->port_start + p, config->timeout_ms, udp, &res[h][p]);
    }
    threadpool_wait(pool);
    threadpool_destroy(pool);

    for (int h = 0; h < n; h++) {
        int k = 0;
        for (int p = 0; p < ports; p++)
            if (res[h][p].open) res[h][k++] = res[h][p];
        open_counts[h] = k;
    }
    return res;
}
