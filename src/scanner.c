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
#include <pthread.h>
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
void *thread_scan(void *arg) {
    ThreadArg *t = (ThreadArg *)arg;
    
    struct timeval t1, t2;
    gettimeofday(&t1, NULL);
    
    int is_open = scan_port(t->ip, t->port, t->timeout_ms);
    
    gettimeofday(&t2, NULL);
    double elapsed = (t2.tv_sec - t1.tv_sec) * 1000.0 +
                     (t2.tv_usec - t1.tv_usec) / 1000.0;
    
    t->result->port = t->port;
    t->result->open = is_open;
    t->result->response_time_ms = elapsed;
    strncpy(t->result->service, get_service_name(t->port), 31);
    t->result->banner[0] = '\0';
    
    if (is_open) {
        grab_banner(t->ip, t->port, t->timeout_ms, 
                    t->result->banner, sizeof(t->result->banner));
    }
    
    return NULL;
}
// Scaneaza un range de porturi si returneaza rezultatele
   PortResult* scan_range(const char *ip, ScanConfig *config, int *open_count) {
    int total = config->port_end - config->port_start + 1;
    PortResult *all_results = malloc(sizeof(PortResult) * total);
    PortResult *open_results = malloc(sizeof(PortResult) * total);
    *open_count = 0;

    pthread_t threads[MAX_THREADS];
    ThreadArg args[MAX_THREADS];

    int i = 0;
    while (i < total) {
        int batch = (total - i < MAX_THREADS) ? total - i : MAX_THREADS;

        for (int j = 0; j < batch; j++) {
            args[j].ip         = ip;
            args[j].port       = config->port_start + i + j;
            args[j].timeout_ms = config->timeout_ms;
            args[j].result     = &all_results[i + j];
            pthread_create(&threads[j], NULL, thread_scan, &args[j]);
        }

        for (int j = 0; j < batch; j++) {
            pthread_join(threads[j], NULL);
            if (all_results[i + j].open) {
                open_results[*open_count] = all_results[i + j];
                printf("  [+] Port %-6d %-12s %.1f ms\n",
                       open_results[*open_count].port,
                       open_results[*open_count].service,
                       open_results[*open_count].response_time_ms);
                fflush(stdout);
                (*open_count)++;
            }
        }

        i += batch;
    }

    free(all_results);
    return open_results;
}