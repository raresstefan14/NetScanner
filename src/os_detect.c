#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "os_detect.h"

static int resolve_host(const char *host, char *ip_out, size_t ip_len)
{
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return 0;
    struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &sa->sin_addr, ip_out, (socklen_t)ip_len);
    freeaddrinfo(res);
    return 1;
}

static OsResult ttl_to_os(int ttl)
{
    OsResult r;
    r.method = "TTL";
    if (ttl <= 0)        { r.os_name = OS_UNKNOWN; r.confidence = 0;  }
    else if (ttl <= 64)  { r.os_name = OS_LINUX;   r.confidence = 60; }
    else if (ttl <= 128) { r.os_name = OS_WINDOWS; r.confidence = 80; }
    else                 { r.os_name = OS_CISCO;   r.confidence = 70; }
    return r;
}

static unsigned short icmp_checksum(unsigned short *buf, int len)
{
    unsigned long sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len) sum += *(unsigned char *)buf;
    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

OsResult detect_os_from_ttl(const char *host)
{
    OsResult fail = { OS_UNKNOWN, "TTL", 0 };
    char ip[INET_ADDRSTRLEN];
    if (!resolve_host(host, ip, sizeof ip)) return fail;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return fail;

    struct { struct icmphdr hdr; char data[32]; } pkt;
    memset(&pkt, 0, sizeof pkt);
    pkt.hdr.type             = ICMP_ECHO;
    pkt.hdr.un.echo.id       = (unsigned short)getpid();
    pkt.hdr.un.echo.sequence = 1;
    memset(pkt.data, 0xAB, sizeof pkt.data);
    pkt.hdr.checksum = icmp_checksum((unsigned short *)&pkt, sizeof pkt);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &dst.sin_addr);

    if (sendto(sock, &pkt, sizeof pkt, 0, (struct sockaddr *)&dst, sizeof dst) < 0) {
        close(sock); return fail;
    }

    fd_set fds; FD_ZERO(&fds); FD_SET(sock, &fds);
    struct timeval tv = { 2, 0 };
    if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0) { close(sock); return fail; }

    char buf[1024];
    struct sockaddr_in src;
    socklen_t src_len = sizeof src;
    ssize_t n = recvfrom(sock, buf, sizeof buf, 0, (struct sockaddr *)&src, &src_len);
    close(sock);

    if (n < (ssize_t)(sizeof(struct iphdr) + sizeof(struct icmphdr))) return fail;
    return ttl_to_os(((struct iphdr *)buf)->ttl);
}

typedef struct { const char *pattern; const char *os; int confidence; } BannerRule;

static const BannerRule banner_rules[] = {
    { "Ubuntu",    OS_LINUX,   95 }, { "Debian",    OS_LINUX,   95 },
    { "CentOS",    OS_LINUX,   95 }, { "Fedora",    OS_LINUX,   95 },
    { "Red Hat",   OS_LINUX,   95 }, { "Arch",      OS_LINUX,   90 },
    { "Alpine",    OS_LINUX,   90 }, { "Linux",     OS_LINUX,   85 },
    { "Android",   OS_ANDROID, 95 }, { "Windows",   OS_WINDOWS, 95 },
    { "Microsoft", OS_WINDOWS, 90 }, { "IIS",       OS_WINDOWS, 85 },
    { "Darwin",    OS_MACOS,   95 }, { "macOS",     OS_MACOS,   95 },
    { "FreeBSD",   OS_FREEBSD, 95 }, { "OpenBSD",   OS_FREEBSD, 90 },
    { "Cisco",     OS_CISCO,   95 }, { "Apache",    OS_LINUX,   50 },
    { "nginx",     OS_LINUX,   50 }, { NULL, NULL, 0 }
};

OsResult detect_os_from_banner(const char *banner)
{
    OsResult fail = { OS_UNKNOWN, "Banner", 0 };
    if (!banner || !*banner) return fail;
    for (int i = 0; banner_rules[i].pattern != NULL; i++) {
        if (strcasestr(banner, banner_rules[i].pattern)) {
            OsResult r = { banner_rules[i].os, "Banner", banner_rules[i].confidence };
            return r;
        }
    }
    return fail;
}

OsResult detect_os(const char *host, const char *banner)
{
    if (banner && *banner) {
        OsResult br = detect_os_from_banner(banner);
        if (br.confidence >= 80) return br;
    }
    OsResult tr = detect_os_from_ttl(host);
    if (tr.confidence > 0) return tr;
    if (banner && *banner) return detect_os_from_banner(banner);
    OsResult unknown = { OS_UNKNOWN, "N/A", 0 };
    return unknown;
}

void print_os_result(const OsResult *r)
{
    if (r->confidence == 0) {
        printf("  [*] OS Detection : Unknown\n");
        printf("  [*] OS Family    : Unknown\n");
        printf("  [*] Confidence   : 0%%\n\n");
    } else {
        printf("  [*] OS Detection : %s (%s)\n", r->os_name, r->method);
        printf("  [*] OS Family    : %s\n", r->os_name);
        printf("  [*] Confidence   : %d%%\n\n", r->confidence);
    }
}

