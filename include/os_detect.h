#ifndef OS_DETECT_H
#define OS_DETECT_H

#define OS_UNKNOWN      "Unknown"
#define OS_LINUX        "Linux"
#define OS_WINDOWS      "Windows"
#define OS_MACOS        "macOS / iOS"
#define OS_FREEBSD      "FreeBSD"
#define OS_CISCO        "Cisco IOS"
#define OS_ANDROID      "Android"

typedef struct {
    const char *os_name;
    const char *method;
    int         confidence;
} OsResult;

OsResult detect_os_from_ttl(const char *host);
OsResult detect_os_from_banner(const char *banner);
OsResult detect_os(const char *host, const char *banner);
void print_os_result(const OsResult *r);

#endif
