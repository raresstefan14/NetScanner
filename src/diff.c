#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include "../include/diff.h"
#include "../include/explain.h"

#define STATE_HEADER "# netscanner-state"

// Loads a state file. Returns entry count, 0 with *when = 0 if the file doesn't exist,
// or -1 if it exists but isn't a NetScanner state file (so we never overwrite it).
static int state_load(const char *path, StateEntry **out, time_t *when) {
    *out = NULL;
    *when = 0;
    FILE *f = fopen(path, "r");
    if (!f) return errno == ENOENT ? 0 : -1;

    char line[512];
    long long t;
    if (!fgets(line, sizeof line, f) || sscanf(line, STATE_HEADER " %lld", &t) != 1) {
        fclose(f);
        return -1;
    }
    *when = (time_t)t;

    int n = 0, cap = 0;
    while (fgets(line, sizeof line, f)) {
        StateEntry e = {0};
        char proto[4];
        int off = 0;
        if (sscanf(line, "%15s %3s %d %n", e.ip, proto, &e.port, &off) < 3) continue;
        e.udp = strcmp(proto, "udp") == 0;
        line[strcspn(line, "\r\n")] = '\0';
        strncpy(e.banner, line + off, sizeof(e.banner) - 1);

        if (n == cap) {
            cap = cap ? cap * 2 : 64;
            *out = realloc(*out, sizeof(StateEntry) * cap);
        }
        (*out)[n++] = e;
    }
    fclose(f);
    return n;
}

static const StateEntry *find(const StateEntry *list, int n, const StateEntry *e) {
    for (int i = 0; i < n; i++)
        if (list[i].port == e->port && list[i].udp == e->udp && strcmp(list[i].ip, e->ip) == 0)
            return &list[i];
    return NULL;
}

static int in_scope(const StateEntry *e, char **ips, int ip_count, const ScanConfig *c, int udp) {
    if (e->udp != udp || e->port < c->port_start || e->port > c->port_end) return 0;
    for (int i = 0; i < ip_count; i++)
        if (strcmp(ips[i], e->ip) == 0) return 1;
    return 0;
}

static void fmt_ago(time_t when, char *buf, size_t len) {
    long s = (long)difftime(time(NULL), when);
    if (s < 3600)       snprintf(buf, len, "%ld min ago", s / 60);
    else if (s < 86400) snprintf(buf, len, "%ld h ago", s / 3600);
    else                snprintf(buf, len, "%ld days ago", s / 86400);
}

static void print_entry(const char *tag, const StateEntry *e) {
    const PortAdvice *a = find_advice(e->port, e->udp);
    printf("  [%-7s] %-15s %s %-6d %-14s", tag, e->ip, e->udp ? "UDP" : "TCP", e->port, a->name);
}

static int save(const char *path, const StateEntry *old, int n_old, const StateEntry *cur, int n_cur,
                char **ips, int ip_count, const ScanConfig *c, int udp) {
    // Write to a temp file and rename, so a crash never leaves a half-written state.
    char tmp[300];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    fprintf(f, STATE_HEADER " %lld\n", (long long)time(NULL));
    for (int i = 0; i < n_old; i++)
        if (!in_scope(&old[i], ips, ip_count, c, udp))
            fprintf(f, "%s %s %d %s\n", old[i].ip, old[i].udp ? "udp" : "tcp", old[i].port, old[i].banner);
    for (int i = 0; i < n_cur; i++)
        fprintf(f, "%s %s %d %s\n", cur[i].ip, cur[i].udp ? "udp" : "tcp", cur[i].port, cur[i].banner);
    if (fclose(f) != 0 || rename(tmp, path) != 0) { remove(tmp); return -1; }
    return 0;
}

int diff_and_save(const char *path, const StateEntry *cur, int n_cur,
                  char **ips, int ip_count, const ScanConfig *config, int udp) {
    StateEntry *old;
    time_t when;
    int n_old = state_load(path, &old, &when);
    if (n_old < 0) {
        fprintf(stderr, "[-] %s exists but is not a NetScanner state file; not touching it\n", path);
        return -1;
    }

    int changes = 0;
    if (when == 0) {
        printf("  [*] No previous scan in %s: saving this one as the baseline.\n\n", path);
    } else {
        char date[32], ago[32];
        strftime(date, sizeof date, "%Y-%m-%d %H:%M", localtime(&when));
        fmt_ago(when, ago, sizeof ago);
        printf("  Changes since last scan (%s, %s)\n", date, ago);
        printf("  ──────────────────────────────────────────────────────\n");

        for (int i = 0; i < n_cur; i++) {
            const StateEntry *was = find(old, n_old, &cur[i]);
            if (!was) {
                print_entry("NEW", &cur[i]);
                printf(" %s risk\n", risk_label(find_advice(cur[i].port, udp)->risk));
                changes++;
            } else if (was->banner[0] && cur[i].banner[0] && strcmp(was->banner, cur[i].banner) != 0) {
                // Only compare when both scans got a banner: banner grabs sometimes time out.
                print_entry("CHANGED", &cur[i]);
                printf(" %s -> %s\n", was->banner, cur[i].banner);
                changes++;
            }
        }
        for (int i = 0; i < n_old; i++) {
            if (in_scope(&old[i], ips, ip_count, config, udp) && !find(cur, n_cur, &old[i])) {
                print_entry("CLOSED", &old[i]);
                printf("\n");
                changes++;
            }
        }
        if (changes == 0) printf("  No changes.\n");
        printf("\n");
    }

    if (save(path, old, n_old, cur, n_cur, ips, ip_count, config, udp) != 0) {
        perror("[-] Cannot save state file");
        free(old);
        return -1;
    }
    printf("  [*] State saved to: %s\n\n", path);
    free(old);
    return changes;
}
