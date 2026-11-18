#ifndef DIFF_H
#define DIFF_H

#include "scanner.h"

typedef struct {
    char ip[16];
    int  udp;
    int  port;
    char banner[256];
} StateEntry;

// Compares this scan with the one saved in path, prints the changes and saves the new state.
// Only ports inside this scan's hosts, mode and port range are compared; other saved entries are kept.
// Returns the number of changes, or -1 if the state file could not be written.
int diff_and_save(const char *path, const StateEntry *cur, int n_cur,
                  char **ips, int ip_count, const ScanConfig *config, int udp);

#endif
