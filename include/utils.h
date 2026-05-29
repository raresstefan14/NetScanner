#ifndef UTILS_H
#define UTILS_H

#include "scanner.h"

int resolve_host(const char *hostname, char *ip_out);
void print_banner();
void print_result(PortResult *results, int count, const char *host);

#endif