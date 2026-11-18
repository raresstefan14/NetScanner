#ifndef EXPLAIN_H
#define EXPLAIN_H

#include <stdio.h>
#include "scanner.h"

typedef enum { RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL } Risk;

typedef struct {
    int         port;
    int         udp;
    const char *name;
    Risk        risk;
    const char *why;   // what an attacker can do with it
    const char *fix;   // what the owner should do
} PortAdvice;

const PortAdvice *find_advice(int port, int udp);
int  security_score(const PortResult *results, int count, int udp);
char score_to_grade(int score);
void explain_host(FILE *f, const char *label, const PortResult *results, int count, int udp);

#endif
