#include <stdio.h>
#include "../include/explain.h"

// Risk assumes the port is reachable by people you don't trust (internet, guest Wi-Fi).
static const PortAdvice advice[] = {
    { 21,    0, "FTP",           RISK_HIGH,     "Sends passwords and files unencrypted; often allows anonymous login.",
                                                "Replace with SFTP, or at least disable anonymous login." },
    { 22,    0, "SSH",           RISK_LOW,      "Safe when patched, but bots constantly try to guess passwords.",
                                                "Use key-only login (PasswordAuthentication no) and keep it updated." },
    { 23,    0, "Telnet",        RISK_CRITICAL, "Remote shell with no encryption; passwords travel in plain text.",
                                                "Turn it off and use SSH instead." },
    { 25,    0, "SMTP",          RISK_MEDIUM,   "Mail server; if misconfigured as an open relay, spammers can abuse it.",
                                                "Make sure relaying requires authentication." },
    { 53,    0, "DNS",           RISK_MEDIUM,   "An open resolver can be used in DDoS amplification attacks.",
                                                "Only answer queries from your own network." },
    { 80,    0, "HTTP",          RISK_MEDIUM,   "Website without encryption; logins and cookies can be sniffed.",
                                                "Redirect everything to HTTPS." },
    { 110,   0, "POP3",          RISK_HIGH,     "Email login sent in plain text.",
                                                "Use POP3S (port 995) instead." },
    { 135,   0, "MS-RPC",        RISK_HIGH,     "Windows RPC; a frequent target for worms and lateral movement.",
                                                "Block it at the firewall; never expose it to the internet." },
    { 139,   0, "NetBIOS",       RISK_HIGH,     "Old Windows file sharing; leaks computer and user names.",
                                                "Disable NetBIOS over TCP/IP or firewall it." },
    { 143,   0, "IMAP",          RISK_HIGH,     "Email login sent in plain text.",
                                                "Use IMAPS (port 993) instead." },
    { 443,   0, "HTTPS",         RISK_LOW,      "Encrypted website; normal to have open.",
                                                "Keep the web server and TLS certificate up to date." },
    { 445,   0, "SMB",           RISK_CRITICAL, "Windows file sharing; exploited by WannaCry and many ransomware worms.",
                                                "Never expose to the internet; firewall it and disable SMBv1." },
    { 1433,  0, "MSSQL",         RISK_HIGH,     "Database open to the network; target of password-guessing attacks.",
                                                "Allow only your app servers through the firewall." },
    { 1883,  0, "MQTT",          RISK_HIGH,     "IoT messaging, often with no password; attackers can control devices.",
                                                "Require a username/password and use TLS (port 8883)." },
    { 2375,  0, "Docker API",    RISK_CRITICAL, "Unauthenticated Docker control = full control of the machine.",
                                                "Close it now; use the local socket or TLS on 2376." },
    { 3306,  0, "MySQL",         RISK_HIGH,     "Database open to the network; target of password-guessing attacks.",
                                                "Bind to 127.0.0.1 or allow only trusted IPs." },
    { 3389,  0, "RDP",           RISK_HIGH,     "Windows remote desktop; a top entry point for ransomware.",
                                                "Put it behind a VPN and enable Network Level Authentication." },
    { 5432,  0, "PostgreSQL",    RISK_HIGH,     "Database open to the network; target of password-guessing attacks.",
                                                "Bind to 127.0.0.1 or restrict pg_hba.conf to trusted IPs." },
    { 5900,  0, "VNC",           RISK_CRITICAL, "Remote screen control, often with a weak or no password.",
                                                "Put it behind a VPN or SSH tunnel and set a strong password." },
    { 6379,  0, "Redis",         RISK_CRITICAL, "Usually has no password; anyone can read data and often run commands.",
                                                "Bind to 127.0.0.1 and set requirepass." },
    { 8080,  0, "HTTP-Alt",      RISK_MEDIUM,   "Often an admin panel or dev server left open by accident.",
                                                "Check what runs here; close it or put it behind a login and HTTPS." },
    { 9200,  0, "Elasticsearch", RISK_CRITICAL, "Often has no login; whole databases have leaked this way.",
                                                "Enable security (xpack) and never expose it publicly." },
    { 11211, 0, "Memcached",     RISK_CRITICAL, "No authentication; data leaks and huge DDoS amplification.",
                                                "Bind to 127.0.0.1 and disable UDP." },
    { 27017, 0, "MongoDB",       RISK_CRITICAL, "Old setups have no login; frequently wiped and held for ransom.",
                                                "Enable authentication and bind to 127.0.0.1." },
    { 53,    1, "DNS",           RISK_MEDIUM,   "An open resolver can be used in DDoS amplification attacks.",
                                                "Only answer queries from your own network." },
    { 69,    1, "TFTP",          RISK_HIGH,     "No passwords at all; anyone can download (or upload) files.",
                                                "Disable it unless you are actively booting devices from it." },
    { 123,   1, "NTP",           RISK_MEDIUM,   "Old servers can be abused for DDoS amplification.",
                                                "Disable 'monlist' and keep NTP updated." },
    { 161,   1, "SNMP",          RISK_HIGH,     "Default 'public' community leaks device config and network info.",
                                                "Change the community string or use SNMPv3." },
    { 1900,  1, "SSDP/UPnP",     RISK_MEDIUM,   "Lets devices open router ports on their own; used in DDoS attacks.",
                                                "Disable UPnP on the router if you don't need it." },
};

static const PortAdvice unknown_advice = {
    0, 0, "unknown", RISK_LOW, "Not a well-known service.",
    "Find out what is listening (ss -tlnp) and close it if you don't need it."
};

static const char *risk_name[] = { "LOW", "MEDIUM", "HIGH", "CRITICAL" };
static const int   penalty[]   = { 2, 10, 25, 50 };

const PortAdvice *find_advice(int port, int udp) {
    for (size_t i = 0; i < sizeof(advice) / sizeof(advice[0]); i++)
        if (advice[i].port == port && advice[i].udp == udp) return &advice[i];
    return &unknown_advice;
}

int security_score(const PortResult *results, int count, int udp) {
    int score = 100;
    for (int i = 0; i < count; i++)
        score -= penalty[find_advice(results[i].port, udp)->risk];
    return score < 0 ? 0 : score;
}

char score_to_grade(int score) {
    if (score >= 90) return 'A';
    if (score >= 75) return 'B';
    if (score >= 60) return 'C';
    if (score >= 40) return 'D';
    return 'F';
}

void explain_host(FILE *f, const char *label, const PortResult *results, int count, int udp) {
    int per_risk[4] = {0};

    fprintf(f, "  Security report for %s\n", label);
    fprintf(f, "  ──────────────────────────────────────────────────────\n");
    for (int i = 0; i < count; i++) {
        const PortAdvice *a = find_advice(results[i].port, udp);
        per_risk[a->risk]++;
        fprintf(f, "  [%-8s] %-6d %-14s %s\n", risk_name[a->risk], results[i].port, a->name, a->why);
        fprintf(f, "  %33s-> %s\n", "", a->fix);
    }

    int score = security_score(results, count, udp);
    fprintf(f, "\n  Grade: %c (%d/100)  %d critical, %d high, %d medium, %d low\n",
            score_to_grade(score), score,
            per_risk[RISK_CRITICAL], per_risk[RISK_HIGH], per_risk[RISK_MEDIUM], per_risk[RISK_LOW]);
    if (count == 0) fprintf(f, "  Nothing open in the scanned range. Nice.\n");
    fprintf(f, "  (Risk assumes these ports are reachable by people you don't trust.)\n\n");
}
