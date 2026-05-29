# NetScanner

A fast, multi-threaded TCP port scanner written in C.

Built from scratch using POSIX sockets and pthreads — no external libraries.

## Features

- Multi-threaded scanning (100 ports in parallel)
- Service detection (SSH, HTTP, FTP, DNS, and more)
- Banner grabbing (reads server response on open ports)
- Configurable port range and timeout
- Fast: scans 1000 ports in ~2 seconds

## Build

```bash
make
```

## Usage

```bash
./netscanner -h  -p  -t 
```

## Examples

```bash
# Scan ports 1-1000 on a remote host
./netscanner -h scanme.nmap.org -p 1-1000 -t 1000

# Scan localhost with fast timeout
./netscanner -h 127.0.0.1 -p 1-500 -t 500

# Scan a single port
./netscanner -h scanme.nmap.org -p 80-80 -t 2000
```

## Example Output

  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                              Port Scanner v1.0

  [*] Target:  scanme.nmap.org (45.33.32.156)
  [*] Porturi: 1 - 1000
  [*] Timeout: 1000 ms

  Scanare in curs...

  
[+] Port 22     SSH          194.4 ms
[+] Port 80     HTTP         190.7 ms
PORT     SERVICIU   TIMP       BANNER
──────────────────────────────────────────
22       SSH        194.4
80       HTTP       191.0      HTTP/1.1 200 OK

## How it works

NetScanner uses non-blocking TCP connect scanning — the same technique as `nmap -sT`.

For each port it:
1. Opens a non-blocking socket
2. Attempts a TCP connection
3. Uses `select()` to wait for the result within the timeout
4. Confirms with `send()` to eliminate false positives
5. If open, attempts to read a banner from the service

Ports are scanned in batches of 100 threads simultaneously.

## Legal

Only scan hosts you own or have explicit permission to scan.
`scanme.nmap.org` is provided by the Nmap project for testing purposes.