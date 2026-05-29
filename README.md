# NetScanner

NetScanner is a lightweight TCP port scanner written in C. It combines fast, multi-threaded scanning with basic service detection and banner grabbing to help you discover open services on target hosts.

Built with POSIX sockets and pthreads, the scanner has no external runtime dependencies beyond a standard C toolchain.

## What NetScanner Does

- Scans TCP ports in parallel using threads
- Detects common services such as SSH, HTTP, FTP, and DNS
- Captures simple service banners when available
- Lets you configure the port range and timeout per scan
- Reports open ports with the associated response time

## Requirements

- Linux or other POSIX-compatible system
- GCC or another C compiler
- `make`

## Build

To compile the scanner from source, run:

```bash
make
```

This produces the executable `netscanner` in the repository root.

## Usage

```bash
./netscanner -h <host> -p <port-range> -t <timeout-ms>
```

Required options:

- `-h <host>` : target hostname or IP address
- `-p <port-range>` : port range to scan, for example `1-1000` or `80-80`
- `-t <timeout-ms>` : connection timeout in milliseconds

## Command-Line Interface

NetScanner is controlled entirely via the command line. The simple interface is designed for fast scans and easy automation.

### Basic syntax

```bash
./netscanner -h example.com -p 1-1024 -t 1500
```

### What the interface displays

- target host and resolved IP
- scanned port range
- timeout value
- per-port scan result with service detection
- banner text for open services when available

### Tips for using the interface

- Use a narrow port range for quick checks: `-p 20-1024`
- Use a longer timeout for slower networks: `-t 2000`
- Use `80-80`, `22-22`, or `443-443` to scan a single port

## Examples

### Scan a full port range on a public test host

```bash
./netscanner -h scanme.nmap.org -p 1-1000 -t 1000
```

### Scan localhost with a fast timeout

```bash
./netscanner -h 127.0.0.1 -p 1-500 -t 500
```

### Scan a single port for a specific service

```bash
./netscanner -h scanme.nmap.org -p 80-80 -t 2000
```

### Scan a restricted service range

```bash
./netscanner -h 192.168.1.1 -p 20-25 -t 1200
```

### Scan two well-known ports at once

```bash
./netscanner -h example.com -p 22-22 -t 1000
./netscanner -h example.com -p 443-443 -t 1000
```

## Example Output

A successful scan prints the target information, the scanned port range, and details for each open port. The interface uses clear labels and a compact table layout.

```text
[*] Target: scanme.nmap.org (45.33.32.156)
[*] Port range: 1 - 1000
[*] Timeout: 1000 ms

Scanning...

[+] Port 22     SSH          194.4 ms
[+] Port 80     HTTP         190.7 ms

PORT   SERVICE   TIME(ms)   BANNER
---------------------------------------------
22     SSH       194.4      SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.6
80     HTTP      191.0      HTTP/1.1 200 OK
```

## Screenshots

A dedicated `assets/` folder is already prepared for your screenshot files.

Use these exact filenames:

- `assets/netscanner-tcp.png`
- `assets/netscanner-udp.png`

The repository includes a placeholder file at `assets/.gitkeep` so the folder appears in Git. When you add the real images and push them, GitHub will render the screenshots in the README.

## How It Works

NetScanner performs TCP connect scans in parallel using POSIX sockets and `select()` for timeouts. For each port in the requested range, the scanner:

1. Creates a non-blocking socket
2. Initiates a TCP connection attempt
3. Waits for the connection result up to the configured timeout
4. Confirms the open port with a lightweight send/receive sequence
5. Reads a service banner when available

The scanner uses a thread pool so many connection attempts can run simultaneously without blocking the entire application.

## Project Structure

- `src/` : application source files
- `include/` : public headers for scanner functionality
- `Makefile` : build instructions

## Notes

- The current implementation is focused on TCP scanning only.
- Use a reasonable timeout value to balance scan speed and accuracy.
- Banner grabbing may not work on every service.

## Legal and Responsible Use

Only scan hosts that you own or have explicit permission to test. Unauthorized scanning may violate local laws and network policies.

`scanme.nmap.org` is a safe public target provided by the Nmap project for testing port scanners.
