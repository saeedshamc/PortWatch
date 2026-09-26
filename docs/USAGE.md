# PortWatch Usage Reference

Detailed reference for both scan modes, all flags, output formats, and common troubleshooting.

## Synopsis

```
python -m portwatch [--mode {local,remote}] [TARGET ...]
                    [-p SPEC] [-c N] [-t SECONDS] [--probe]
                    [--protocol {inet,tcp,udp}]
                    [-f {table,json}] [--version]
```

## Local mode

The default mode. Enumerates listening sockets on the current machine using psutil and maps each one to its owning process.

```bash
python -m portwatch                     # TCP + UDP, table output
python -m portwatch --protocol tcp      # TCP only
python -m portwatch --protocol udp      # UDP only
python -m portwatch -f json             # machine-readable output
```

Each row contains:

| Field | Meaning |
| --- | --- |
| `protocol` | `TCP` or `UDP` |
| `local_address` | Bound address (`0.0.0.0` / `::` means all interfaces) |
| `local_port` | Listening port number |
| `pid` | Owning process ID, if attributable |
| `process_name` | Process executable name |
| `executable` | Full path to the executable, when readable |
| `command_line` | Full command line, when readable |

### Local mode permissions

- **Windows:** enumerating system-wide sockets is restricted; run from an elevated prompt for complete results. Rows the user cannot read show `(no access)` for the process name.
- **macOS:** full socket tables generally require `sudo`.
- **Linux:** sockets owned by other users may be hidden without root, depending on hardening settings.

If the socket table itself cannot be read, PortWatch exits with code 2 and an explanatory message instead of printing a partial table.

## Remote mode

Performs a full TCP connect scan (real three-way handshake) with asyncio.

```bash
python -m portwatch --mode remote TARGET... [-p SPEC] [-c N] [-t SECONDS] [--probe] [-f FORMAT]
```

### Targets

Targets may be mixed freely and repeated:

```bash
python -m portwatch --mode remote 192.168.1.10 myserver.local 10.0.0.0/24 ::1
```

- Single IPv4/IPv6 addresses are scanned as given.
- Hostnames are resolved once per host (not once per port); only the first resolved address is probed, and it is recorded in `resolved_ip`.
- CIDR subnets are expanded to their host addresses. Network and broadcast addresses are skipped for IPv4. Subnets expanding to more than 4096 hosts are refused; the cap can be raised programmatically via `expand_targets(..., max_cidr_hosts=N)`.
- Duplicate targets are scanned once.

### Port specification

`-p/--ports` accepts single ports, ranges, and comma-separated combinations:

```
-p 80
-p 80-90
-p 22,80,443,8000-8100
-p 1-65535
```

Values outside 1–65535 or reversed ranges are rejected with exit code 2. The default is `1-1024`.

### Concurrency and timing

- `-c/--concurrency` (default 100) caps in-flight connection attempts with an internal semaphore.
- `-t/--timeout` (default 2.0 seconds) applies to each TCP connect and each banner read.
- Closed local ports return almost immediately; filtered ports (silent firewalls) consume the full timeout, so tune `-t` down for large ranges.

### Banner grabbing and probing

Banner grabbing is always on in remote mode:

- **Passive read** catches services that greet on connect: SSH, FTP, SMTP, POP3, IMAP, VNC, Redis, MySQL.
- **`--probe`** additionally sends a minimal `HEAD / HTTP/1.0` request before reading, which coaxes responses out of silent web servers. Only enable against hosts you are authorized to test; the probe is visible in server logs.

Service identification checks banner patterns first, then falls back to a well-known-port table (`22 → ssh`, `443 → https`, `3389 → rdp`, ...). Unidentified ports are shown as `?` in tables and `null` in JSON.

## Output formats

### Table (default)

Aligned columns; remote mode appends a summary line:

```
1 target(s), 1024 port(s) scanned, 3 open
```

### JSON

- Local mode: a top-level array of port records.
- Remote mode: a top-level array, one object per target:

```json
{
  "host": "10.0.0.5",
  "resolved_ip": "10.0.0.5",
  "ports_scanned": 3,
  "open_ports": [
    {"host": "10.0.0.5", "port": 22, "open": true,
     "error": null, "banner": "SSH-2.0-OpenSSH_9.6", "service": "ssh"}
  ]
}
```

Only open ports are listed under `open_ports`. Closed and filtered ports are not included; per-target totals appear in `ports_scanned`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed |
| `2` | Usage or input error (bad port spec, invalid target, unreadable socket table) |
| `130` | Interrupted with Ctrl+C |

## Examples

Audit what your own machine is exposing:

```bash
python -m portwatch -f json > listeners.json
```

Quick sweep of a lab subnet's common management ports:

```bash
python -m portwatch --mode remote 192.168.56.0/24 -p 22,80,443,3389,5900 -c 150 -t 1
```

Identify an unknown service on a single host:

```bash
python -m portwatch --mode remote 10.0.0.7 -p 8000-8100 --probe -f json
```

## Troubleshooting

- **`insufficient permissions to enumerate system-wide sockets`** — re-run from an elevated prompt (Windows) or with `sudo` (macOS/Linux).
- **Everything shows as `timed out` on a remote host** — a firewall is silently dropping packets; lower `-t` to move faster or scan from a network where the host is reachable.
- **A web server shows no banner** — it waits for the client to speak first; re-run with `--probe`.
- **`subnet ... refusing to expand`** — the CIDR exceeds the 4096-host safety cap; scan a set of smaller subnets instead.
- **`no-such-host` style targets report nothing** — DNS resolution failed for the name; check spelling or use the IP directly.
