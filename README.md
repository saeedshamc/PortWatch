# PortWatch

[![CI](https://github.com/saeedshamc/PortWatch/actions/workflows/ci.yml/badge.svg)](https://github.com/saeedshamc/PortWatch/actions/workflows/ci.yml)

A cross-platform port scanning toolkit with three modes:

- **Local scan** — list every listening TCP/UDP socket on the current machine, together with the owning process (PID, process name, executable path).
- **Remote scan** — concurrently scan one or more targets (IPs, hostnames, or CIDR subnets) for open TCP ports, with banner grabbing to identify the running service.
- **Diff** — compare two saved scan files and report newly opened, newly closed, and service-changed ports (exit code 2 on any change, so it can gate CI jobs).

## Features

- Local socket enumeration with process attribution via [psutil](https://github.com/giampaolo/psutil)
- Fully asynchronous remote TCP connect scanner (asyncio) with a configurable concurrency limit and per-connection timeout
- Banner grabbing: passive read for greeting services (SSH, FTP, SMTP, POP3, IMAP, VNC, Redis, MySQL) and an optional HTTP HEAD probe for silent web servers
- Service fingerprinting from banner patterns with well-known-port fallback
- Targets: single IPs (IPv4/IPv6), hostnames, and CIDR subnets (with a safety cap on subnet size)
- Structured JSON output or aligned CLI tables

## Requirements

- Python 3.10 or newer
- Windows, macOS, or Linux

## Installation

```bash
git clone <your-repo-url> portwatch
cd portwatch
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

Run it as a module:

```bash
python -m portwatch --help
```

## Usage

### Local mode (default)

List all listening sockets with their owning process:

```bash
python -m portwatch
```

Sample output (Windows):

```
PROTO  ADDRESS       PORT   PID    PROCESS             EXECUTABLE
-----  ------------  -----  -----  ------------------  --------------------------------------------------------------
TCP    0.0.0.0       135    2040   svchost.exe         C:\Windows\System32\svchost.exe
TCP    ::            135    2040   svchost.exe         C:\Windows\System32\svchost.exe
TCP    172.31.1.167  139    4      System              -
TCP    0.0.0.0       445    4      System              -
TCP    127.0.0.1     1042   2224   asus_framework.exe  C:\Program Files (x86)\ASUS\ArmouryDevice\asus_framework.exe
```

TCP only, or UDP only:

```bash
python -m portwatch --protocol tcp
python -m portwatch --protocol udp
```

JSON output:

```bash
python -m portwatch -f json
```

```json
[
  {
    "protocol": "TCP",
    "local_address": "0.0.0.0",
    "local_port": 135,
    "pid": 2040,
    "process_name": "svchost.exe",
    "executable": "C:\\Windows\\System32\\svchost.exe",
    "command_line": null
  }
]
```

### Remote mode

Scan specific ports on one target:

```bash
python -m portwatch --mode remote 192.168.1.10 -p 22,80,443,8000-8100
```

Scan a subnet with custom concurrency and timeout:

```bash
python -m portwatch --mode remote 192.168.1.0/24 -p 1-1024 -c 200 -t 1.5
```

Identify silent web servers by sending an HTTP HEAD probe:

```bash
python -m portwatch --mode remote 10.0.0.5 -p 80,8080,8443 --probe
```

Sample output:

```
HOST       PORT   SERVICE  BANNER
---------  -----  -------  ---------------------------------------------------------
127.0.0.1  8080   http     HTTP/1.0 200 OK Server: BaseHTTP/0.6 Python/3.14.2 ...

1 target(s), 1 port(s) scanned, 1 open
```

JSON output:

```bash
python -m portwatch --mode remote 127.0.0.1 -p 8080 --probe -f json
```

Save any scan directly to a file with guaranteed UTF-8 encoding and LF line endings on every platform (see [docs/EXPORT.md](docs/EXPORT.md)):

```bash
python -m portwatch -f json -o listeners.json
python -m portwatch --mode remote 192.168.1.0/24 -p 1-1024 -o subnet.json
```

```json
[
  {
    "host": "127.0.0.1",
    "resolved_ip": "127.0.0.1",
    "ports_scanned": 1,
    "open_ports": [
      {
        "host": "127.0.0.1",
        "port": 8080,
        "open": true,
        "error": null,
        "banner": "HTTP/1.0 200 OK Server: BaseHTTP/0.6 Python/3.14.2",
        "service": "http"
      }
    ]
  }
]
```

### Diff mode

Compare two saved scans of the same host (saved with `-f json -o file.json`):

```bash
python -m portwatch --mode remote 10.0.0.5 -p 1-1024 -f json -o old.json
# ...time passes...
python -m portwatch --mode remote 10.0.0.5 -p 1-1024 -f json -o new.json
python -m portwatch --mode diff old.json new.json
```

Sample output:

```
Port changes for 10.0.0.5:

NEWLY OPENED:
  8080   http

NEWLY CLOSED:
  22     ssh  (SSH-2.0-OpenSSH_9.6)

SERVICE CHANGED:
  (none)

1 opened, 1 closed, 0 service change(s), 0 unchanged
```

With `-f json` the diff is emitted as a JSON object instead. The exit code is `2` when any difference exists and `0` when the scans match, which makes it usable as a change gate in scripts and CI jobs.

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--mode {local,remote,diff}` | `local` | Scan mode |
| `TARGET ...` (diff mode) | — | Exactly two saved scan JSON files, old then new |
| `TARGET ...` | — | Remote mode: IPs, hostnames, or CIDR subnets |
| `-p, --ports SPEC` | `1-1024` | Remote mode: port spec, e.g. `80,443,8000-8010` |
| `-c, --concurrency N` | `100` | Remote mode: maximum simultaneous connections |
| `-t, --timeout SECONDS` | `2.0` | Remote mode: per-connection timeout |
| `--probe` | off | Remote mode: send an HTTP HEAD request to open ports before reading the banner |
| `--protocol {inet,tcp,udp}` | `inet` | Local mode: socket protocols to list |
| `-f, --format {table,json}` | `table` | Output format |
| `-o, --output FILE` | — | Also write the result to FILE as UTF-8 with LF line endings; console output is unaffected |
| `--version` | — | Print version and exit |

See [docs/USAGE.md](docs/USAGE.md) for the full reference, exit codes, and troubleshooting, and [docs/EXPORT.md](docs/EXPORT.md) for saving output to files on Windows and Linux (PowerShell/cmd/bash examples, JSON post-processing with jq and PowerShell).

## Notes

- **Windows:** listing sockets owned by other processes (and some system socket tables) may require an elevated prompt; restricted entries are shown as `(no access)` instead of failing the scan.
- **Scanning ethics:** only scan networks and hosts you own or are explicitly authorized to test. A TCP connect scan is fully visible in target connection logs.
- **Subnet safety:** CIDR targets are refused if they expand to more than 4096 hosts, preventing accidental wide-area sweeps.

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest
```

Continuous integration runs the full test suite on Linux, Windows and macOS (Python 3.10 and 3.13) for every push and pull request via GitHub Actions (`.github/workflows/ci.yml`).

## Project layout

```
portwatch/        source package (cli, local_scan, remote_scan, banner, targets, models)
tests/            pytest suite
docs/             USAGE.md (reference) and EXPORT.md (saving output on Windows/Linux)
```

## License

See [LICENSE](LICENSE).
