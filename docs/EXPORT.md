# Exporting Output (Windows & Linux)

How to save PortWatch results to files and post-process them on Windows and Linux/macOS.

PortWatch always prints results to standard output, so every ordinary redirection technique works. Use `-f json` whenever the file will be read by another program; use the default table format for human-readable reports.

> **Recommended:** add `-f json` for anything you plan to parse, sort, diff, or archive. The table format is for reading in a terminal.
>
> **Simplest option:** let PortWatch write the file itself with `-o FILE` — the file is always UTF-8 with LF line endings on every platform, with none of the codepage caveats below:
>
> ```bash
> python -m portwatch -f json -o ports.json
> python -m portwatch --mode remote 192.168.1.0/24 -p 1-1024 -o subnet.json
> ```
>
> The console still shows the same output, and the sections below cover shell redirection when you need pipelines instead.

## Windows

### PowerShell (recommended)

PowerShell's redirection operator (`>`) writes UTF-16 by default, which some Unix tools and older parsers mishandle. Use `Out-File -Encoding utf8` (or `-Encoding utf8NoBOM` on PowerShell 7+) instead:

```powershell
# Table output (human-readable)
python -m portwatch | Out-File -Encoding utf8 ports.txt

# JSON output for tooling
python -m portwatch -f json | Out-File -Encoding utf8 ports.json

# Local + remote scans into separate files
python -m portwatch --protocol tcp | Out-File -Encoding utf8 local.txt
python -m portwatch --mode remote 192.168.1.0/24 -p 22,80,443 | Out-File -Encoding utf8 subnet.json

# Append successive scans to one log with a timestamp
python -m portwatch -f json | Out-File -Encoding utf8 -Append "scan-$(Get-Date -F yyyyMMdd-HHmm).json"
```

### Command Prompt (cmd.exe)

cmd writes output using the console codepage. For clean UTF-8 files, switch the console to UTF-8 first:

```bat
chcp 65001
python -m portwatch -f json > ports.json
python -m portwatch --mode remote 10.0.0.5 -p 1-1024 > scan.txt
```

Without `chcp 65001`, files are written in the active codepage (for example cp437 or cp1252); PortWatch replaces characters that cannot be encoded instead of failing, but JSON parsed downstream may contain `?` where other characters were.

### Verify the encoding (optional)

Note that `-o FILE` sidesteps all of the Windows codepage concerns above — the file is written by Python with pinned UTF-8 encoding, not by the shell.

```powershell
Get-Content ports.json -Encoding utf8 | ConvertFrom-Json
```

## Linux / macOS

Standard shell redirection writes UTF-8 by default:

```bash
# Local listeners to JSON
python -m portwatch -f json > listeners.json

# Remote scan to a report
python -m portwatch --mode remote 192.168.1.0/24 -p 1-1024 > subnet-scan.txt

# Append a timestamped snapshot to a rolling log
python -m portwatch -f json >> portwatch.log

# Save both formats in one go using tee
python -m portwatch --mode remote 10.0.0.5 -p 80,443 | tee scan.txt
```

### Cron example (periodic snapshots)

```cron
# Every 15 minutes, append local listening sockets as one JSON line
*/15 * * * * cd /opt/portwatch && .venv/bin/python -m portwatch -f json >> /var/log/portwatch.log 2>>/var/log/portwatch.err
```

Tip: pipe local-mode JSON through `jq -c '.'` if you prefer one compact JSON object per line in the log.

## Consuming the JSON

Remote scans produce one object per target:

```json
[
  {
    "host": "10.0.0.5",
    "resolved_ip": "10.0.0.5",
    "ports_scanned": 1024,
    "open_ports": [
      {"host": "10.0.0.5", "port": 22, "open": true,
       "error": null, "banner": "SSH-2.0-OpenSSH_9.6", "service": "ssh"}
    ]
  }
]
```

Local scans produce a flat array of listener records (`protocol`, `local_address`, `local_port`, `pid`, `process_name`, `executable`, `command_line`).

### jq (Linux, macOS, Windows)

```bash
# Only open ports, sorted by port
jq '.[] | {host, open: [.open_ports[].port]} | select(.open | length > 0)' ports.json

# Flat list of host:port pairs
jq -r '.[] | .open_ports[] | "\(.host):\(.port)"' ports.json

# Count open ports per host
jq -r '.[] | "\(.host): \(.open_ports | length)"' ports.json
```

### PowerShell

```powershell
# Convert and filter
$data = Get-Content ports.json -Raw | ConvertFrom-Json
$data | ForEach-Object { "$($_.host): $($_.open_ports.Count) open" }

# Open ports as host:port lines
$data | ForEach-Object { $_.open_ports } | ForEach-Object { "$($_.host):$($_.port)" }
```

### Python one-liner

```bash
python -c "import json,sys; [print(f\"{p['host']}:{p['port']}\") for t in json.load(open('ports.json')) for p in t['open_ports']]"
```

## Quick diff between two scans

With jq (requires `-f json` output from both scans, one object per line):

```bash
python -m portwatch --mode remote 10.0.0.5 -p 1-1024 -f json \
  | jq -r '.[0].open_ports[].port' > old.txt
python -m portwatch --mode remote 10.0.0.5 -p 1-1024 -f json \
  | jq -r '.[0].open_ports[].port' > new.txt
diff old.txt new.txt
```

Ports only in `new.txt` opened since the first scan; ports only in `old.txt` have closed.

## Troubleshooting exports

- **Garbled characters on Windows** — write with `Out-File -Encoding utf8` (PowerShell) or `chcp 65001` first (cmd). Files written in a legacy codepage may contain `?`.
- **PowerShell converted JSON badly** — never use `ConvertTo-Json` as a pass-through for captured output; it rewrites numbers and nesting. Save the raw stdout with `Out-File` instead.
- **Empty file from a failed scan** — PortWatch writes errors to stderr, so a usage error leaves the output file empty; check the console message and exit code (`2`).
- **Permission denied writing to a protected path** — run the terminal as administrator, or write to a user-writable location.
