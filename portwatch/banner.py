"""Banner grabbing and service fingerprinting for open TCP ports."""

from __future__ import annotations

import asyncio
import re

#: How many bytes of a banner to keep (banner is truncated beyond this).
MAX_BANNER_LENGTH = 256

#: Patterns checked in order; the first match names the service.
_SERVICE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ssh", re.compile(r"\bSSH-\d", re.IGNORECASE)),
    ("http", re.compile(r"\bHTTP/1\.[01]\b", re.IGNORECASE)),
    ("ftp", re.compile(r"\b220[ -].*(?:FTP|FileZilla|vsftpd|ProFTPD)", re.IGNORECASE)),
    ("smtp", re.compile(r"\b220[ -].*(?:ESMTP|SMTP|Postfix|Exchange|mail)", re.IGNORECASE)),
    ("mysql", re.compile(r"(?:\x00\x00\x00\x0a|5\.[0-9]+\.[0-9]+(?:-log)?)", re.IGNORECASE)),
    ("redis", re.compile(r"^-ERR|-PONG|^-NOAUTH|redis", re.IGNORECASE)),
    ("pop3", re.compile(r"^\+OK\b", re.IGNORECASE)),
    ("imap", re.compile(r"^\* (?:OK|CAPABILITY)\b", re.IGNORECASE)),
    ("vnc", re.compile(r"^RFB \d{3}\.\d{3}\n?$")),
]

#: Well-known ports that are reported even when the banner is empty.
_PORT_ALIASES: dict[int, str] = {
    20: "ftp",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http",
    8443: "https",
}


async def grab_banner(reader: asyncio.StreamReader, timeout: float = 2.0) -> str | None:
    """Read the first bytes a service sends after accepting the connection.

    Returns a cleaned single-line-safe string, or ``None`` when the server
    stays silent (most HTTP servers wait for the client to speak first).
    """
    try:
        data = await asyncio.wait_for(reader.read(MAX_BANNER_LENGTH), timeout=timeout)
    except (OSError, asyncio.TimeoutError, asyncio.LimitOverrunError):
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    cleaned = " ".join(text.split())
    if not cleaned:
        return None
    return cleaned[:MAX_BANNER_LENGTH]


def build_http_probe(host: str, port: int) -> bytes:
    """Minimal HTTP HEAD request used to coax a response from silent servers."""
    host_header = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return (
        f"HEAD / HTTP/1.0\r\nHost: {host_header}\r\n"
        f"User-Agent: portwatch/0.1\r\nConnection: close\r\n\r\n"
    ).encode("ascii")


def identify_service(banner: str | None, port: int | None = None) -> str | None:
    """Guess the service from a banner pattern, falling back to the port number."""
    if banner:
        for name, pattern in _SERVICE_PATTERNS:
            if pattern.search(banner):
                return name
    if port is not None:
        return _PORT_ALIASES.get(port)
    return None
