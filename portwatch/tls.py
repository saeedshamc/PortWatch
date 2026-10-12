"""TLS certificate inspection for open remote ports.

A scanner must be able to report certificates it does not trust (self-signed,
expired, wrong host), so the handshake runs with verification disabled and the
peer certificate is decoded from its DER form. Chain validity is recovered
separately by a second, verifying handshake against the system trust store.

Parsing uses :func:`ssl._ssl._test_decode_cert`, a long-standing CPython
helper that turns a PEM file into the same dict ``getpeercert()`` returns on a
verified connection. It is guarded so that if it is ever removed, PortWatch
degrades to reporting protocol and cipher rather than crashing.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import tempfile
from typing import Any

from portwatch.models import TlsInfo

#: Used only to decide whether the certificate chains to a trusted root.
_TRUSTED_CONTEXT = ssl.create_default_context()

#: The C extension module backing :mod:`ssl`, resolved defensively so a
#: missing private helper degrades gracefully instead of raising. ``getattr``
#: keeps this import-safe on non-CPython runtimes.
_ssl_core: Any = getattr(ssl, "_ssl", None)


def _flatten_name(name: object) -> str | None:
    """Render an X.509 RDN tuple like ``(('CN', 'example.com'),)`` as text."""
    parts: list[str] = []
    if not isinstance(name, tuple):
        return None
    for rdn in name:
        if not isinstance(rdn, tuple):
            continue
        for attribute in rdn:
            if isinstance(attribute, tuple) and len(attribute) == 2:
                key, value = attribute
                parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else None


def _decode_cert_pem(pem_path: str) -> dict[str, Any] | None:
    """Decode a PEM certificate into a field dict, or ``None`` if unavailable.

    Uses CPython's long-standing ``_test_decode_cert`` helper (the same dict
    ``getpeercert()`` returns on a verified connection). It is looked up
    defensively so a future CPython removal degrades to no certificate
    details instead of crashing the scan.
    """
    try:
        decoder = getattr(_ssl_core, "_test_decode_cert", None)
        if decoder is None:
            return None
        return decoder(pem_path)
    except (OSError, ValueError, ssl.SSLError):
        return None


async def inspect_tls(host: str, port: int, timeout: float = 2.0) -> TlsInfo:
    """Perform a TLS handshake with ``host:port`` and capture certificate details.

    Never raises: any failure (plaintext service, timeout, reset, undecodable
    certificate) is reported in the returned :class:`TlsInfo.error` so the
    surrounding scan is unaffected.
    """
    info = TlsInfo()
    # Build a fresh context per handshake. Reusing ``_INSECURE_CONTEXT`` across
    # successive ``asyncio.open_connection`` calls is unreliable on some
    # platforms, so a dedicated context is created per call instead.
    insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=insecure, server_hostname=host
            ),
            timeout=timeout,
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        info.error = _describe_error(exc)
        return info

    try:
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            info.error = "no TLS session established"
            return info
        info.protocol = ssl_object.version()
        cipher = ssl_object.cipher()
        info.cipher = cipher[0] if cipher else None

        der = ssl_object.getpeercert(binary_form=True)
        if der:
            pem = ssl.DER_cert_to_PEM_cert(der)
            fd, path = tempfile.mkstemp(suffix=".pem")
            try:
                with os.fdopen(fd, "w", encoding="ascii") as handle:
                    handle.write(pem)
                decoded = _decode_cert_pem(path)
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            if decoded:
                info.subject = _flatten_name(decoded.get("subject"))
                info.issuer = _flatten_name(decoded.get("issuer"))
                not_before = decoded.get("notBefore")
                not_after = decoded.get("notAfter")
                info.not_before = not_before if isinstance(not_before, str) else None
                info.not_after = not_after if isinstance(not_after, str) else None
                sans = decoded.get("subjectAltName")
                if isinstance(sans, tuple):
                    info.subject_alt_names = [
                        f"{kind}:{value}"
                        for kind, value in sans
                        if isinstance(kind, str) and isinstance(value, str)
                    ]
        info.verified = await _is_trusted(host, port, timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    return info


async def _is_trusted(host: str, port: int, timeout: float) -> bool:
    """Return whether the certificate chains to a trusted root.

    Runs a second handshake with normal verification. Reaching this point
    means the connection succeeded *and* the chain validated, so any success
    is a trusted certificate.
    """
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=_TRUSTED_CONTEXT, server_hostname=host
            ),
            timeout=timeout,
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


def _describe_error(exc: BaseException) -> str:
    if isinstance(exc, asyncio.TimeoutError):
        return "timed out"
    name = type(exc).__name__
    return str(exc) or name.lower()
