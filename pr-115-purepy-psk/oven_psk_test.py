#!/usr/bin/env python3
"""Authenticate to an appliance with a binary PSK identity, then GET /oic/d.

Written for https://github.com/QuiteYellow/SmartThings-Local/pull/115 to test
a pure-Python DTLS 1.2 ECDHE-PSK client against real hardware. It replaces the
compiled Mbed TLS backend in that PR with `dtls_psk.py` next to this file, so
there is nothing to build.

What it does, and nothing else:

1. one DTLS 1.2 ECDHE-PSK handshake, sending the identity you give it with an
   explicit length, so a zero byte inside it survives
2. one CoAP GET of /oic/d over that session
3. a close_notify, then exit

It never writes to the appliance, never touches a security resource, and never
retries. Stop the bridge or integration first if one is running, since the
appliance will already have a session with it.

Usage:

    export PSK_HOST=192.0.2.100
    export PSK_PORT=49154
    export PSK_IDENTITY_HEX=0102...        # 32 hex chars, the 16-byte UUID
    export PSK_KEY_HEX=...                 # 32 or 64 hex chars
    export PSK_EXPECTED_DI=...             # optional, the di you expect
    python3 oven_psk_test.py

Output is written to be safe to paste into the thread: the identity and the
device id are reported as a comparison result or a hash prefix, never printed.
"""
from __future__ import annotations

import hashlib
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from dtls_psk import DtlsPskClient, WantRead, ZeroReturn
except ImportError:
    sys.exit("dtls_psk.py must sit next to this script")


def _env(name: str, *, required: bool = True) -> str | None:
    value = os.environ.get(name)
    if required and not value:
        sys.exit(f"{name} is not set; see the docstring at the top of this file")
    return value


def _hexbytes(name: str, lengths: tuple[int, ...]) -> bytes:
    raw = _env(name)
    try:
        value = bytes.fromhex(raw.strip())
    except ValueError:
        sys.exit(f"{name} must be hex")
    if len(value) not in lengths:
        sys.exit(f"{name} must decode to {' or '.join(map(str, lengths))} bytes, "
                 f"got {len(value)}")
    return value


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:16]


def _coap_get(path: tuple[str, ...], token: bytes, message_id: int) -> bytes:
    """Encode a CON GET. Uri-Path is option 11; deltas are 11 then 0."""
    out = bytearray()
    out.append(0x40 | len(token))          # ver 1, CON, token length
    out.append(1)                          # 0.01 GET
    out += struct.pack("!H", message_id)
    out += token
    delta = 11
    for segment in path:
        encoded = segment.encode()
        if len(encoded) > 12:
            out.append((delta << 4) | 13)
            out.append(len(encoded) - 13)
        else:
            out.append((delta << 4) | len(encoded))
        out += encoded
        delta = 0
    return bytes(out)


def _coap_parse(datagram: bytes) -> tuple[str, bytes]:
    """Return the response code as 'c.dd' and the payload."""
    if len(datagram) < 4:
        return "?", b""
    token_length = datagram[0] & 0x0F
    code = datagram[1]
    offset = 4 + token_length
    while offset < len(datagram):
        if datagram[offset] == 0xFF:
            offset += 1
            break
        delta = datagram[offset] >> 4
        length = datagram[offset] & 0x0F
        offset += 1
        for nibble in (delta, length):
            if nibble == 13:
                offset += 1
            elif nibble == 14:
                offset += 2
        if length == 13:
            length = datagram[offset - 1] + 13
        elif length == 14:
            length = 0  # not expected on these responses
        offset += length
    return f"{code >> 5}.{code & 0x1F:02d}", datagram[offset:]


def _split_records(buf: bytes) -> list[bytes]:
    """One DTLS record per datagram; the appliance drops packed records."""
    out, offset = [], 0
    while offset + 13 <= len(buf):
        length = int.from_bytes(buf[offset + 11:offset + 13], "big")
        if offset + 13 + length > len(buf):
            break
        out.append(buf[offset:offset + 13 + length])
        offset += 13 + length
    return out


def _flush(client, sock) -> None:
    try:
        pending = client.bio_read(65535)
    except WantRead:
        return
    for record in _split_records(pending):
        sock.send(record)


def main() -> int:
    host = _env("PSK_HOST")
    port = int(_env("PSK_PORT") or 0)
    identity = _hexbytes("PSK_IDENTITY_HEX", (16,))
    key = _hexbytes("PSK_KEY_HEX", (16, 32))
    expected_di = _env("PSK_EXPECTED_DI", required=False)

    print(f"host          : {host}:{port}")
    print(f"identity      : 16 bytes, sha256:{_digest(identity)}, "
          f"contains a zero byte: {'yes' if 0 in identity else 'no'}")
    print(f"key           : {len(key)} bytes, sha256:{_digest(key)}")

    client = DtlsPskClient(identity, key, mtu=1400)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((host, port))
    sock.settimeout(0.5)

    started = time.monotonic()
    deadline = started + 20
    completed = False
    while time.monotonic() < deadline:
        try:
            client.do_handshake()
            completed = True
            break
        except WantRead:
            pass
        except Exception as exc:  # noqa: BLE001 - reported, not handled
            print(f"handshake     : FAILED ({type(exc).__name__}: {exc})")
            sock.close()
            return 1
        _flush(client, sock)
        try:
            client.bio_write(sock.recv(65535))
        except socket.timeout:
            remaining = client.DTLSv1_get_timeout()
            if remaining is not None and remaining <= 0:
                client.DTLSv1_handle_timeout()

    if not completed:
        print(f"handshake     : TIMED OUT after {time.monotonic() - started:.1f}s")
        sock.close()
        return 1
    print(f"handshake     : OK in {time.monotonic() - started:.1f}s "
          f"(DTLS 1.2, ECDHE-PSK-AES128-CBC-SHA256)")

    client.send(_coap_get(("oic", "d"), b"\x01\x02\x03\x04", 0x1234))
    _flush(client, sock)

    payload, code = b"", "?"
    reply_deadline = time.monotonic() + 10
    while time.monotonic() < reply_deadline:
        try:
            code, payload = _coap_parse(client.recv(65535))
            break
        except WantRead:
            pass
        except ZeroReturn:
            print("GET /oic/d    : peer closed before replying")
            break
        try:
            client.bio_write(sock.recv(65535))
        except socket.timeout:
            continue

    print(f"GET /oic/d    : {code}, {len(payload)} byte payload")
    if payload:
        try:
            import cbor2

            document = cbor2.loads(payload)
        except Exception:  # noqa: BLE001 - absence of cbor2 is not a failure
            document = None
        if isinstance(document, dict):
            keys = sorted(str(k) for k in document)
            print(f"  decoded keys: {', '.join(keys)}")
            di = document.get("di")
            if isinstance(di, str):
                if expected_di:
                    print("  di matches PSK_EXPECTED_DI: "
                          f"{'YES' if di == expected_di else 'NO'}")
                else:
                    print(f"  di sha256   : {_digest(di.encode())}")
        else:
            print("  payload did not decode as a CBOR map "
                  "(install cbor2 to decode)")

    client.shutdown()
    _flush(client, sock)
    sock.close()
    print("close_notify  : sent")
    return 0


def _cap_memory(limit_mb: int = 512) -> None:
    """Abort rather than exhaust the machine if something goes wrong.

    A backstop, not a hard cap: macOS refuses to lower RLIMIT_AS/RLIMIT_DATA,
    so on that platform this is a polling watchdog that turns a runaway
    allocation into a dead process instead of a dead laptop.
    """
    import os
    import resource
    import sys
    import threading
    import time

    ceiling = limit_mb * 1024 * 1024
    for name in ("RLIMIT_AS", "RLIMIT_DATA"):
        limit = getattr(resource, name, None)
        if limit is None:
            continue
        try:
            resource.setrlimit(limit, (ceiling, resource.getrlimit(limit)[1]))
            return
        except (ValueError, OSError):
            continue
    scale = 1 if sys.platform == "darwin" else 1024

    def watch() -> None:
        while True:
            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * scale
            if rss > ceiling:
                print(f"aborting: {rss // 1048576} MB exceeds the "
                      f"{limit_mb} MB cap", flush=True)
                os._exit(97)
            time.sleep(0.05)

    threading.Thread(target=watch, daemon=True).start()


if __name__ == "__main__":
    _cap_memory()
    sys.exit(main())
