"""Optional binary-identity DTLS backend, sharing the existing session driver.

The C shim owns Mbed TLS contexts compiled against real headers. No guessed
structure sizes, runtime compilation, or Python callbacks cross the native ABI.
"""
from __future__ import annotations

import ctypes
from functools import lru_cache
from pathlib import Path
import weakref

from OpenSSL import SSL

_UNAVAILABLE = (
    "a PSK identity containing a NUL byte requires the optional Mbed TLS "
    "backend; build it with python -m smartthings_local.protocol._build_mbedtls"
)


@lru_cache(maxsize=1)
def _load_library():
    try:
        library = ctypes.CDLL(str(Path(__file__).with_name("_mbedtls_native.so")))
        pointer, size, integer = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int
        signatures = {
            "lt_api_version": ([], integer),
            "lt_new": ([pointer, size, pointer, size, ctypes.c_ushort, ctypes.POINTER(integer)], pointer),
            "lt_free": ([pointer], None),
            "lt_handshake": ([pointer], integer),
            "lt_shutdown": ([pointer], integer),
            "lt_timeout": ([pointer], ctypes.c_double),
        }
        for name in ("lt_write", "lt_read", "lt_feed", "lt_drain"):
            signatures[name] = ([pointer, pointer, size], integer)
        for name, (arguments, result) in signatures.items():
            function = getattr(library, name)
            function.argtypes = arguments
            function.restype = result
        if library.lt_api_version() != 1:
            raise ValueError(_UNAVAILABLE)
        return library
    except (OSError, AttributeError):
        raise ValueError(_UNAVAILABLE) from None


def _check(result):
    if result in (-0x6900, -0x6880):  # WANT_READ / WANT_WRITE: memory BIO never blocks.
        raise SSL.WantReadError()
    if result == -0x7880:
        raise SSL.ZeroReturnError()
    if result < 0:
        raise SSL.Error([("Mbed TLS", "DTLS", f"backend error {-result:#x}")])
    return result


class _MbedConnection:
    """The memory-BIO operations used by DtlsCoapSession, not a public SSL API."""

    def __init__(self, identity: bytes, key: bytes, mtu: int):
        if type(mtu) is not int or not 256 <= mtu <= 65535:
            raise ValueError("DTLS MTU must be between 256 and 65535")
        self._library = _load_library()
        error = ctypes.c_int()
        self._handle = self._library.lt_new(identity, len(identity), key, len(key), mtu, ctypes.byref(error))
        if not self._handle:
            _check(error.value)
            raise SSL.Error("Mbed TLS allocation failed")
        # The reader retains a connection reference until it exits. Finalize
        # only after that reference is gone, including failure and abort paths.
        self._finalizer = weakref.finalize(self, self._library.lt_free, self._handle)

    def do_handshake(self):
        _check(self._library.lt_handshake(self._handle))

    def bio_write(self, data):
        return _check(self._library.lt_feed(self._handle, data, len(data)))

    def _read(self, function, capacity):
        if not 1 <= capacity <= 65535:
            raise ValueError("DTLS buffer size must be between 1 and 65535")
        buffer = ctypes.create_string_buffer(capacity)
        length = _check(function(self._handle, buffer, capacity))
        return buffer.raw[:length]

    def bio_read(self, capacity):
        return self._read(self._library.lt_drain, capacity)

    def recv(self, capacity):
        result = self._read(self._library.lt_read, capacity)
        if not result:
            raise SSL.ZeroReturnError()
        return result

    def send(self, data):
        written = _check(self._library.lt_write(self._handle, data, len(data)))
        if written != len(data):
            raise SSL.Error("Mbed TLS incomplete datagram write")
        return written

    def shutdown(self):
        _check(self._library.lt_shutdown(self._handle))

    def DTLSv1_get_timeout(self):
        remaining = self._library.lt_timeout(self._handle)
        return None if remaining < 0 else remaining

    def DTLSv1_handle_timeout(self):
        # Mbed TLS services its expired timer on the next handshake call.
        return None
