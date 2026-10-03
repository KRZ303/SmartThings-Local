"""Binary PSK identity regression tests; no appliance or network needed."""
from pathlib import Path

import pytest
from OpenSSL import SSL

from smartthings_local.protocol.auth import PskAuth


def _relay(source, destination):
    try:
        data = source.bio_read(65535)
    except SSL.WantReadError:
        return b""
    if data:
        destination.bio_write(data)
    return data


def _openssl_peer():
    from smartthings_local.protocol.auth import _util
    context = SSL.Context(SSL.DTLS_METHOD)
    context.set_cipher_list(b"ECDHE-PSK-AES128-CBC-SHA256:@SECLEVEL=0")

    @_util.ffi.callback("unsigned int(*)(SSL *, const char *, unsigned char *, unsigned int)")
    def callback(_ssl, _identity, key, capacity):
        if capacity < 16:
            return 0
        _util.ffi.memmove(key, b"k" * 16, 16)
        return 16

    _util.lib.SSL_CTX_set_psk_server_callback(context._context, callback)
    peer = SSL.Connection(context, None)
    peer.set_accept_state()
    return peer, callback


@pytest.mark.parametrize("zero_position", [0, 8, 15])
def test_native_handshake_preserves_binary_identity_and_exchanges_data(zero_position):
    from smartthings_local.protocol._mbedtls import _MbedConnection
    if not Path("smartthings_local/protocol/_mbedtls_native.so").exists():
        pytest.skip("optional Mbed TLS shim not built")
    identity = bytearray(range(1, 17))
    identity[zero_position] = 0
    client = _MbedConnection(bytes(identity), b"k" * 16, 1200)
    server, callback = _openssl_peer()
    complete = [False, False]
    outbound = bytearray()
    for _ in range(50):
        for i, source, destination in [(0, client, server), (1, server, client)]:
            try:
                source.do_handshake()
                complete[i] = True
            except SSL.WantReadError:
                pass
            data = _relay(source, destination)
            if i == 0:
                outbound.extend(data)
        if all(complete):
            break
    assert all(complete)
    # ClientKeyExchange precedes encryption and carries the explicit identity length.
    from smartthings_local.protocol.coap import split_dtls
    exchanges = [r[25:] for r in split_dtls(bytes(outbound)) if r[0] == 22 and r[13] == 16]
    assert any(body[:2] == b"\x00\x10" and body[2:18] == identity for body in exchanges)
    client.send(b"client payload")
    _relay(client, server)
    assert server.recv(65535) == b"client payload"
    server.send(b"server payload")
    _relay(server, client)
    assert client.recv(65535) == b"server payload"
    client.shutdown()
    _relay(client, server)
    with pytest.raises(SSL.ZeroReturnError):
        server.recv(65535)


def test_binary_identity_uses_native_backend_when_installed():
    if not Path("smartthings_local/protocol/_mbedtls_native.so").exists():
        pytest.skip("optional Mbed TLS shim not built")
    identity = bytes(range(16))
    provider = PskAuth(identity=identity, key=b"k" * 16)
    connection = provider._mbedtls_factory(1200)
    with pytest.raises(SSL.WantReadError):
        connection.do_handshake()
    assert connection.bio_read(65535)[0] == 22
    with pytest.raises(ValueError, match="Mbed TLS"):
        provider.configure_context(SSL.Context(SSL.DTLS_METHOD))


def test_binary_identity_never_falls_back_when_backend_missing(monkeypatch):
    from smartthings_local.protocol import _mbedtls

    def unavailable():
        raise ValueError("Mbed TLS backend is unavailable")

    monkeypatch.setattr(_mbedtls, "_load_library", unavailable)
    with pytest.raises(ValueError, match="Mbed TLS"):
        PskAuth(identity=bytes(range(16)), key=b"k" * 16)


def test_non_nul_identity_keeps_openssl_without_native_dependency(monkeypatch):
    from smartthings_local.protocol import _mbedtls

    monkeypatch.setattr(_mbedtls, "_load_library", lambda: pytest.fail("native load"))
    provider = PskAuth(identity=b"i" * 16, key=b"k" * 16)
    assert provider._mbedtls_factory is None
    provider.configure_context(SSL.Context(SSL.DTLS_METHOD))


def test_native_timer_retransmits_and_finalizer_frees_context():
    import gc
    import time
    from smartthings_local.protocol._mbedtls import _MbedConnection

    if not Path("smartthings_local/protocol/_mbedtls_native.so").exists():
        pytest.skip("optional Mbed TLS shim not built")
    client = _MbedConnection(bytes(range(16)), b"k" * 16, 1200)
    finalizer = client._finalizer
    with pytest.raises(SSL.WantReadError):
        client.do_handshake()
    initial = client.bio_read(65535)
    remaining = client.DTLSv1_get_timeout()
    assert 0 < remaining <= 1.1
    time.sleep(remaining + 0.01)
    assert client.DTLSv1_get_timeout() == 0
    client.DTLSv1_handle_timeout()
    with pytest.raises(SSL.WantReadError):
        client.do_handshake()
    assert client.bio_read(65535)[0] == initial[0] == 22
    assert client.DTLSv1_get_timeout() > 0
    del client
    gc.collect()
    assert not finalizer.alive


def test_native_wrong_key_cannot_complete_authentication():
    from smartthings_local.protocol._mbedtls import _MbedConnection
    if not Path("smartthings_local/protocol/_mbedtls_native.so").exists():
        pytest.skip("optional Mbed TLS shim not built")
    client = _MbedConnection(bytes(range(16)), b"wrong key bytes!", 1200)
    server, callback = _openssl_peer()
    completed = [False, False]
    failed = False
    for _ in range(50):
        for i, source, destination in [(0, client, server), (1, server, client)]:
            try:
                source.do_handshake()
                completed[i] = True
            except SSL.WantReadError:
                pass
            except SSL.Error:
                failed = True
            _relay(source, destination)
        if failed:
            break
    assert not all(completed)


def test_native_rejects_oversized_and_unconsumed_datagrams():
    from smartthings_local.protocol._mbedtls import _MbedConnection
    if not Path("smartthings_local/protocol/_mbedtls_native.so").exists():
        pytest.skip("optional Mbed TLS shim not built")
    connection = _MbedConnection(bytes(range(16)), b"k" * 16, 1200)
    with pytest.raises(SSL.Error):
        connection.bio_write(b"x" * 65536)
    assert connection.bio_write(b"one datagram") == 12
    with pytest.raises(SSL.Error):
        connection.bio_write(b"another datagram")
