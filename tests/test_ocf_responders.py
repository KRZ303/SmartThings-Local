"""Responder enumeration: identity + advertised secure ports per OCF device.

Two layers are covered. The composition logic (which primitives are called, how
their results become an ``OcfResponder``, how failures surface) is tested by
substituting the three underlying primitives. The real unicast read path is
tested against a loopback dual-stack emulator that serves ``/oic/d`` and
``/oic/res`` from two ports on one address, reproducing the "two OCF devices at
one IP" shape without appliance hardware.
"""

from __future__ import annotations

import socket
import threading
from types import SimpleNamespace

import cbor2
import pytest

from smartthings_local.protocol import ocf_multicast
from smartthings_local.protocol.coap import (
    CF_CBOR,
    CONTENT_FORMAT,
    TYPE_NON,
    URI_PATH,
    build_coap,
    parse_coap,
)
from smartthings_local.protocol.ocf_multicast import (
    OcfResponder,
    OcfResponderDiscovery,
    discover_ocf_responders,
    read_ocf_responder,
    secure_ports_for_di,
)

_TARGET = "192.0.2.20"
_INTERFACE = "192.0.2.10"


# --------------------------------------------------------------------------- #
# OcfResponder / selector / repr redaction
# --------------------------------------------------------------------------- #


def test_repr_redacts_device_uuid_and_name_but_shows_types():
    responder = OcfResponder(
        plaintext_port=60137,
        rt=("oic.wk.d", "oic.d.airconditioner"),
        di="5e1627e-secret-uuid",
        name="[floor ac] Someone's House",
        secure_ports=(60912,),
    )
    text = repr(responder)
    assert "5e1627e-secret-uuid" not in text
    assert "Someone's House" not in text
    assert "oic.d.airconditioner" in text
    assert "has_di=True" in text and "has_name=True" in text
    assert "secure_port_count=1" in text


def test_has_identity_reflects_di():
    assert OcfResponder(1, ("oic.wk.d",), "d", None, ()).has_identity is True
    assert OcfResponder(1, ("oic.wk.d",), None, None, ()).has_identity is False


def test_secure_ports_for_di_matches_one_responder():
    ac = OcfResponder(60137, ("oic.wk.d", "oic.d.airconditioner"), "ac", None, (60912,))
    bare = OcfResponder(47616, ("oic.wk.d",), "bare", None, (49999,))
    assert secure_ports_for_di((bare, ac), "ac") == (60912,)
    assert secure_ports_for_di((bare, ac), "bare") == (49999,)
    assert secure_ports_for_di((bare, ac), "absent") == ()


def test_secure_ports_for_di_rejects_empty_di():
    with pytest.raises(ValueError):
        secure_ports_for_di((), "")


def test_discovery_repr_is_redacted():
    text = repr(OcfResponderDiscovery((), error_code="no_response"))
    assert "responder_count=0" in text and "no_response" in text


# --------------------------------------------------------------------------- #
# read_ocf_responder / discover_ocf_responders composition (primitives faked)
# --------------------------------------------------------------------------- #


def _fake_identity(payload=b"", *, successful=True, error_code=None):
    return SimpleNamespace(
        successful=successful, payload=payload, error_code=error_code
    )


def _oic_d(rt, di=None, name=None):
    body = {"rt": list(rt), "if": ["oic.if.baseline", "oic.if.r"]}
    if di is not None:
        body["di"] = di
    if name is not None:
        body["n"] = name
    return cbor2.dumps(body)


def test_read_ocf_responder_bundles_identity_and_secure_ports(monkeypatch):
    monkeypatch.setattr(
        ocf_multicast,
        "read_plaintext_ocf_resource",
        lambda host, href, **kw: _fake_identity(
            _oic_d(("oic.wk.d", "oic.d.oven"), di="oven-di", name="[oven] X")
        ),
    )
    monkeypatch.setattr(
        ocf_multicast,
        "discover_ocf_secure_ports",
        lambda host, **kw: SimpleNamespace(ports=(49154,)),
    )

    responder = read_ocf_responder(_TARGET, 51000)

    assert responder.plaintext_port == 51000
    assert responder.rt == ("oic.wk.d", "oic.d.oven")
    assert responder.di == "oven-di"
    assert responder.name == "[oven] X"
    assert responder.secure_ports == (49154,)
    assert responder.error_code is None


def test_read_ocf_responder_reports_identity_failure_but_still_reads_ports(monkeypatch):
    monkeypatch.setattr(
        ocf_multicast,
        "read_plaintext_ocf_resource",
        lambda host, href, **kw: _fake_identity(
            successful=False, error_code="timeout"
        ),
    )
    monkeypatch.setattr(
        ocf_multicast,
        "discover_ocf_secure_ports",
        lambda host, **kw: SimpleNamespace(ports=(60912,)),
    )

    responder = read_ocf_responder(_TARGET, 60137)

    assert responder.rt == ()
    assert responder.di is None and responder.name is None
    assert responder.error_code == "timeout"
    # The secure-port read is independent and still runs.
    assert responder.secure_ports == (60912,)


def test_read_ocf_responder_survives_malformed_identity_payload(monkeypatch):
    monkeypatch.setattr(
        ocf_multicast,
        "read_plaintext_ocf_resource",
        lambda host, href, **kw: _fake_identity(b"\xff\xff not cbor"),
    )
    monkeypatch.setattr(
        ocf_multicast,
        "discover_ocf_secure_ports",
        lambda host, **kw: SimpleNamespace(ports=()),
    )

    responder = read_ocf_responder(_TARGET, 5683)
    assert responder.rt == () and responder.di is None


def test_read_ocf_responder_validates_port():
    with pytest.raises(TypeError):
        read_ocf_responder(_TARGET, "5683")
    with pytest.raises(ValueError):
        read_ocf_responder(_TARGET, 70000)


def test_discover_ocf_responders_enumerates_both_stacks(monkeypatch):
    monkeypatch.setattr(
        ocf_multicast,
        "discover_ocf_responder_ports",
        lambda target, **kw: SimpleNamespace(
            ports=(47616, 60137), error_code=None
        ),
    )

    identities = {
        47616: _oic_d(("oic.wk.d",), di="bare-di"),
        60137: _oic_d(("oic.wk.d", "oic.d.airconditioner"), di="ac-di"),
    }
    secure = {47616: (49999,), 60137: (60912,)}

    def fake_identity_read(host, href, *, port, **kw):
        return _fake_identity(identities[port])

    monkeypatch.setattr(
        ocf_multicast, "read_plaintext_ocf_resource", fake_identity_read
    )
    monkeypatch.setattr(
        ocf_multicast,
        "discover_ocf_secure_ports",
        lambda host, *, discovery_port, **kw: SimpleNamespace(
            ports=secure[discovery_port]
        ),
    )

    result = discover_ocf_responders(_TARGET, interface_address=_INTERFACE)

    assert result.found and result.error_code is None
    by_port = {r.plaintext_port: r for r in result.responders}
    assert by_port[47616].rt == ("oic.wk.d",)
    assert by_port[60137].rt == ("oic.wk.d", "oic.d.airconditioner")
    # The appliance is the typed responder; the caller filters on rt.
    typed = [r for r in result.responders if any(t.startswith("oic.d.") for t in r.rt)]
    assert len(typed) == 1 and typed[0].plaintext_port == 60137
    assert secure_ports_for_di(result.responders, "ac-di") == (60912,)


def test_discover_ocf_responders_surfaces_multicast_failure(monkeypatch):
    monkeypatch.setattr(
        ocf_multicast,
        "discover_ocf_responder_ports",
        lambda target, **kw: SimpleNamespace(ports=(), error_code="no_response"),
    )
    result = discover_ocf_responders(_TARGET, interface_address=_INTERFACE)
    assert not result.found
    assert result.responders == ()
    assert result.error_code == "no_response"


# --------------------------------------------------------------------------- #
# Loopback dual-stack emulator (real unicast I/O)
# --------------------------------------------------------------------------- #


class _LoopbackResponder:
    """One OCF responder on a loopback UDP port, serving /oic/d and /oic/res.

    Single-datagram CBOR responses (no Block2); resources are kept small enough
    to fit one datagram. Built from owned/synthetic payloads only, so it ships
    in the repo without any appliance-internal data.
    """

    def __init__(self, *, rt, di, name=None, secure_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(1.0)
        self.port = self.sock.getsockname()[1]
        self._oic_d = _oic_d(rt, di=di, name=name)
        self._oic_res = cbor2.dumps(
            [
                {
                    "di": di,
                    "links": [
                        {
                            "href": "/oic/sec/doxm",
                            "rt": ["oic.r.doxm"],
                            "if": ["oic.if.baseline"],
                            "p": {"bm": 1, "sec": True, "port": secure_port},
                        }
                    ],
                }
            ]
        )
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()

    def close(self):
        self._stop.set()
        self._thread.join(timeout=2.0)
        self.sock.close()

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, client = self.sock.recvfrom(8192)
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                _mtype, _code, mid, token, options, _payload = parse_coap(data)
            except Exception:  # noqa: BLE001,S112 - ignore malformed probes
                continue
            path = tuple(v for (o, v) in options if o == URI_PATH)
            if path == (b"oic", b"d"):
                body = self._oic_d
            elif path == (b"oic", b"res"):
                body = self._oic_res
            else:
                continue
            try:
                self.sock.sendto(
                    build_coap(
                        TYPE_NON, 0x45, mid, token, [(CONTENT_FORMAT, CF_CBOR)], body
                    ),
                    client,
                )
            except OSError:
                pass


def test_read_ocf_responder_against_loopback_emulator():
    responder = _LoopbackResponder(
        rt=("oic.wk.d", "oic.d.oven"),
        di="oven-di",
        name="[oven] Samsung",
        secure_port=49154,
    )
    responder.start()
    try:
        result = read_ocf_responder(
            "127.0.0.1", responder.port, timeout=1.5, retries=1
        )
    finally:
        responder.close()

    assert result.plaintext_port == responder.port
    assert result.rt == ("oic.wk.d", "oic.d.oven")
    assert result.di == "oven-di"
    assert result.secure_ports == (49154,)
    assert result.error_code is None


def test_dual_stack_emulator_reproduces_two_devices_at_one_ip(monkeypatch):
    bare = _LoopbackResponder(rt=("oic.wk.d",), di="bare-di", secure_port=49999)
    ac = _LoopbackResponder(
        rt=("oic.wk.d", "oic.d.airconditioner"),
        di="ac-di",
        secure_port=60912,
    )
    bare.start()
    ac.start()

    # Only the multicast leg is stubbed (covered by test_ocf_multicast); the
    # per-responder reads are real unicast against the two loopback ports.
    monkeypatch.setattr(
        ocf_multicast,
        "discover_ocf_responder_ports",
        lambda target, **kw: SimpleNamespace(
            ports=(bare.port, ac.port), error_code=None
        ),
    )
    try:
        result = discover_ocf_responders(
            "127.0.0.1", interface_address="127.0.0.1", per_read_timeout=1.5
        )
    finally:
        bare.close()
        ac.close()

    assert result.found and len(result.responders) == 2
    typed = [r for r in result.responders if any(t.startswith("oic.d.") for t in r.rt)]
    assert len(typed) == 1
    assert typed[0].rt == ("oic.wk.d", "oic.d.airconditioner")
    assert secure_ports_for_di(result.responders, "ac-di") == (60912,)
    assert secure_ports_for_di(result.responders, "bare-di") == (49999,)
