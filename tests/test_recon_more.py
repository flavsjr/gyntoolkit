"""Mais cobertura de recon — rede/DNS/socket mockados (offline)."""
import dns.resolver

import gyntoolkit.recon as recon


class _RD:
    def __init__(self, s):
        self._s = s

    def to_text(self):
        return self._s

    def __str__(self):
        return self._s


# ---------- dns_lookup ----------
class _FakeResolver:
    def __init__(self):
        self.lifetime = 0
        self.nameservers = []

    def resolve(self, domain, rtype):
        return [_RD("1.2.3.4"), _RD("5.6.7.8")]


def test_dns_lookup_records(monkeypatch):
    monkeypatch.setattr(recon.dns.resolver, "Resolver", _FakeResolver)
    out = recon.dns_lookup("example.com", "A")
    assert out == ["1.2.3.4", "5.6.7.8"]


def test_dns_lookup_no_answer(monkeypatch):
    class _R(_FakeResolver):
        def resolve(self, domain, rtype):
            raise dns.resolver.NoAnswer()
    monkeypatch.setattr(recon.dns.resolver, "Resolver", _R)
    out = recon.dns_lookup("example.com", "MX")
    assert len(out) == 1 and "MX" in out[0]


def test_dns_lookup_nxdomain(monkeypatch):
    class _R(_FakeResolver):
        def resolve(self, domain, rtype):
            raise dns.resolver.NXDOMAIN()
    monkeypatch.setattr(recon.dns.resolver, "Resolver", _R)
    out = recon.dns_lookup("nope.invalid", "A")
    assert len(out) == 1


# ---------- reverse_dns ----------
def test_reverse_dns_ok(monkeypatch):
    monkeypatch.setattr(recon.socket, "gethostbyaddr",
                        lambda ip: ("host.example.com", ["alias"], ["1.2.3.4"]))
    out = recon.reverse_dns("1.2.3.4")
    assert out["hostname"] == "host.example.com"


def test_reverse_dns_no_ptr(monkeypatch):
    import socket as _s
    monkeypatch.setattr(recon.socket, "gethostbyaddr",
                        lambda ip: (_ for _ in ()).throw(_s.herror("no ptr")))
    out = recon.reverse_dns("1.2.3.4")
    assert "erro" in out


# ---------- mac_vendor ----------
def test_mac_vendor_ok(monkeypatch):
    class _Resp:
        status_code = 200
        text = "Cisco Systems"
    monkeypatch.setattr(recon.requests, "get", lambda *a, **k: _Resp())
    assert recon.mac_vendor("00:1A:2B:3C:4D:5E") == "Cisco Systems"


def test_mac_vendor_invalid():
    out = recon.mac_vendor("zz:zz")
    assert "zz:zz".upper() in out or "inv" in out.lower()


# ---------- ssl_inspect (error path) ----------
def test_ssl_inspect_conn_refused(monkeypatch):
    def _boom(*a, **k):
        raise ConnectionRefusedError("refused")
    monkeypatch.setattr(recon.socket, "create_connection", _boom)
    out = recon.ssl_inspect("example.com", 443)
    assert "erro" in out


# ---------- whois_lookup ----------
def test_whois_lookup(monkeypatch):
    monkeypatch.setattr(recon.whois, "whois", lambda d: {"domain_name": d, "registrar": "X"})
    out = recon.whois_lookup("example.com")
    assert out["registrar"] == "X"


# ---------- zone_transfer ----------
def test_zone_transfer_refused(monkeypatch):
    monkeypatch.setattr(recon.dns.resolver, "resolve", lambda d, rt, lifetime=10: [_RD("ns1.example.com.")])
    monkeypatch.setattr(recon.socket, "gethostbyname", lambda h: "9.9.9.9")

    def _xfr_boom(*a, **k):
        raise Exception("refused")
    monkeypatch.setattr(recon.dns.zone, "from_xfr", _xfr_boom)
    out = recon.zone_transfer("example.com")
    assert out["vulnerable"] is False
    assert "ns1.example.com" in out["nameservers"]


def test_zone_transfer_no_ns(monkeypatch):
    monkeypatch.setattr(recon.dns.resolver, "resolve",
                        lambda d, rt, lifetime=10: (_ for _ in ()).throw(Exception("no ns")))
    out = recon.zone_transfer("example.com")
    assert "erro" in out
