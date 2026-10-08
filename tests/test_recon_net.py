"""Testes dos módulos de recon que usam HTTP — rede mockada (offline)."""
import gyntoolkit.recon as recon


class _FakeResp:
    def __init__(self, *, status=200, payload=None, text="", headers=None, url="", history=None):
        self.status_code = status
        self._payload = payload
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.history = history or []

    def raise_for_status(self):
        if self.status_code >= 400:
            raise recon.requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


# ---------- geo_ip ----------
def test_geo_ip_success(monkeypatch):
    monkeypatch.setattr(recon.socket, "gethostbyname", lambda t: "1.2.3.4")
    monkeypatch.setattr(recon.requests, "get",
                        lambda *a, **k: _FakeResp(payload={"status": "success", "country": "Brazil", "query": "1.2.3.4"}))
    out = recon.geo_ip("example.com")
    assert out["country"] == "Brazil"
    assert "erro" not in out


def test_geo_ip_api_failure(monkeypatch):
    monkeypatch.setattr(recon.socket, "gethostbyname", lambda t: "1.2.3.4")
    monkeypatch.setattr(recon.requests, "get",
                        lambda *a, **k: _FakeResp(payload={"status": "fail", "message": "reserved range"}))
    out = recon.geo_ip("10.0.0.1")
    assert "erro" in out


# ---------- internetdb_lookup ----------
def test_internetdb_success(monkeypatch):
    monkeypatch.setattr(recon.requests, "get",
                        lambda *a, **k: _FakeResp(payload={"ip": "1.2.3.4", "ports": [80, 443], "vulns": ["CVE-1"]}))
    out = recon.internetdb_lookup("1.2.3.4")
    assert out["ports"] == [80, 443]


def test_internetdb_404(monkeypatch):
    monkeypatch.setattr(recon.requests, "get", lambda *a, **k: _FakeResp(status=404))
    out = recon.internetdb_lookup("1.2.3.4")
    assert "info" in out


# ---------- hibp_breaches ----------
def test_hibp_breaches_list(monkeypatch):
    monkeypatch.setattr(recon.requests, "get",
                        lambda *a, **k: _FakeResp(payload=[{"Name": "Acme", "BreachDate": "2020-01-01"}]))
    out = recon.hibp_breaches("example.com")
    assert out[0]["Name"] == "Acme"


def test_hibp_breaches_none_404(monkeypatch):
    monkeypatch.setattr(recon.requests, "get", lambda *a, **k: _FakeResp(status=404))
    assert recon.hibp_breaches("example.com") == []


# ---------- http_fingerprint ----------
def test_http_fingerprint_detects_tech(monkeypatch):
    resp = _FakeResp(
        status=200,
        headers={"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1"},
        text="<html>wp-content/themes ...</html>",
        url="https://example.com",
    )
    monkeypatch.setattr(recon.requests, "get", lambda *a, **k: resp)
    out = recon.http_fingerprint("https://example.com")
    assert out["server"] == "nginx/1.18.0"
    assert "nginx" in out["tech"]
    assert "PHP" in out["tech"]
    assert "WordPress" in out["tech"]


# ---------- subdomain_enum ----------
def test_subdomain_enum_dedup_and_filter(monkeypatch):
    payload = [
        {"name_value": "a.example.com\n*.example.com"},
        {"name_value": "a.example.com"},          # duplicado
        {"name_value": "b.example.com"},
        {"name_value": "other.test"},             # fora do domínio → filtrado
    ]
    monkeypatch.setattr(recon.requests, "get", lambda *a, **k: _FakeResp(payload=payload))
    subs = recon.subdomain_enum("example.com")
    assert subs == ["a.example.com", "b.example.com", "example.com"]
