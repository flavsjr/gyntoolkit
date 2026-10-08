"""Testes offline do módulo Shodan (sem rede: no-key path + parser)."""
from gyntoolkit import commands, i18n
from gyntoolkit.recon import _summarize_shodan, shodan_host


def test_no_key_returns_hint():
    i18n.set_lang("en")
    out = shodan_host("8.8.8.8", api_key="")
    assert "erro" in out
    assert "api key" in out["erro"].lower()


def test_summarize_shodan_fields():
    raw = {
        "ip_str": "1.2.3.4",
        "org": "ACME",
        "isp": "ACME ISP",
        "asn": "AS123",
        "os": None,
        "country_name": "Brazil",
        "hostnames": ["host.acme.com"],
        "ports": [443, 22, 80],
        "tags": ["cloud"],
        "vulns": ["CVE-2021-1234", "CVE-2020-0001"],
        "data": [
            {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.18.0", "cpe": ["cpe:/a:nginx"]},
            {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.2"},
        ],
        "last_update": "2024-01-01",
    }
    s = _summarize_shodan(raw)
    assert s["ip"] == "1.2.3.4"
    assert s["ports"] == [22, 80, 443]            # ordenado
    assert s["vulns"] == ["CVE-2020-0001", "CVE-2021-1234"]
    assert [svc["port"] for svc in s["services"]] == [22, 80]   # ordenado por porta
    assert s["services"][1]["product"] == "nginx"


def test_cli_shodan_no_key(capsys):
    import json
    rc = commands.run(["recon", "shodan", "8.8.8.8"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "erro" in out       # sem key configurada → erro orientando


# ---------- paths HTTP (rede mockada) ----------
import gyntoolkit.recon as recon  # noqa: E402


class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise recon.requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def test_shodan_host_200_summarized(monkeypatch):
    raw = {"ip_str": "1.2.3.4", "ports": [443, 80], "data": [{"port": 80, "product": "nginx"}]}
    monkeypatch.setattr(recon.requests, "get", lambda *a, **k: _Resp(200, raw))
    out = shodan_host("1.2.3.4", api_key="k")
    assert out["ip"] == "1.2.3.4"
    assert out["ports"] == [80, 443]


def test_shodan_host_401(monkeypatch):
    monkeypatch.setattr(recon.requests, "get", lambda *a, **k: _Resp(401))
    out = shodan_host("1.2.3.4", api_key="bad")
    assert "erro" in out and "401" in out["erro"]


def test_shodan_host_404(monkeypatch):
    monkeypatch.setattr(recon.requests, "get", lambda *a, **k: _Resp(404))
    out = shodan_host("1.2.3.4", api_key="k")
    assert "info" in out
