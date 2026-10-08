"""Testes do enriquecimento de CVE (CVSS/EPSS/KEV) — offline, com mocks."""
import gyntoolkit.scan as scan
from gyntoolkit.cli import _fmt_cve
from gyntoolkit.scan import (
    _extract_cvss,
    _filter_vulns,
    _host_risk,
    _severity_from_cvss,
    check_vulnerabilities,
)


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


# ---------- CVSS / severidade ----------
def test_severity_from_cvss_bands():
    assert _severity_from_cvss(9.8) == "critical"
    assert _severity_from_cvss(7.0) == "high"
    assert _severity_from_cvss(4.0) == "medium"
    assert _severity_from_cvss(0.1) == "low"
    assert _severity_from_cvss(None) == "unknown"


def test_extract_cvss_prefers_v31():
    item = {"cve": {"metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
    }}}
    assert _extract_cvss(item) == (9.8, "critical")


def test_extract_cvss_v2_fallback():
    item = {"cve": {"metrics": {
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
    }}}
    assert _extract_cvss(item) == (5.0, "medium")


def test_extract_cvss_none():
    assert _extract_cvss({"cve": {"metrics": {}}}) == (None, None)


# ---------- risco do host ----------
def test_host_risk_takes_max_severity():
    vulns = [{"severity": "low"}, {"severity": "critical"}, {"severity": "medium"}]
    assert _host_risk(vulns) == "critical"


def test_host_risk_empty_is_low():
    assert _host_risk([]) == "low"


# ---------- filtros ----------
def test_filter_min_cvss():
    vulns = [{"id": "A", "cvss": 9.8, "kev": False}, {"id": "B", "cvss": 3.0, "kev": False}]
    out = _filter_vulns(vulns, min_cvss=7.0, kev_only=False)
    assert [v["id"] for v in out] == ["A"]


def test_filter_kev_only():
    vulns = [{"id": "A", "cvss": 9.8, "kev": True}, {"id": "B", "cvss": 9.0, "kev": False}]
    out = _filter_vulns(vulns, min_cvss=0, kev_only=True)
    assert [v["id"] for v in out] == ["A"]


# ---------- EPSS / KEV (mock de rede) ----------
def test_epss_scores(monkeypatch):
    payload = {"data": [{"cve": "CVE-1", "epss": "0.42"}, {"cve": "CVE-2", "epss": "0.01"}]}
    monkeypatch.setattr(scan.requests, "get", lambda *a, **k: _FakeResp(payload))
    out = scan._epss_scores(["CVE-1", "CVE-2"])
    assert out == {"CVE-1": 0.42, "CVE-2": 0.01}


def test_load_kev_caches(monkeypatch, tmp_path):
    monkeypatch.setattr(scan, "_kev_cache", None)
    monkeypatch.setattr(scan, "_KEV_CACHE_PATH", tmp_path / "kev.json")
    payload = {"vulnerabilities": [{"cveID": "CVE-1"}, {"cveID": "CVE-2"}]}
    monkeypatch.setattr(scan.requests, "get", lambda *a, **k: _FakeResp(payload))
    kev = scan._load_kev()
    assert kev == {"CVE-1", "CVE-2"}
    assert (tmp_path / "kev.json").is_file()      # gravou cache em disco


# ---------- integração check_vulnerabilities ----------
def test_check_vulnerabilities_enriches(monkeypatch):
    monkeypatch.setattr(scan, "_nvd_get", lambda params, key: [
        {"id": "CVE-1", "cvss": 9.8, "severity": "critical"},
        {"id": "CVE-2", "cvss": 5.0, "severity": "medium"},
    ])
    monkeypatch.setattr(scan, "_epss_scores", lambda ids, timeout=10: {"CVE-1": 0.9})
    monkeypatch.setattr(scan, "_load_kev", lambda ttl=0: {"CVE-2"})
    out = check_vulnerabilities("nginx/1.18.0")
    by_id = {c["id"]: c for c in out}
    assert by_id["CVE-1"]["epss"] == 0.9
    assert by_id["CVE-2"]["kev"] is True
    assert by_id["CVE-2"]["severity"] == "critical"   # KEV força critical


def test_check_vulnerabilities_unknown_service():
    assert check_vulnerabilities("unknown") == []


# ---------- formatação CLI ----------
def test_fmt_cve_compact():
    s = _fmt_cve({"id": "CVE-1", "cvss": 9.8, "epss": 0.9, "kev": True})
    assert s.startswith("CVE-1 (")
    assert "CVSS 9.8" in s and "EPSS 90.0%" in s and "KEV" in s
