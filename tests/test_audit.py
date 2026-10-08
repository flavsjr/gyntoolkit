"""Testes do orquestrador audit (offline: stages mockados)."""
import asyncio

import gyntoolkit.audit as audit
from gyntoolkit.audit import _select_stages, _summarize, run_audit


# ---------- seleção de etapas ----------
def test_select_passive_for_domain():
    s = _select_stages(is_ip=False, active=False, only=None, skip=None)
    assert "mailsec" in s and "subdomains" in s
    assert "scan" not in s            # sem active


def test_select_skips_domain_only_for_ip():
    s = _select_stages(is_ip=True, active=False, only=None, skip=None)
    assert "mailsec" not in s and "subdomains" not in s and "whois" not in s
    assert "geo" in s


def test_select_active_adds_scan():
    s = _select_stages(is_ip=True, active=True, only=None, skip=None)
    assert "scan" in s


def test_select_only_and_skip():
    s = _select_stages(is_ip=False, active=True, only=["dns", "scan", "ssl"], skip=["ssl"])
    assert set(s) == {"dns", "scan"}


def test_select_only_excludes_scan_when_inactive():
    s = _select_stages(is_ip=False, active=False, only=["dns", "scan"], skip=None)
    assert s == ["dns"]               # scan só com active


# ---------- resumo ----------
def test_summarize_counts():
    out = {
        "scan": {"80": {"vulnerabilidades": [{"id": "C1", "kev": True}, {"id": "C2", "kev": False}]}},
        "subdomains": {"total": 3},
        "mailsec": {"summary": {"weak": 1, "missing": 2, "ok": 2}},
    }
    s = _summarize(out)
    assert s["open_ports"] == 1
    assert s["cves"] == 2
    assert s["kev_cves"] == 1
    assert s["subdomains"] == 3
    assert s["mailsec_weak"] == 3


# ---------- run_audit ----------
def test_run_audit_passive(monkeypatch):
    monkeypatch.setattr(audit, "_passive_stage", lambda name, target, ctx: {"ok": name})
    report = asyncio.run(run_audit("example.com"))
    assert report["target"] == "example.com"
    assert report["active"] is False
    assert "scan" not in report["stages"]
    assert report["stages"]["mailsec"] == {"ok": "mailsec"}
    # ordem estável conforme ALL_STAGES
    assert list(report["stages"].keys())[0] == "whois"


def test_run_audit_active_requires_auth(monkeypatch):
    monkeypatch.setattr(audit, "_passive_stage", lambda name, target, ctx: {"ok": name})
    report = asyncio.run(run_audit("example.com", active=True, authorized=False))
    assert report["active"] is False
    assert report["active_requested_without_auth"] is True
    assert "scan" not in report["stages"]


def test_run_audit_active_with_scan(monkeypatch):
    import gyntoolkit.scan as scan

    monkeypatch.setattr(audit, "_passive_stage", lambda name, target, ctx: {"ok": name})

    async def fake_scan(ip, stype, concurrency=100, nvd_api_key="", **kw):
        return {80: {"service": "nginx", "vulnerabilidades": []}}
    monkeypatch.setattr(scan, "perform_scan", fake_scan)

    report = asyncio.run(run_audit("1.2.3.4", active=True, authorized=True))
    assert report["active"] is True
    assert "scan" in report["stages"]
    assert report["stages"]["scan"]["80"]["service"] == "nginx"


def test_run_audit_stage_error_isolated(monkeypatch):
    def boom(name, target, ctx):
        if name == "geo":
            raise RuntimeError("down")
        return {"ok": name}
    monkeypatch.setattr(audit, "_passive_stage", boom)
    report = asyncio.run(run_audit("example.com"))
    assert report["stages"]["geo"] == {"error": "down"}
    assert report["stages"]["dns"] == {"ok": "dns"}   # resto sobrevive
