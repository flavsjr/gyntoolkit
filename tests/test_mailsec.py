"""Testes de email security recon (SPF/DKIM/DMARC/DNSSEC/CAA) — offline, mocks."""
import gyntoolkit.mailsec as m
from gyntoolkit.cli import _mailsec_detail
from gyntoolkit.mailsec import (
    analyze_dkim,
    analyze_dmarc,
    analyze_dnssec,
    analyze_spf,
    mailsec_report,
)


# ---------- SPF ----------
def test_spf_ok(monkeypatch):
    monkeypatch.setattr(m, "_txt", lambda n, t=5: ["v=spf1 include:_spf.google.com -all"])
    r = analyze_spf("ex.com")
    assert r["verdict"] == "ok"
    assert r["all"] == "-all"
    assert r["lookups"] == 1


def test_spf_plus_all_weak(monkeypatch):
    monkeypatch.setattr(m, "_txt", lambda n, t=5: ["v=spf1 +all"])
    assert analyze_spf("ex.com")["verdict"] == "weak"


def test_spf_too_many_lookups_weak(monkeypatch):
    rec = "v=spf1 " + " ".join(f"include:h{i}.com" for i in range(11)) + " -all"
    monkeypatch.setattr(m, "_txt", lambda n, t=5: [rec])
    r = analyze_spf("ex.com")
    assert r["verdict"] == "weak"
    assert r["lookups"] == 11


def test_spf_missing(monkeypatch):
    monkeypatch.setattr(m, "_txt", lambda n, t=5: [])
    assert analyze_spf("ex.com")["verdict"] == "missing"


# ---------- DMARC ----------
def test_dmarc_reject_ok(monkeypatch):
    monkeypatch.setattr(m, "_txt", lambda n, t=5: ["v=DMARC1; p=reject; rua=mailto:x@ex.com"])
    r = analyze_dmarc("ex.com")
    assert r["verdict"] == "ok"
    assert r["policy"] == "reject"


def test_dmarc_none_weak(monkeypatch):
    monkeypatch.setattr(m, "_txt", lambda n, t=5: ["v=DMARC1; p=none"])
    assert analyze_dmarc("ex.com")["verdict"] == "weak"


def test_dmarc_missing(monkeypatch):
    monkeypatch.setattr(m, "_txt", lambda n, t=5: [])
    assert analyze_dmarc("ex.com")["verdict"] == "missing"


# ---------- DKIM ----------
def test_dkim_found_selector(monkeypatch):
    def fake_txt(name, t=5):
        return ["v=DKIM1; k=rsa; p=ABC"] if name.startswith("google._domainkey") else []
    monkeypatch.setattr(m, "_txt", fake_txt)
    r = analyze_dkim("ex.com", selectors=["google", "default"])
    assert r["verdict"] == "ok"
    assert r["selectors_found"] == ["google"]


def test_dkim_none(monkeypatch):
    monkeypatch.setattr(m, "_txt", lambda n, t=5: [])
    assert analyze_dkim("ex.com", selectors=["x"])["verdict"] == "unknown"


# ---------- DNSSEC ----------
def test_dnssec_signed(monkeypatch):
    monkeypatch.setattr(m, "_has_rrset", lambda n, rd, t=5: rd == "DNSKEY")
    r = analyze_dnssec("ex.com")
    assert r["verdict"] == "ok"
    assert r["dnskey"] is True


def test_dnssec_missing(monkeypatch):
    monkeypatch.setattr(m, "_has_rrset", lambda n, rd, t=5: False)
    assert analyze_dnssec("ex.com")["verdict"] == "missing"


# ---------- report agregado ----------
def test_mailsec_report_summary(monkeypatch):
    monkeypatch.setattr(m, "_txt", lambda n, t=5: (
        ["v=spf1 -all"] if n == "ex.com"
        else ["v=DMARC1; p=reject"] if n == "_dmarc.ex.com"
        else []
    ))
    monkeypatch.setattr(m, "_has_rrset", lambda n, rd, t=5: False)  # DNSSEC missing
    monkeypatch.setattr(m.dns.resolver, "resolve", lambda *a, **k: (_ for _ in ()).throw(m.dns.resolver.NoAnswer()))
    r = mailsec_report("ex.com")
    assert r["domain"] == "ex.com"
    assert r["checks"]["spf"]["verdict"] == "ok"
    assert r["checks"]["dmarc"]["verdict"] == "ok"
    assert r["checks"]["dnssec"]["verdict"] == "missing"
    assert r["summary"]["ok"] >= 2


# ---------- CLI detalhe ----------
def test_mailsec_detail_dmarc():
    assert _mailsec_detail("dmarc", {"policy": "reject"}) == "p=reject"


def test_mailsec_detail_dkim_none():
    assert _mailsec_detail("dkim", {"selectors_found": []}) == "no selector matched"
