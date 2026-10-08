#!/usr/bin/env python3
"""Postura de segurança de e-mail/DNS: SPF, DKIM, DMARC, DNSSEC e CAA.

Consulta e **analisa** (não só despeja) os registros relevantes de um domínio,
emitindo um veredito por item (``ok`` / ``weak`` / ``missing``) e um resumo.
Tudo via DNS (``dnspython``), sem API key.

Vereditos são tokens neutros (DATA); o display os localiza via i18n.
"""

import dns.exception
import dns.resolver

from .core import log, sanitize_input

# Seletores DKIM comuns testados por padrão (DKIM exige seletor conhecido;
# ausência aqui NÃO prova ausência de DKIM).
DEFAULT_DKIM_SELECTORS: tuple[str, ...] = (
    "default", "google", "selector1", "selector2", "k1", "dkim", "mail",
    "smtp", "mandrill", "mailjet", "amazonses", "pm", "zoho", "s1", "s2",
)

# Mecanismos SPF que consomem DNS-lookups (limite RFC 7208 = 10).
_SPF_LOOKUP_MECHANISMS = ("include:", "a:", "mx:", "ptr", "exists:", "redirect=", "a ", "mx ")


def _txt(name: str, timeout: int = 5) -> list[str]:
    """Resolve registros TXT de ``name`` (strings já concatenadas). [] se nada."""
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=timeout)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.Timeout):
        return []
    except Exception as e:  # noqa: BLE001 - DNS tem muitas exceções de borda
        log.debug("TXT %s falhou: %s", name, e)
        return []
    out = []
    for r in answers:
        parts = getattr(r, "strings", None) or []
        out.append("".join(s.decode(errors="ignore") if isinstance(s, bytes) else s for s in parts))
    return out


def _has_rrset(name: str, rdtype: str, timeout: int = 5) -> bool:
    """True se ``name`` tem registro ``rdtype`` (usado p/ DNSKEY/DS presence)."""
    try:
        dns.resolver.resolve(name, rdtype, lifetime=timeout)
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.Timeout):
        return False
    except Exception as e:  # noqa: BLE001
        log.debug("%s %s falhou: %s", rdtype, name, e)
        return False


def analyze_spf(domain: str, timeout: int = 5) -> dict:
    """Analisa SPF: presença, qualificador ``all`` e contagem de DNS-lookups."""
    records = [t for t in _txt(domain, timeout) if t.lower().startswith("v=spf1")]
    if not records:
        return {"verdict": "missing", "record": None}
    record = records[0]
    low = record.lower()
    # qualificador final do 'all'
    all_q = None
    for q in ("-all", "~all", "?all", "+all"):
        if q in low:
            all_q = q
            break
    # contagem (estática, não-recursiva) de mecanismos que geram lookup
    lookups = sum(low.count(m) for m in ("include:", "a:", "mx:", "exists:", "redirect="))
    lookups += len([tok for tok in low.split() if tok in ("a", "mx", "ptr")])
    verdict = "ok"
    notes = []
    if all_q == "+all":
        verdict = "weak"
        notes.append("+all allows any sender")
    elif all_q is None:
        verdict = "weak"
        notes.append("no 'all' mechanism")
    if lookups > 10:
        verdict = "weak"
        notes.append(f"{lookups} DNS lookups (>10 RFC limit; estimate)")
    return {"verdict": verdict, "record": record, "all": all_q, "lookups": lookups, "notes": notes}


def analyze_dmarc(domain: str, timeout: int = 5) -> dict:
    """Analisa DMARC em ``_dmarc.<domain>``: política e rua/ruf."""
    records = [t for t in _txt(f"_dmarc.{domain}", timeout) if t.lower().startswith("v=dmarc1")]
    if not records:
        return {"verdict": "missing", "record": None}
    record = records[0]
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            tags[k.strip().lower()] = v.strip()
    policy = tags.get("p", "").lower()
    verdict = "ok" if policy in ("quarantine", "reject") else "weak"
    return {
        "verdict": verdict,
        "record": record,
        "policy": policy or None,
        "subdomain_policy": tags.get("sp"),
        "pct": tags.get("pct"),
        "rua": tags.get("rua"),
    }


def analyze_dkim(domain: str, selectors: list[str] | None = None, timeout: int = 5) -> dict:
    """Testa seletores DKIM em ``<selector>._domainkey.<domain>``."""
    sels = list(selectors) if selectors else list(DEFAULT_DKIM_SELECTORS)
    found = []
    for sel in sels:
        records = _txt(f"{sel}._domainkey.{domain}", timeout)
        if any("v=dkim1" in r.lower() or "k=" in r.lower() or "p=" in r.lower() for r in records):
            found.append(sel)
    # DKIM não pode ser enumerado exaustivamente: achar = ok; não achar = unknown.
    verdict = "ok" if found else "unknown"
    return {"verdict": verdict, "selectors_found": found, "selectors_tested": sels}


def analyze_dnssec(domain: str, timeout: int = 5) -> dict:
    """Checa presença de DNSSEC (DNSKEY/DS). Presença != validação de cadeia."""
    dnskey = _has_rrset(domain, "DNSKEY", timeout)
    ds = _has_rrset(domain, "DS", timeout)
    verdict = "ok" if (dnskey or ds) else "missing"
    return {"verdict": verdict, "dnskey": dnskey, "ds": ds,
            "note": "presence only, not full chain validation"}


def analyze_caa(domain: str, timeout: int = 5) -> dict:
    """Lista registros CAA (autoridades de certificado permitidas)."""
    try:
        answers = dns.resolver.resolve(domain, "CAA", lifetime=timeout)
        records = [r.to_text() for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.Timeout):
        records = []
    except Exception as e:  # noqa: BLE001
        log.debug("CAA %s falhou: %s", domain, e)
        records = []
    return {"verdict": "ok" if records else "missing", "records": records}


def mailsec_report(domain: str, selectors: list[str] | None = None, timeout: int = 5) -> dict:
    """Roda todas as checagens e agrega com resumo de vereditos."""
    domain = sanitize_input(domain, r"[A-Za-z0-9.-]")
    checks = {
        "spf": analyze_spf(domain, timeout),
        "dmarc": analyze_dmarc(domain, timeout),
        "dkim": analyze_dkim(domain, selectors, timeout),
        "dnssec": analyze_dnssec(domain, timeout),
        "caa": analyze_caa(domain, timeout),
    }
    summary = {"ok": 0, "weak": 0, "missing": 0, "unknown": 0}
    for c in checks.values():
        summary[c["verdict"]] = summary.get(c["verdict"], 0) + 1
    return {"domain": domain, "checks": checks, "summary": summary}
