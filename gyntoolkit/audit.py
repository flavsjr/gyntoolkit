#!/usr/bin/env python3
"""Audit: orquestrador de engajamento — 1 alvo, perfil consolidado.

Roda um pipeline de etapas (recon passivo por padrão; scan ativo só com
``active=True`` + ``authorized=True``) e agrega tudo num único relatório com
resumo executivo. Reaproveita os módulos existentes (recon/scan/mailsec).

Etapas são resilientes: a falha de uma registra ``{"error": ...}`` na sua seção
sem derrubar o resto.
"""

import asyncio
import ipaddress
import socket
from datetime import datetime, timezone
from typing import Any

from .core import log, sanitize_input

# Etapas passivas (seguras) e ativas (intrusivas). Ordem define a saída.
PASSIVE_STAGES = ("whois", "dns", "geo", "subdomains", "ssl", "httpfp",
                  "internetdb", "hibp", "mailsec")
ACTIVE_STAGES = ("scan",)
ALL_STAGES = PASSIVE_STAGES + ACTIVE_STAGES

# Etapas que só fazem sentido p/ domínio (não p/ IP literal).
_DOMAIN_ONLY = {"whois", "subdomains", "hibp", "mailsec"}


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _resolve(target: str) -> str | None:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


# --------------------------------------------------------------------------
# Runners por etapa.
# --------------------------------------------------------------------------
def _passive_stage(name: str, target: str, ctx: dict) -> Any:
    """Executa uma etapa passiva (síncrona: requests/dns). Roda em thread."""
    from . import recon
    from .mailsec import mailsec_report

    is_ip = ctx["is_ip"]
    if name == "whois":
        return {"whois": str(recon.whois_lookup(target))}
    if name == "dns":
        return {t: recon.dns_lookup(target, t) for t in ("A", "MX", "NS", "TXT")}
    if name == "geo":
        return recon.geo_ip(target)
    if name == "subdomains":
        subs = recon.subdomain_enum(target)
        return {"total": len(subs), "subdomains": subs}
    if name == "ssl":
        return recon.ssl_inspect(target, 443)
    if name == "httpfp":
        scheme = "http" if is_ip else "https"
        return recon.http_fingerprint(f"{scheme}://{target}")
    if name == "internetdb":
        return recon.internetdb_lookup(target)
    if name == "hibp":
        return {"breaches": recon.hibp_breaches(target)}
    if name == "mailsec":
        return mailsec_report(target)
    raise ValueError(f"unknown passive stage: {name}")


async def _run_one(name: str, target: str, ctx: dict) -> tuple[str, Any]:
    """Executa uma etapa com captura de erro. Passivas rodam em thread."""
    try:
        if name == "scan":
            from .scan import perform_scan

            ip = target if ctx["is_ip"] else (_resolve(target) or target)
            results = await perform_scan(
                ip, ctx["scan_type"], concurrency=ctx["concurrency"], nvd_api_key=ctx["nvd_key"],
            )
            return (name, {str(port): data for port, data in results.items()})
        return (name, await asyncio.to_thread(_passive_stage, name, target, ctx))
    except Exception as e:  # noqa: BLE001 - etapa resiliente
        log.warning("audit stage '%s' falhou: %s", name, e)
        return (name, {"error": str(e)})


def _select_stages(is_ip: bool, active: bool, only: list[str] | None,
                   skip: list[str] | None) -> list[str]:
    """Resolve a lista final de etapas conforme tipo de alvo e flags."""
    stages = list(PASSIVE_STAGES) + (list(ACTIVE_STAGES) if active else [])
    if only:
        wanted = set(only)
        stages = [s for s in ALL_STAGES if s in wanted and (active or s not in ACTIVE_STAGES)]
    if skip:
        stages = [s for s in stages if s not in set(skip)]
    if is_ip:
        stages = [s for s in stages if s not in _DOMAIN_ONLY]
    return stages


def _summarize(stages_out: dict) -> dict:
    """Resumo executivo: contagens e destaques das seções coletadas."""
    summary: dict[str, Any] = {}
    scan = stages_out.get("scan")
    if isinstance(scan, dict) and "error" not in scan:
        open_ports = list(scan.keys())
        cves = [c for port in scan.values() for c in port.get("vulnerabilidades", [])]
        kev = [c for c in cves if c.get("kev")]
        summary["open_ports"] = len(open_ports)
        summary["cves"] = len(cves)
        summary["kev_cves"] = len(kev)
    subs = stages_out.get("subdomains")
    if isinstance(subs, dict) and "total" in subs:
        summary["subdomains"] = subs["total"]
    mail = stages_out.get("mailsec")
    if isinstance(mail, dict) and "summary" in mail:
        summary["mailsec_weak"] = mail["summary"].get("weak", 0) + mail["summary"].get("missing", 0)
    return summary


async def run_audit(
    target: str,
    active: bool = False,
    authorized: bool = False,
    only: list[str] | None = None,
    skip: list[str] | None = None,
    concurrency: int = 100,
    nvd_key: str = "",
    scan_type: str = "fast",
) -> dict:
    """Roda o audit e devolve o relatório consolidado.

    Etapas ativas (scan) só rodam com ``active=True`` **e** ``authorized=True`` —
    autorização é exigida p/ qualquer ação intrusiva.
    """
    target = sanitize_input(target, r"[A-Za-z0-9.:/-]")
    is_ip = _is_ip(target)
    run_active = active and authorized
    ctx = {"is_ip": is_ip, "concurrency": concurrency, "nvd_key": nvd_key, "scan_type": scan_type}

    stages = _select_stages(is_ip, run_active, only, skip)
    results = await asyncio.gather(*[_run_one(s, target, ctx) for s in stages])
    stages_out = dict(results)
    # reordena conforme ALL_STAGES p/ saída estável
    ordered = {s: stages_out[s] for s in ALL_STAGES if s in stages_out}

    return {
        "target": target,
        "is_ip": is_ip,
        "active": run_active,
        "active_requested_without_auth": active and not authorized,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "summary": _summarize(ordered),
        "stages": ordered,
    }
