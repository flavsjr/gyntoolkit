#!/usr/bin/env python3
"""Varredura avançada: port scan (SYN/connect), banner, CVE lookup, host discovery."""

import asyncio
import contextlib
import ipaddress
import json
import os
import re
import threading
import time
from pathlib import Path

import requests
from colorama import Fore, Style
from scapy.all import ARP, IP, TCP, Ether, sr1, srp

from . import i18n
from .core import MAX_THREADS, TOP_PORTS, is_admin_windows, log

# Limite default de sondas simultâneas no port scan. Sem isto, um full scan
# (1-65535) dispara 65k tasks de uma vez e esgota file descriptors/sockets.
DEFAULT_CONCURRENCY = MAX_THREADS

# NVD público permite ~5 req / 30s (≈1 a cada 6s); com API key, ~50 / 30s.
# Serializamos as chamadas e respeitamos o intervalo mínimo p/ não tomar 403/429.
_NVD_MIN_INTERVAL_NO_KEY = 6.0
_NVD_MIN_INTERVAL_KEY = 0.6
_nvd_lock = threading.Lock()
_nvd_last_call = 0.0

# Enriquecimento de CVE: EPSS (probabilidade de exploração) e CISA KEV
# (vulnerabilidades sabidamente exploradas). Ambos públicos, sem key.
_EPSS_URL = "https://api.first.org/data/v1/epss"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_KEV_CACHE_PATH = Path.home() / ".gyntoolkit" / "kev.json"
_KEV_DEFAULT_TTL = 86400  # 24h
_kev_lock = threading.Lock()
_kev_cache: set[str] | None = None  # cache em memória por processo


async def syn_scan(target: str, port: int) -> tuple[int, bool]:
    """Varredura stealth SYN (requer admin/root).

    Se o scapy não conseguir enviar (sem Npcap/interface indisponível), degrada
    para ``connect_scan`` em vez de derrubar toda a varredura.
    """
    try:
        pkt = IP(dst=target)/TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=2, verbose=0)
        if response is None:
            return (port, False)
        return (port, response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12)
    except (OSError, PermissionError) as e:
        log.warning("syn_scan %s:%s falhou: %s", target, port, e)
        return (port, False)
    except Exception as e:
        # scapy indisponível (ex.: interface/Npcap ausente): usa connect scan.
        log.warning("syn_scan indisponível em %s:%s (%s); fallback connect_scan", target, port, e)
        return await connect_scan(target, port)

async def connect_scan(target: str, port: int) -> tuple[int, bool]:
    """Varredura TCP completa"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=2
        )
        writer.close()
        await writer.wait_closed()
        return (port, True)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return (port, False)

async def get_banner(target: str, port: int) -> tuple[int, str]:
    """Obtém banner do serviço.

    Muitos serviços (SSH, FTP, SMTP, POP3, IMAP) enviam um greeting ao conectar:
    tenta ler passivamente primeiro. Se nada chega (ex.: HTTP, que espera uma
    requisição), envia um probe HTTP com header ``Host`` e lê a resposta.
    """
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=3
        )
        # 1) Greeting passivo (serviços que falam primeiro).
        try:
            banner = await asyncio.wait_for(reader.read(512), timeout=1.5)
        except asyncio.TimeoutError:
            banner = b""
        # 2) Sem greeting: provoca com um GET mínimo e Host válido.
        if not banner.strip():
            writer.write(f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
            with contextlib.suppress(OSError):
                await writer.drain()
            with contextlib.suppress(asyncio.TimeoutError):
                banner = await asyncio.wait_for(reader.read(512), timeout=2)
        return (port, banner.decode(errors="ignore").strip())
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
        log.debug("banner %s:%s vazio: %s", target, port, e)
        return (port, "")
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

def _nvd_throttle(has_key: bool) -> None:
    """Bloqueia até respeitar o intervalo mínimo entre chamadas ao NVD."""
    global _nvd_last_call
    interval = _NVD_MIN_INTERVAL_KEY if has_key else _NVD_MIN_INTERVAL_NO_KEY
    with _nvd_lock:
        wait = interval - (time.monotonic() - _nvd_last_call)
        if wait > 0:
            time.sleep(wait)
        _nvd_last_call = time.monotonic()

# Normaliza nomes de produto do banner → nome do produto no CPE da NVD.
_CPE_PRODUCT_ALIASES = {
    "apache": "http_server",
    "httpd": "http_server",
    "microsoft-iis": "internet_information_services",
    "iis": "internet_information_services",
    "openssh": "openssh",
    "nginx": "nginx",
    "lighttpd": "lighttpd",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "pureftpd": "pure-ftpd",
    "postfix": "postfix",
    "exim": "exim",
    "sendmail": "sendmail",
    "dovecot": "dovecot",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "redis": "redis",
    "mongodb": "mongodb",
    "openssl": "openssl",
    "samba": "samba",
    "bind": "bind",
}

# Ordem importa: padrões mais específicos primeiro.
_BANNER_PATTERNS = (
    # SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
    re.compile(r"ssh-[\d.]+-openssh[_-](?P<ver>\d+\.\d+(?:\.\d+)?(?:p\d+)?)", re.I),
    # 220 (vsFTPd 3.0.3)
    re.compile(r"(?P<prod>vsftpd)[ /_](?P<ver>\d+\.\d+(?:\.\d+)?)", re.I),
    # Server: nginx/1.18.0  |  Apache/2.4.41  |  lighttpd/1.4.55
    re.compile(r"server:\s*(?P<prod>[A-Za-z][\w+-]*)[/ ](?P<ver>\d+\.\d+(?:\.\d+)?)", re.I),
    # genérico: produto/versão ou produto_versão  (OpenSSH_8.2p1, nginx/1.18.0)
    re.compile(r"(?P<prod>[A-Za-z][\w+-]{2,})[/_ ]v?(?P<ver>\d+\.\d+(?:\.\d+)?(?:p\d+)?)", re.I),
)


def parse_service(banner: str) -> tuple[str, str | None]:
    """Extrai (produto, versão) de um banner, best-effort.

    Produto é minúsculo e normalizado p/ o nome usado no CPE da NVD quando há
    alias conhecido. Versão é ``None`` quando não identificada. Sem match, usa o
    primeiro token como produto.
    """
    if not banner:
        return ("", None)
    text = banner.strip()
    for pat in _BANNER_PATTERNS:
        m = pat.search(text)
        if not m:
            continue
        gd = m.groupdict()
        # padrão OpenSSH não captura 'prod' (nome fixo)
        prod = (gd.get("prod") or "openssh").lower()
        prod = _CPE_PRODUCT_ALIASES.get(prod, prod)
        return (prod, gd.get("ver"))
    token = re.split(r"[/_ ]", text, maxsplit=1)[0].lower()
    # token puramente numérico (ex.: código de status "220") não é um produto:
    # evita uma consulta de keyword inútil e ruidosa ao NVD.
    if not token or token.isdigit():
        return ("", None)
    return (_CPE_PRODUCT_ALIASES.get(token, token), None)


def _build_cpe(product: str, version: str) -> str:
    """Monta um CPE 2.3 match string (vendor curinga) p/ virtualMatchString."""
    return f"cpe:2.3:a:*:{product}:{version}:*:*:*:*:*:*:*"


def _severity_from_cvss(score: float | None) -> str:
    """Mapeia CVSS base score → faixa de severidade (tokens neutros p/ i18n)."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def _extract_cvss(cve_item: dict) -> tuple[float | None, str | None]:
    """Extrai (baseScore, severity) do item NVD. Preferência v3.1 > v3.0 > v2."""
    metrics = cve_item.get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            sev = (data.get("baseSeverity") or "").lower() or None
            return (score, sev)
    v2 = metrics.get("cvssMetricV2")
    if v2:
        score = v2[0].get("cvssData", {}).get("baseScore")
        sev = (v2[0].get("baseSeverity") or "").lower() or None
        return (score, sev or _severity_from_cvss(score))
    return (None, None)


def _nvd_get(params: dict, api_key: str) -> list[dict]:
    """Requisita o NVD e retorna até 5 CVEs com CVSS. [] em erro/sem dados.

    Cada item: ``{"id", "cvss", "severity"}`` (severity deriva do CVSS quando o
    NVD não informa baseSeverity explícito).
    """
    headers = {"User-Agent": "gyntoolkit/2.0"}
    if api_key:
        headers["apiKey"] = api_key
    _nvd_throttle(bool(api_key))
    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={**params, "resultsPerPage": 5},
            headers=headers,
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        out = []
        for item in data.get("vulnerabilities", [])[:5]:
            cvss, sev = _extract_cvss(item)
            out.append({
                "id": item["cve"]["id"],
                "cvss": cvss,
                "severity": sev or _severity_from_cvss(cvss),
            })
        return out
    except (requests.RequestException, ValueError, KeyError) as e:
        log.warning("NVD lookup falhou (%s): %s", params, e)
        return []


def _epss_scores(cve_ids: list[str], timeout: int = 10) -> dict[str, float]:
    """Busca scores EPSS (prob. de exploração) em lote. {} em erro."""
    if not cve_ids:
        return {}
    try:
        response = requests.get(
            _EPSS_URL,
            params={"cve": ",".join(cve_ids)},
            headers={"User-Agent": "gyntoolkit/2.0"},
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        return {
            row["cve"]: float(row["epss"])
            for row in data.get("data", [])
            if row.get("cve") and row.get("epss") is not None
        }
    except (requests.RequestException, ValueError, KeyError, TypeError) as e:
        log.warning("EPSS lookup falhou: %s", e)
        return {}


def _load_kev(ttl: int = _KEV_DEFAULT_TTL, timeout: int = 15) -> set[str]:
    """Carrega o catálogo CISA KEV (set de CVE ids), com cache em disco + memória.

    Cache em ``~/.gyntoolkit/kev.json``; rebaixa gracioso p/ cache velho ou vazio
    se a rede falhar.
    """
    global _kev_cache
    with _kev_lock:
        if _kev_cache is not None:
            return _kev_cache
        # cache em disco válido?
        try:
            if _KEV_CACHE_PATH.is_file() and (time.time() - _KEV_CACHE_PATH.stat().st_mtime) < ttl:
                ids = set(json.loads(_KEV_CACHE_PATH.read_text(encoding="utf-8")))
                _kev_cache = ids
                return ids
        except (OSError, ValueError) as e:
            log.debug("KEV cache leitura falhou: %s", e)
        # baixa feed
        try:
            response = requests.get(_KEV_URL, headers={"User-Agent": "gyntoolkit/2.0"}, timeout=timeout)
            response.raise_for_status()
            ids = {v["cveID"] for v in response.json().get("vulnerabilities", []) if v.get("cveID")}
            with contextlib.suppress(OSError):
                _KEV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
                _KEV_CACHE_PATH.write_text(json.dumps(sorted(ids)), encoding="utf-8")
            _kev_cache = ids
            return ids
        except (requests.RequestException, ValueError, KeyError) as e:
            log.warning("KEV feed falhou: %s", e)
        # fallback: cache velho em disco, se houver
        try:
            if _KEV_CACHE_PATH.is_file():
                return set(json.loads(_KEV_CACHE_PATH.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
        _kev_cache = set()
        return _kev_cache


def check_vulnerabilities(
    service: str,
    api_key: str = "",
    enrich: bool = True,
    kev_ttl: int = _KEV_DEFAULT_TTL,
) -> list[dict]:
    """Consulta CVEs no NVD a partir de um banner/serviço e os enriquece.

    Estratégia de match: parseia produto+versão do banner. Com versão, consulta
    por CPE (``virtualMatchString``), bem mais preciso que keyword. Sem resultado
    (ou sem versão), cai para ``keywordSearch`` com 'produto versão' ou só o produto.

    Enriquecimento (``enrich=True``): anexa ``epss`` (prob. exploração) e ``kev``
    (bool, CISA Known Exploited). Cada item:
    ``{"id","cvss","severity","epss","kev"}``.
    """
    if not service or service.lower() in {"desconhecido", "unknown"}:
        return []

    product, version = parse_service(service)
    if not product:
        return []

    cves: list[dict] = []
    if version:
        cves = _nvd_get({"virtualMatchString": _build_cpe(product, version)}, api_key)
        if not cves:
            cves = _nvd_get({"keywordSearch": f"{product} {version}"}, api_key)
    else:
        cves = _nvd_get({"keywordSearch": product}, api_key)

    if not cves:
        return []

    for c in cves:
        c.setdefault("epss", None)
        c.setdefault("kev", False)

    if enrich:
        ids = [c["id"] for c in cves]
        epss = _epss_scores(ids)
        kev = _load_kev(ttl=kev_ttl)
        for c in cves:
            c["epss"] = epss.get(c["id"])
            c["kev"] = c["id"] in kev
            if c["kev"]:
                c["severity"] = "critical"  # KEV é sempre prioridade máxima
    return cves

def network_discovery(cidr: str, timeout: int = 2) -> list[str]:
    """Descobre hosts ativos em rede via ARP scan (requer privilégio)."""
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        log.error("CIDR inválido '%s': %s", cidr, e)
        print(f"{Fore.RED}{i18n.t('scan.cidr_invalid', err=e)}{Style.RESET_ALL}")
        return []

    try:
        arp = ARP(pdst=cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(ether / arp, timeout=timeout, verbose=0)
        hosts = sorted({r.psrc for _, r in answered}, key=lambda ip: ipaddress.ip_address(ip))
        return hosts
    except PermissionError:
        print(f"{Fore.RED}{i18n.t('scan.arp_priv')}{Style.RESET_ALL}")
        return []
    except OSError as e:
        log.error("ARP scan falhou: %s", e)
        print(f"{Fore.RED}{i18n.t('scan.arp_fail', err=e)}{Style.RESET_ALL}")
        return []

# Ordem de severidade p/ computar o risco do host (maior vence).
_SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _host_risk(vulns: list[dict]) -> str:
    """Risco do host = maior severidade entre os CVEs. Sem CVE → 'low'."""
    if not vulns:
        return "low"
    top = max((_SEVERITY_RANK.get(v.get("severity", "unknown"), 0) for v in vulns), default=0)
    for name, rank in _SEVERITY_RANK.items():
        if rank == top:
            return name if name != "unknown" else "low"
    return "low"


def _filter_vulns(vulns: list[dict], min_cvss: float, kev_only: bool) -> list[dict]:
    """Aplica filtros de exibição: CVSS mínimo e/ou somente KEV."""
    out = vulns
    if kev_only:
        out = [v for v in out if v.get("kev")]
    if min_cvss > 0:
        out = [v for v in out if (v.get("cvss") or 0) >= min_cvss]
    return out


async def perform_scan(
    target: str,
    scan_type: str,
    concurrency: int = DEFAULT_CONCURRENCY,
    nvd_api_key: str = "",
    min_cvss: float = 0.0,
    kev_only: bool = False,
) -> dict[int, dict]:
    """Executa varredura completa com análise de vulnerabilidades.

    ``concurrency`` limita sondas simultâneas (evita esgotar sockets no full scan).
    ``nvd_api_key`` (opcional) eleva o rate-limit da consulta de CVEs no NVD.
    ``min_cvss``/``kev_only`` filtram os CVEs exibidos (não a coleta).
    """
    # aceita canônico "fast" e legados pt ("rápido"/"rapido"); resto = full range
    ports = TOP_PORTS if scan_type in ("fast", "rápido", "rapido") else range(1, 65536)
    open_ports = []
    results = {}
    sem = asyncio.Semaphore(max(1, concurrency))

    # Fase 1: Varredura de portas.
    # Privilégio é constante durante o scan: decide SYN vs connect uma vez.
    use_syn = os.geteuid() == 0 if os.name == 'posix' else is_admin_windows()  # type: ignore[attr-defined]

    async def _scan_one(port: int) -> tuple[int, bool]:
        async with sem:
            return await (syn_scan(target, port) if use_syn else connect_scan(target, port))

    for future in asyncio.as_completed([_scan_one(p) for p in ports]):
        port, is_open = await future
        if is_open:
            open_ports.append(port)

    # Fase 2: Obter banners (também sob o limite de concorrência).
    async def _banner_one(port: int) -> tuple[int, str]:
        async with sem:
            return await get_banner(target, port)

    banners: dict[int, str] = {}
    for b_future in asyncio.as_completed([_banner_one(p) for p in open_ports]):
        port, banner = await b_future
        banners[port] = banner

    # Fase 3: Analisar vulnerabilidades. O lookup usa o banner inteiro (parseia
    # produto+versão → CPE). Dedup por banner: consulta o NVD uma vez por banner
    # distinto (rate-limit caro) e reaproveita o resultado.
    vuln_cache: dict[str, list[dict]] = {}
    for port in open_ports:
        banner = banners[port]
        service = banner.split()[0] if banner else "unknown"
        if banner not in vuln_cache:
            vuln_cache[banner] = check_vulnerabilities(banner, api_key=nvd_api_key)
        vulns = _filter_vulns(vuln_cache[banner], min_cvss, kev_only)

        # 'service' e 'risco' são tokens neutros (DATA); o display os localiza
        # via i18n (scan.service_unknown / scan.risk_*). 'vulnerabilidades' agora
        # é lista de dicts enriquecidos {id, cvss, severity, epss, kev}.
        results[port] = {
            'service': service,
            'banner': banners[port],
            'vulnerabilidades': vulns,
            'risco': _host_risk(vulns),
        }

    return results
