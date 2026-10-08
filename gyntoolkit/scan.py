#!/usr/bin/env python3
"""Varredura avançada: port scan (SYN/connect), banner, CVE lookup, host discovery."""

import asyncio
import contextlib
import ipaddress
import os
import threading
import time

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

def check_vulnerabilities(service: str, api_key: str = "") -> list[str]:
    """Consulta NVD API 2.0 por CVEs associados ao serviço (com rate-limit)."""
    if not service or service.lower() in {"desconhecido", "unknown"}:
        return []
    headers = {"User-Agent": "gyntoolkit/2.0"}
    if api_key:
        headers["apiKey"] = api_key
    _nvd_throttle(bool(api_key))
    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": service, "resultsPerPage": 5},
            headers=headers,
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        return [item["cve"]["id"] for item in data.get("vulnerabilities", [])[:5]]
    except (requests.RequestException, ValueError, KeyError) as e:
        log.warning("NVD lookup falhou para '%s': %s", service, e)
        return []

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

async def perform_scan(
    target: str,
    scan_type: str,
    concurrency: int = DEFAULT_CONCURRENCY,
    nvd_api_key: str = "",
) -> dict[int, dict]:
    """Executa varredura completa com análise de vulnerabilidades.

    ``concurrency`` limita sondas simultâneas (evita esgotar sockets no full scan).
    ``nvd_api_key`` (opcional) eleva o rate-limit da consulta de CVEs no NVD.
    """
    # aceita canônico "fast" e legados pt ("rápido"/"rapido"); resto = full range
    ports = TOP_PORTS if scan_type in ("fast", "rápido", "rapido") else range(1, 65536)
    open_ports = []
    results = {}
    sem = asyncio.Semaphore(max(1, concurrency))

    # Fase 1: Varredura de portas.
    # Privilégio é constante durante o scan: decide SYN vs connect uma vez.
    use_syn = os.geteuid() == 0 if os.name == 'posix' else is_admin_windows()

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

    # Fase 3: Analisar vulnerabilidades. Dedup por serviço: consulta o NVD
    # uma vez por serviço distinto (rate-limit caro) e reaproveita o resultado.
    vuln_cache: dict[str, list[str]] = {}
    for port in open_ports:
        service = banners[port].split()[0] if banners[port] else "unknown"
        if service not in vuln_cache:
            vuln_cache[service] = check_vulnerabilities(service, api_key=nvd_api_key)
        vulns = vuln_cache[service]

        # 'service' e 'risco' são tokens neutros (DATA); o display os localiza
        # via i18n (scan.service_unknown / scan.risk_high / scan.risk_low).
        results[port] = {
            'service': service,
            'banner': banners[port],
            'vulnerabilidades': vulns,
            'risco': "high" if vulns else "low"
        }

    return results
