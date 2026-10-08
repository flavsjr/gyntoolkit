#!/usr/bin/env python3
"""Varredura avançada: port scan (SYN/connect), banner, CVE lookup, host discovery."""

import asyncio
import contextlib
import ipaddress
import os

import requests
from colorama import Fore, Style
from scapy.all import ARP, IP, TCP, Ether, sr1, srp

from . import i18n
from .core import TOP_PORTS, is_admin_windows, log


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
    """Obtém banner do serviço"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=3
        )
        writer.write(b"GET / HTTP/1.1\r\n\r\n")
        banner = await asyncio.wait_for(reader.read(512), timeout=2)
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
        return (port, banner.decode(errors='ignore').strip())
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
        log.debug("banner %s:%s vazio: %s", target, port, e)
        return (port, "")

def check_vulnerabilities(service: str) -> list[str]:
    """Consulta NVD API 2.0 por CVEs associados ao serviço."""
    if not service or service.lower() in {"desconhecido", "unknown"}:
        return []
    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": service, "resultsPerPage": 5},
            headers={"User-Agent": "gyntoolkit/2.0"},
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

async def perform_scan(target: str, scan_type: str) -> dict[int, dict]:
    """Executa varredura completa com análise de vulnerabilidades"""
    # aceita canônico "fast" e legados pt ("rápido"/"rapido"); resto = full range
    ports = TOP_PORTS if scan_type in ("fast", "rápido", "rapido") else range(1, 65536)
    open_ports = []
    results = {}

    # Fase 1: Varredura de portas.
    # Privilégio é constante durante o scan: decide SYN vs connect uma vez.
    use_syn = os.geteuid() == 0 if os.name == 'posix' else is_admin_windows()
    tasks = [
        syn_scan(target, port) if use_syn else connect_scan(target, port)
        for port in ports
    ]

    # Processar resultados
    for future in asyncio.as_completed(tasks):
        port, is_open = await future
        if is_open:
            open_ports.append(port)

    # Fase 2: Obter banners
    banner_tasks = [get_banner(target, port) for port in open_ports]
    banners = {}
    for future in asyncio.as_completed(banner_tasks):
        port, banner = await future
        banners[port] = banner

    # Fase 3: Analisar vulnerabilidades
    for port in open_ports:
        service = banners[port].split()[0] if banners[port] else "unknown"
        vulns = check_vulnerabilities(service)

        # 'service' e 'risco' são tokens neutros (DATA); o display os localiza
        # via i18n (scan.service_unknown / scan.risk_high / scan.risk_low).
        results[port] = {
            'service': service,
            'banner': banners[port],
            'vulnerabilidades': vulns,
            'risco': "high" if vulns else "low"
        }

    return results
