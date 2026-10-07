#!/usr/bin/env python3
"""Recon passivo e ativo: WHOIS, DNS, geo, TLS, fingerprint, breaches, traceroute."""

import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

import dns.resolver
import requests
import whois
from colorama import Fore, Style
from scapy.all import IP, TCP, sr1

from .core import PROMPT, log, sanitize_input


def whois_lookup(domain: str):
    """Consulta informações WHOIS"""
    try:
        domain = sanitize_input(domain, r"[A-Za-z0-9.-]")
        return whois.whois(domain)
    except Exception as e:
        return f"Erro na consulta WHOIS: {str(e)}"

def dns_lookup(domain: str,
               record_type: str = "A",
               nameserver: str = None,
               timeout: int = 5) -> list[str]:
    """
    Consulta registros DNS de um domínio.
    :param domain: domínio a ser consultado
    :param record_type: tipo de registro (A, AAAA, MX, TXT, CNAME, NS, SOA, etc.)
    :param nameserver: servidor DNS (ex: "8.8.8.8"); None para usar o default
    :param timeout: tempo máximo de espera, em segundos
    :return: lista de strings com os dados retornados
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    if nameserver:
        resolver.nameservers = [nameserver]
    try:
        answers = resolver.resolve(domain, record_type)
        return [rdata.to_text() for rdata in answers]
    except dns.resolver.NoAnswer:
        return [f"No {record_type} record found for {domain}"]
    except dns.resolver.NXDOMAIN:
        return [f"Domain {domain} does not exist"]
    except Exception as e:
        return [f"Error: {e}"]

def geo_ip(target: str) -> dict[str, str]:
    """Geolocalização de IP/host via ip-api.com (free tier, sem key)."""
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        return {"erro": f"Falha ao resolver {target}: {e}"}

    fields = "status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting,query"
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": fields},
            headers={"User-Agent": "gyntoolkit/2.0"},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "success":
            return {"erro": data.get("message", "Consulta falhou")}
        return data
    except (requests.RequestException, ValueError) as e:
        log.warning("geo_ip %s falhou: %s", target, e)
        return {"erro": str(e)}


def reverse_dns(ip: str) -> dict[str, Any]:
    """PTR lookup via socket + dnspython fallback."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        try:
            ip = socket.gethostbyname(ip)
        except socket.gaierror as e:
            return {"erro": f"Falha ao resolver {ip}: {e}"}
    try:
        hostname, aliases, addrs = socket.gethostbyaddr(ip)
        return {"ip": ip, "hostname": hostname, "aliases": aliases, "addrs": addrs}
    except socket.herror as e:
        log.debug("reverse_dns %s falhou: %s", ip, e)
        return {"ip": ip, "erro": f"Sem PTR: {e}"}


def subdomain_enum(domain: str, timeout: int = 30) -> list[str]:
    """Enumeração de subdomínios via crt.sh Certificate Transparency."""
    try:
        response = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            headers={"User-Agent": "gyntoolkit/2.0"},
            timeout=timeout,
        )
        response.raise_for_status()
        entries = response.json()
    except (requests.RequestException, ValueError) as e:
        log.warning("crt.sh falhou para %s: %s", domain, e)
        return []

    subs = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lstrip("*.").lower()
            if name and name.endswith(domain.lower()):
                subs.add(name)
    return sorted(subs)


def _parse_cert_der(der: bytes) -> dict[str, Any]:
    """Parse cert DER usando cryptography (parseamento robusto sem depender de validação TLS)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as crypto_hashes

    cert = x509.load_der_x509_certificate(der)

    def _name_attr(name_obj, oid):
        try:
            attrs = name_obj.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else None
        except Exception:
            return None

    subject_cn = _name_attr(cert.subject, x509.NameOID.COMMON_NAME)
    subject_org = _name_attr(cert.subject, x509.NameOID.ORGANIZATION_NAME)
    issuer_cn = _name_attr(cert.issuer, x509.NameOID.COMMON_NAME)

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(n.value) for n in san_ext.value]
    except x509.ExtensionNotFound:
        pass

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    days_left = (not_after - datetime.now(timezone.utc)).days

    fingerprint = cert.fingerprint(crypto_hashes.SHA256()).hex()

    return {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "org": subject_org,
        "not_before": not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "dias_para_expirar": days_left,
        "sans": sans,
        "sha256": fingerprint,
        "serial": format(cert.serial_number, "x"),
        "signature_algo": cert.signature_algorithm_oid._name,
    }


def ssl_inspect(host: str, port: int = 443, timeout: int = 8) -> dict[str, Any]:
    """Inspeciona certificado SSL/TLS do alvo (aceita cert inválido, apenas inspeciona)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
            cipher = tls.cipher()
            version = tls.version()
    except (TimeoutError, socket.gaierror, ConnectionRefusedError, OSError, ssl.SSLError) as e:
        return {"erro": f"Falha SSL para {host}:{port}: {e}"}

    if not der:
        return {"erro": "Peer não enviou certificado"}

    try:
        parsed = _parse_cert_der(der)
    except Exception as e:
        log.warning("Falha ao parsear cert DER: %s", e)
        return {"erro": f"Falha ao parsear cert: {e}"}

    parsed.update({
        "host": host,
        "porta": port,
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
    })
    return parsed


TECH_SIGNATURES = [
    ("nginx", r"nginx"),
    ("Apache", r"Apache"),
    ("IIS", r"Microsoft-IIS"),
    ("Cloudflare", r"cloudflare"),
    ("PHP", r"PHP/"),
    ("Express", r"Express"),
    ("Django", r"csrftoken|Django"),
    ("Rails", r"_rails_|Phusion"),
    ("WordPress", r"wp-content|wp-includes"),
    ("Laravel", r"laravel_session"),
    ("ASP.NET", r"ASP\.NET|AspNet"),
    ("Node.js", r"X-Powered-By.*Express|Node"),
]


def http_fingerprint(url: str, timeout: int = 10) -> dict[str, Any]:
    """Detecta tecnologias via headers HTTP + cookies + body snippet."""
    try:
        response = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 gyntoolkit/2.0"},
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
    except requests.RequestException as e:
        return {"erro": f"Falha HTTP: {e}"}

    headers = dict(response.headers)
    body_snippet = response.text[:8192]
    haystack = "\n".join([f"{k}: {v}" for k, v in headers.items()]) + "\n" + body_snippet

    techs = [name for name, pattern in TECH_SIGNATURES if re.search(pattern, haystack, re.IGNORECASE)]

    return {
        "url": response.url,
        "status": response.status_code,
        "redirects": len(response.history),
        "server": headers.get("Server"),
        "x_powered_by": headers.get("X-Powered-By"),
        "content_type": headers.get("Content-Type"),
        "set_cookie": headers.get("Set-Cookie"),
        "hsts": headers.get("Strict-Transport-Security"),
        "csp": headers.get("Content-Security-Policy"),
        "xfo": headers.get("X-Frame-Options"),
        "tech": techs,
    }


def internetdb_lookup(ip: str, timeout: int = 10) -> dict[str, Any]:
    """Consulta InternetDB (Shodan free tier, sem key)."""
    try:
        socket.inet_aton(ip)
    except OSError:
        try:
            ip = socket.gethostbyname(ip)
        except socket.gaierror as e:
            return {"erro": f"Falha ao resolver: {e}"}
    try:
        response = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            headers={"User-Agent": "gyntoolkit/2.0"},
            timeout=timeout,
        )
        if response.status_code == 404:
            return {"ip": ip, "info": "Sem dados no InternetDB"}
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as e:
        log.warning("InternetDB %s falhou: %s", ip, e)
        return {"erro": str(e)}


def hibp_breaches(domain: str, timeout: int = 10) -> list[dict[str, Any]]:
    """Consulta HIBP breaches por domínio (endpoint público)."""
    try:
        response = requests.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            params={"domain": domain},
            headers={"User-Agent": "gyntoolkit-recon"},
            timeout=timeout,
        )
        if response.status_code == 404:
            return []
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as e:
        log.warning("HIBP falhou para %s: %s", domain, e)
        return [{"erro": str(e)}]


def mac_vendor(mac: str, timeout: int = 6) -> str:
    """Lookup fabricante via api.macvendors.com (free, no key)."""
    mac = mac.strip().replace("-", ":").upper()
    if not re.fullmatch(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
        return f"MAC inválido: {mac}"
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=timeout)
        if response.status_code == 200:
            return response.text.strip()
        return f"Não encontrado (HTTP {response.status_code})"
    except requests.RequestException as e:
        return f"Erro: {e}"


def traceroute(target: str, max_hops: int = 20, timeout: int = 3, dport: int = 80) -> list[dict[str, Any]]:
    """Traceroute TCP via scapy (requer privilégio)."""
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        return [{"erro": f"Falha ao resolver: {e}"}]

    hops = []
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target_ip, ttl=ttl) / TCP(dport=dport, flags="S")
        start = datetime.now(timezone.utc)
        try:
            reply = sr1(pkt, timeout=timeout, verbose=0)
        except PermissionError:
            return [{"erro": "traceroute requer privilégio root/admin"}]
        except OSError as e:
            return [{"erro": f"scapy: {e}"}]
        rtt_ms = (datetime.now(timezone.utc) - start).total_seconds() * 1000

        if reply is None:
            hops.append({"ttl": ttl, "ip": "*", "rtt_ms": None})
            continue

        hops.append({"ttl": ttl, "ip": reply.src, "rtt_ms": round(rtt_ms, 2)})
        if reply.haslayer(TCP) and reply.getlayer(TCP).flags & 0x12:
            break
        if reply.haslayer("ICMP") and reply.getlayer("ICMP").type == 3:
            break
    return hops


DNS_TYPES = [
    ("A",     "Endereço IPv4"),
    ("AAAA",  "Endereço IPv6"),
    ("MX",    "Servidores de e-mail"),
    ("NS",    "Servidores DNS autoritativos"),
    ("CNAME", "Apelido de outro domínio"),
    ("TXT",   "Registros de texto como SPF, DKIM, etc."),
    ("SOA",   "Informações administrativas do domínio")
]

def escolher_tipo_dns() -> str:
    """Mostra menu e retorna o tipo DNS escolhido"""
    print(f"\n{Fore.CYAN}Selecione o tipo de registro DNS:{Style.RESET_ALL}")
    for idx, (tipo, desc) in enumerate(DNS_TYPES, 1):
        print(f" {Fore.YELLOW}[{idx}]{Style.RESET_ALL} {tipo} → {desc}")
    print(f" {Fore.YELLOW}[0]{Style.RESET_ALL} Voltar")

    while True:
        try:
            choice = int(input(f"\n{PROMPT}"))
            if choice == 0:
                return None
            elif 1 <= choice <= len(DNS_TYPES):
                return DNS_TYPES[choice - 1][0]
            else:
                raise ValueError
        except ValueError:
            print(f"{Fore.RED}Escolha inválida. Tente novamente.{Style.RESET_ALL}")
