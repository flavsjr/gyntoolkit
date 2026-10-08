#!/usr/bin/env python3
"""GynToolkit — canivete suíço de pentest (recon, scan, brute, utils).

Este ``__init__`` re-exporta a API pública para manter compatibilidade com
``import gyntoolkit as g`` (usado pelo lab E2E) e pelo entry point do pyproject.
"""

__version__ = "2.1.1"

from . import i18n, ui
from .brute import (
    cupp_generate,
    http_bruteforce,
    load_wordlist,
    print_ethical_warning,
    ssh_bruteforce,
)
from .cli import main_entry, main_flow
from .config import CONFIG, DEFAULTS, load_config
from .core import (
    LOGO,
    MAX_THREADS,
    PROJECT_ROOT,
    PROMPT,
    TOP_PORTS,
    clear_screen,
    is_admin_windows,
    log,
    sanitize_input,
    show_menu,
)
from .export import export_csv, export_html, export_json, export_md, save_report
from .recon import (
    DNS_TYPES,
    TECH_SIGNATURES,
    dns_lookup,
    escolher_tipo_dns,
    geo_ip,
    hibp_breaches,
    http_fingerprint,
    internetdb_lookup,
    mac_vendor,
    reverse_dns,
    shodan_host,
    ssl_inspect,
    subdomain_enum,
    traceroute,
    whois_lookup,
    zone_transfer,
)
from .scan import (
    check_vulnerabilities,
    connect_scan,
    get_banner,
    network_discovery,
    parse_service,
    perform_scan,
    syn_scan,
)
from .utils import b64_decode, b64_encode, hash_file, hash_text, jwt_decode
from .web import COMMON_PATHS, web_discovery
from .wordlist import generate_wordlist

__all__ = [
    "__version__",
    # core
    "LOGO", "PROMPT", "TOP_PORTS", "MAX_THREADS", "PROJECT_ROOT", "log",
    "clear_screen", "is_admin_windows", "sanitize_input", "show_menu",
    # scan
    "syn_scan", "connect_scan", "get_banner", "check_vulnerabilities",
    "parse_service", "network_discovery", "perform_scan",
    # recon
    "whois_lookup", "dns_lookup", "geo_ip", "reverse_dns", "subdomain_enum",
    "ssl_inspect", "http_fingerprint", "internetdb_lookup", "hibp_breaches",
    "mac_vendor", "traceroute", "zone_transfer", "shodan_host",
    "escolher_tipo_dns", "DNS_TYPES", "TECH_SIGNATURES",
    # web discovery
    "web_discovery", "COMMON_PATHS",
    # wordlist
    "generate_wordlist",
    # brute
    "print_ethical_warning", "load_wordlist", "cupp_generate",
    "ssh_bruteforce", "http_bruteforce",
    # utils
    "hash_text", "hash_file", "b64_encode", "b64_decode", "jwt_decode",
    # config / export / ui
    "CONFIG", "DEFAULTS", "load_config", "save_report",
    "export_json", "export_html", "export_csv", "export_md", "ui", "i18n",
    # cli
    "main_flow", "main_entry",
]
