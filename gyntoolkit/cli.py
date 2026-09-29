#!/usr/bin/env python3
"""Fluxo interativo (menu) e ponto de entrada da CLI."""

import asyncio
import json
import os
import sys
from pathlib import Path

from colorama import Fore, Style

from . import ui
from .brute import (
    cupp_generate,
    http_bruteforce,
    load_wordlist,
    print_ethical_warning,
    ssh_bruteforce,
)
from .config import CONFIG
from .core import is_admin_windows, sanitize_input, show_menu
from .export import save_report
from .recon import (
    dns_lookup,
    escolher_tipo_dns,
    geo_ip,
    hibp_breaches,
    http_fingerprint,
    internetdb_lookup,
    mac_vendor,
    reverse_dns,
    ssl_inspect,
    subdomain_enum,
    traceroute,
    whois_lookup,
)
from .scan import network_discovery, perform_scan
from .utils import b64_decode, b64_encode, hash_file, hash_text, jwt_decode


def _pause() -> None:
    input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")


def _offer_export(data, basename: str, title: str) -> None:
    """Oferece salvar ``data`` em JSON/HTML conforme config. No-op se vazio."""
    if not data:
        return
    cfg = CONFIG["export"]
    if cfg.get("auto"):
        fmt = cfg.get("format", "json")
    else:
        ans = input(
            f"{Fore.CYAN}Exportar resultado? [json/html/N]: {Style.RESET_ALL}"
        ).strip().lower()
        if ans not in ("json", "html"):
            return
        fmt = ans
    try:
        path = save_report(data, basename, fmt=fmt, out_dir=cfg.get("dir", "reports"), title=title)
        ui.success(f"Relatório salvo: {path}")
    except OSError as e:
        ui.error(f"Falha ao exportar: {e}")


async def main_flow():
    while True:
        choice = show_menu("Menu Principal:", [
            "Obter Informações",
            "Brute Force",
            "Varredura Avançada",
            "Utilitários"
        ])

        if choice == 0:
            print(f"\n{Fore.MAGENTA}Saindo...{Style.RESET_ALL}")
            sys.exit()

        elif choice == 1:  # Obter Informações
            sub_choice = show_menu("Obter Informações:", [
                "Consulta WHOIS",
                "DNS Lookup",
                "Geolocalização IP",
                "Reverse DNS (PTR)",
                "Subdomain Enum (crt.sh)",
                "SSL/TLS Cert Inspector",
                "HTTP Fingerprint",
                "InternetDB (Shodan free)",
                "HIBP Breach Check",
                "MAC Vendor Lookup",
                "Traceroute (TCP)",
            ])

            if sub_choice == 1:
                domain = input(f"\n{Fore.CYAN}Digite o domínio: {Style.RESET_ALL}")
                with ui.status(f"Consultando WHOIS de {domain}..."):
                    result = whois_lookup(domain)
                print(f"\n{Fore.GREEN}Resultado:{Style.RESET_ALL}")
                print(result)
                if not isinstance(result, str) or not result.startswith("Erro"):
                    _offer_export({"domain": domain, "whois": str(result)},
                                  f"whois-{domain}", f"WHOIS {domain}")

            elif sub_choice == 2:
                domain = sanitize_input(
                    input(f"\n{Fore.CYAN}Digite o domínio: {Style.RESET_ALL}"),
                    r"[A-Za-z0-9.-]",
                )

                rtype = escolher_tipo_dns()
                if not rtype:
                    continue

                ns = input(f"{Fore.CYAN}Servidor DNS (ENTER para default): {Style.RESET_ALL}") or None

                with ui.status(f"Consultando registro {rtype} para {domain}..."):
                    records = dns_lookup(domain, rtype.upper(), ns)
                ui.print_list(f"Registros {rtype} de {domain}", records)
                _offer_export({"domain": domain, "type": rtype, "records": records},
                              f"dns-{domain}-{rtype}", f"DNS {rtype} {domain}")

            elif sub_choice == 3:
                target = sanitize_input(
                    input(f"\n{Fore.CYAN}IP ou domínio: {Style.RESET_ALL}"),
                    r"[A-Za-z0-9.:-]",
                )
                with ui.status(f"Consultando geolocalização de {target}..."):
                    info = geo_ip(target)
                if "erro" in info:
                    ui.error(info["erro"])
                else:
                    label_map = {
                        "query": "IP", "country": "País", "regionName": "Região",
                        "city": "Cidade", "zip": "CEP", "lat": "Latitude", "lon": "Longitude",
                        "timezone": "Fuso", "isp": "ISP", "org": "Organização", "as": "ASN",
                        "reverse": "Reverse DNS", "mobile": "Mobile", "proxy": "Proxy",
                        "hosting": "Hosting",
                    }
                    shown = {label: info[key] for key, label in label_map.items() if key in info}
                    ui.print_kv(f"Geolocalização de {target}", shown)
                    _offer_export(info, f"geoip-{target}", f"Geo IP {target}")

            elif sub_choice == 4:
                target = sanitize_input(input(f"\n{Fore.CYAN}IP ou domínio: {Style.RESET_ALL}"), r"[A-Za-z0-9.:-]")
                with ui.status(f"Reverse DNS de {target}..."):
                    r = reverse_dns(target)
                ui.print_kv(f"Reverse DNS de {target}", r)
                _offer_export(r, f"revdns-{target}", f"Reverse DNS {target}")

            elif sub_choice == 5:
                domain = sanitize_input(input(f"\n{Fore.CYAN}Domínio raiz: {Style.RESET_ALL}"), r"[A-Za-z0-9.-]")
                with ui.status("Enumerando subdomínios via crt.sh (pode demorar)..."):
                    subs = subdomain_enum(domain, timeout=CONFIG["recon"]["subdomain_timeout"])
                if not subs:
                    ui.error("Nenhum subdomínio encontrado.")
                else:
                    ui.print_list(f"Subdomínios de {domain} (total: {len(subs)})", subs)
                    _offer_export({"domain": domain, "total": len(subs), "subdomains": subs},
                                  f"subdomains-{domain}", f"Subdomínios {domain}")

            elif sub_choice == 6:
                host = sanitize_input(input(f"\n{Fore.CYAN}Host: {Style.RESET_ALL}"), r"[A-Za-z0-9.-]")
                port = int(input(f"{Fore.CYAN}Porta [443]: {Style.RESET_ALL}") or 443)
                with ui.status(f"Inspecionando cert TLS de {host}:{port}..."):
                    info = ssl_inspect(host, port, timeout=CONFIG["recon"]["ssl_timeout"])
                if "erro" in info:
                    ui.error(info["erro"])
                else:
                    ui.print_kv(
                        f"Certificado TLS de {host}:{port}", info,
                        warn_keys={"dias_para_expirar": lambda v: isinstance(v, int) and v < 30},
                    )
                    _offer_export(info, f"ssl-{host}", f"SSL {host}:{port}")

            elif sub_choice == 7:
                url = input(f"\n{Fore.CYAN}URL (com http/https): {Style.RESET_ALL}").strip()
                with ui.status(f"Fingerprinting {url}..."):
                    info = http_fingerprint(url, timeout=CONFIG["recon"]["http_timeout"])
                if "erro" in info:
                    ui.error(info["erro"])
                else:
                    ui.print_kv(f"HTTP Fingerprint de {url}", info)
                    _offer_export(info, f"httpfp-{url}", f"HTTP Fingerprint {url}")

            elif sub_choice == 8:
                target = sanitize_input(input(f"\n{Fore.CYAN}IP ou domínio: {Style.RESET_ALL}"), r"[A-Za-z0-9.:-]")
                with ui.status("Consultando InternetDB (Shodan free)..."):
                    info = internetdb_lookup(target)
                if "erro" in info:
                    ui.error(info["erro"])
                elif "info" in info:
                    ui.notice(info["info"])
                else:
                    shown = {
                        "IP": info.get("ip"),
                        "Hostnames": info.get("hostnames", []),
                        "Portas abertas": info.get("ports", []),
                        "Tags": info.get("tags", []),
                        "CPEs": info.get("cpes", [])[:10],
                        "CVEs": info.get("vulns", [])[:15],
                    }
                    ui.print_kv(f"InternetDB de {target}", shown)
                    _offer_export(info, f"internetdb-{target}", f"InternetDB {target}")

            elif sub_choice == 9:
                domain = sanitize_input(input(f"\n{Fore.CYAN}Domínio: {Style.RESET_ALL}"), r"[A-Za-z0-9.-]")
                with ui.status(f"Consultando HIBP breaches para {domain}..."):
                    breaches = hibp_breaches(domain)
                if not breaches:
                    ui.success(f"Nenhum breach conhecido para {domain}.")
                elif breaches and "erro" in breaches[0]:
                    ui.error(breaches[0]["erro"])
                else:
                    rows = [
                        (b.get("Name"), b.get("BreachDate"), b.get("PwnCount"),
                         ", ".join(b.get("DataClasses", [])))
                        for b in breaches
                    ]
                    ui.print_table(f"Breaches de {domain}",
                                   ["Nome", "Data", "Contas", "Classes"], rows)
                    _offer_export(breaches, f"hibp-{domain}", f"HIBP {domain}")

            elif sub_choice == 10:
                mac = input(f"\n{Fore.CYAN}MAC (ex: 00:1A:2B:3C:4D:5E): {Style.RESET_ALL}").strip()
                with ui.status("Consultando fabricante..."):
                    vendor = mac_vendor(mac)
                ui.print_kv("MAC Vendor", {"MAC": mac, "Fabricante": vendor})

            elif sub_choice == 11:
                target = sanitize_input(input(f"\n{Fore.CYAN}Alvo: {Style.RESET_ALL}"), r"[A-Za-z0-9.-]")
                max_hops = int(input(f"{Fore.CYAN}Max hops [{CONFIG['recon']['traceroute_max_hops']}]: {Style.RESET_ALL}")
                               or CONFIG["recon"]["traceroute_max_hops"])
                dport = int(input(f"{Fore.CYAN}Porta TCP destino [{CONFIG['recon']['traceroute_dport']}]: {Style.RESET_ALL}")
                            or CONFIG["recon"]["traceroute_dport"])
                with ui.status(f"Traceroute TCP para {target}:{dport}..."):
                    hops = traceroute(target, max_hops=max_hops, dport=dport)
                if hops and "erro" in hops[0]:
                    ui.error(hops[0]["erro"])
                else:
                    rows = [(h["ttl"], h["ip"], f"{h['rtt_ms']} ms" if h["rtt_ms"] is not None else "*")
                            for h in hops]
                    ui.print_table(f"Traceroute {target}:{dport}", ["TTL", "IP", "RTT"], rows)
                    _offer_export({"target": target, "dport": dport, "hops": hops},
                                  f"traceroute-{target}", f"Traceroute {target}")

        elif choice == 2:  # Brute Force
            b = CONFIG["brute"]
            sub_choice = show_menu("Brute Force:", [
                "Gerar Wordlist (CUPP)",
                "Ataque SSH",
                "Ataque HTTP"
            ])

            if sub_choice == 1:
                cupp_generate()

            elif sub_choice == 2:
                if not print_ethical_warning("Brute-force SSH"):
                    ui.error("Autorização não confirmada. Abortando.")
                    _pause()
                    continue
                host = sanitize_input(input(f"\n{Fore.CYAN}Host alvo: {Style.RESET_ALL}"))
                port = int(input(f"{Fore.CYAN}Porta [22]: {Style.RESET_ALL}") or 22)
                user_default = f" [{b['users_wordlist']}]" if b["users_wordlist"] else ""
                user_input = (input(f"{Fore.CYAN}Usuário único ou path de wordlist de usuários{user_default}: {Style.RESET_ALL}").strip()
                              or b["users_wordlist"])
                users = load_wordlist(user_input) if Path(user_input).is_file() else [user_input]
                pass_default = f" [{b['passwords_wordlist']}]" if b["passwords_wordlist"] else ""
                pass_path = (input(f"{Fore.CYAN}Path da wordlist de senhas{pass_default}: {Style.RESET_ALL}").strip()
                             or b["passwords_wordlist"])
                passwords = load_wordlist(pass_path)
                if not users or not users[0] or not passwords:
                    ui.error("Wordlist vazia. Abortando.")
                    _pause()
                    continue
                workers = int(input(f"{Fore.CYAN}Workers concorrentes [{b['ssh_workers']}]: {Style.RESET_ALL}") or b["ssh_workers"])
                ui.notice(f"Iniciando SSH brute em {host}:{port} ({len(users)}x{len(passwords)} = {len(users)*len(passwords)} combos)...")
                results = await ssh_bruteforce(host, users, passwords, port=port, workers=workers,
                                               delay=b["delay"], timeout=b["ssh_timeout"])
                if results:
                    ui.print_table("Credenciais encontradas", ["Usuário", "Senha"], results)
                else:
                    ui.error("Nenhuma credencial válida encontrada.")

            elif sub_choice == 3:
                if not print_ethical_warning("Brute-force HTTP"):
                    ui.error("Autorização não confirmada. Abortando.")
                    _pause()
                    continue
                url = input(f"\n{Fore.CYAN}URL alvo (com http/https): {Style.RESET_ALL}").strip()
                mode = (input(f"{Fore.CYAN}Modo [basic/form] (default basic): {Style.RESET_ALL}").strip().lower() or "basic")
                user_field = pass_field = fail_sig = ""
                if mode == "form":
                    user_field = input(f"{Fore.CYAN}Nome do campo usuário [username]: {Style.RESET_ALL}").strip() or "username"
                    pass_field = input(f"{Fore.CYAN}Nome do campo senha [password]: {Style.RESET_ALL}").strip() or "password"
                    fail_sig = input(f"{Fore.CYAN}Trecho de texto que indica falha (ex: 'Invalid'): {Style.RESET_ALL}").strip()
                user_default = f" [{b['users_wordlist']}]" if b["users_wordlist"] else ""
                user_input = (input(f"{Fore.CYAN}Usuário único ou path de wordlist{user_default}: {Style.RESET_ALL}").strip()
                              or b["users_wordlist"])
                users = load_wordlist(user_input) if Path(user_input).is_file() else [user_input]
                pass_default = f" [{b['passwords_wordlist']}]" if b["passwords_wordlist"] else ""
                pass_path = (input(f"{Fore.CYAN}Path da wordlist de senhas{pass_default}: {Style.RESET_ALL}").strip()
                             or b["passwords_wordlist"])
                passwords = load_wordlist(pass_path)
                if not users or not users[0] or not passwords:
                    ui.error("Wordlist vazia. Abortando.")
                    _pause()
                    continue
                workers = int(input(f"{Fore.CYAN}Workers concorrentes [{b['http_workers']}]: {Style.RESET_ALL}") or b["http_workers"])
                ui.notice(f"Iniciando HTTP brute em {url} ({len(users)*len(passwords)} combos)...")
                results = await http_bruteforce(
                    url, users, passwords, mode=mode,
                    user_field=user_field, pass_field=pass_field,
                    fail_signature=fail_sig, workers=workers,
                    delay=b["delay"], timeout=b["http_timeout"],
                )
                if results:
                    ui.print_table("Credenciais encontradas", ["Usuário", "Senha"], results)
                else:
                    ui.error("Nenhuma credencial válida encontrada.")

        elif choice == 3:  # Varredura Avançada
            default_type = CONFIG["scan"]["default_type"]
            target = sanitize_input(input(f"\n{Fore.CYAN}Alvo (IP/rede): {Style.RESET_ALL}"))
            scan_type = input(f"Tipo de varredura [rápido/completo] (default {default_type}): ").lower().strip() or default_type

            if '/' in target:
                with ui.status("Descobrindo hosts ativos..."):
                    hosts = network_discovery(target)
                if not hosts:
                    ui.error("Nenhum host respondeu.")
                    _pause()
                    continue
                ui.print_list(f"Hosts encontrados: {len(hosts)}", [f"{i}. {h}" for i, h in enumerate(hosts, 1)])
                selection = input("Selecione o host (ENTER para todos): ").strip()
                if selection:
                    try:
                        targets = [hosts[int(selection) - 1]]
                    except (ValueError, IndexError):
                        ui.error("Seleção inválida.")
                        continue
                else:
                    targets = hosts
            else:
                targets = [target]

            report = {}
            for host in targets:
                with ui.status(f"Escaneando {host}..."):
                    results = await perform_scan(host, scan_type)
                report[host] = results
                rows = [
                    (port, data["service"], data["risco"], (data["banner"] or "")[:60],
                     ", ".join(data["vulnerabilidades"]) or "—")
                    for port, data in results.items()
                ]
                row_styles = ["red" if data["risco"] == "Alto" else "green" for data in results.values()]
                if rows:
                    ui.print_table(f"Resultados para {host}",
                                   ["Porta", "Serviço", "Risco", "Banner", "CVEs"],
                                   rows, row_styles=row_styles)
                else:
                    ui.notice(f"Nenhuma porta aberta em {host}.")
            _offer_export(report, f"scan-{targets[0]}", f"Scan {', '.join(targets)}")

        elif choice == 4:  # Utilitários
            sub_choice = show_menu("Utilitários:", [
                "Hash de texto (MD5/SHA1/SHA256/SHA512)",
                "Hash de arquivo",
                "Base64 encode",
                "Base64 decode",
                "JWT decode (sem verificar assinatura)",
            ])

            if sub_choice == 1:
                text = input(f"\n{Fore.CYAN}Texto: {Style.RESET_ALL}")
                algo = (input(f"{Fore.CYAN}Algoritmo [sha256]: {Style.RESET_ALL}").strip().lower() or "sha256")
                try:
                    ui.print_kv("Hash", {algo: hash_text(text, algo)})
                except ValueError as e:
                    ui.error(f"Algoritmo inválido: {e}")

            elif sub_choice == 2:
                path = input(f"\n{Fore.CYAN}Path do arquivo: {Style.RESET_ALL}").strip()
                algo = (input(f"{Fore.CYAN}Algoritmo [sha256]: {Style.RESET_ALL}").strip().lower() or "sha256")
                try:
                    ui.print_kv("Hash de arquivo", {algo: hash_file(path, algo)})
                except ValueError as e:
                    ui.error(f"Algoritmo inválido: {e}")

            elif sub_choice == 3:
                text = input(f"\n{Fore.CYAN}Texto: {Style.RESET_ALL}")
                ui.print_kv("Base64 encode", {"b64": b64_encode(text)})

            elif sub_choice == 4:
                text = input(f"\n{Fore.CYAN}Base64: {Style.RESET_ALL}")
                ui.print_kv("Base64 decode", {"decoded": b64_decode(text)})

            elif sub_choice == 5:
                token = input(f"\n{Fore.CYAN}JWT: {Style.RESET_ALL}").strip()
                r = jwt_decode(token)
                if "erro" in r:
                    ui.error(r["erro"])
                else:
                    print(f"\n {Fore.YELLOW}header:{Style.RESET_ALL} {json.dumps(r['header'], indent=2)}")
                    print(f" {Fore.YELLOW}payload:{Style.RESET_ALL} {json.dumps(r['payload'], indent=2)}")
                    print(f" {Fore.YELLOW}signature:{Style.RESET_ALL} {r['signature']}")

        _pause()


def main_entry() -> None:
    """Entry point CLI (usado por pyproject scripts)."""
    try:
        if os.name == 'posix' and os.geteuid() != 0:
            print(f"\n{Fore.RED}Aviso: Funcionalidades avançadas requerem root!{Style.RESET_ALL}")
        elif os.name == 'nt' and not is_admin_windows():
            print(f"\n{Fore.RED}Aviso: Funcionalidades avançadas requerem administrador!{Style.RESET_ALL}")

        asyncio.run(main_flow())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Scan interrompido pelo usuário.{Style.RESET_ALL}")
        sys.exit(1)
