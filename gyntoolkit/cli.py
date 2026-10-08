#!/usr/bin/env python3
"""Fluxo interativo (menu) e ponto de entrada da CLI."""

import asyncio
import json
import os
import sys
from pathlib import Path

from colorama import Fore, Style

from . import i18n, ui
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

# Valores canônicos de scan_type (DATA, usados por perform_scan). Neutros de
# idioma; entradas localizadas (en/pt) são mapeadas por _normalize_scan_type.
_FAST = "fast"
_FULL = "full"


def _cyan(key: str, **kw) -> str:
    """Prompt ciano traduzido para input()."""
    return f"\n{Fore.CYAN}{i18n.t(key, **kw)}{Style.RESET_ALL}"


def _pause() -> None:
    input(f"\n{Fore.YELLOW}{i18n.t('common.press_enter')}{Style.RESET_ALL}")


def _normalize_scan_type(raw: str, default: str) -> str:
    raw = (raw or "").strip().lower() or default
    # aceita canônico "fast", localizados pt ("rápido"/"rapido") e abreviações
    return _FAST if raw in (_FAST, "rápido", "rapido", "f", "r") else _FULL


def _scan_risk_label(risco: str) -> str:
    return i18n.t("scan.risk_high") if risco == "high" else i18n.t("scan.risk_low")


def _scan_service_label(service: str) -> str:
    return i18n.t("scan.service_unknown") if service == "unknown" else service


def _offer_export(data, basename: str, title: str) -> None:
    """Oferece salvar ``data`` em JSON/HTML conforme config. No-op se vazio."""
    if not data:
        return
    cfg = CONFIG["export"]
    if cfg.get("auto"):
        fmt = cfg.get("format", "json")
    else:
        ans = input(
            f"{Fore.CYAN}{i18n.t('msg.export_prompt')}{Style.RESET_ALL}"
        ).strip().lower()
        if ans not in ("json", "html"):
            return
        fmt = ans
    try:
        path = save_report(data, basename, fmt=fmt, out_dir=cfg.get("dir", "reports"), title=title)
        ui.success(i18n.t("msg.report_saved", path=path))
    except OSError as e:
        ui.error(i18n.t("msg.export_fail", err=e))


async def main_flow():
    while True:
        choice = show_menu(i18n.t("menu.main.title"), [
            i18n.t("menu.main.info"),
            i18n.t("menu.main.brute"),
            i18n.t("menu.main.scan"),
            i18n.t("menu.main.utils"),
        ])

        if choice == 0:
            print(f"\n{Fore.MAGENTA}{i18n.t('common.exiting')}{Style.RESET_ALL}")
            sys.exit()

        elif choice == 1:  # Obter Informações
            sub_choice = show_menu(i18n.t("menu.info.title"), [
                i18n.t("menu.info.whois"),
                i18n.t("menu.info.dns"),
                i18n.t("menu.info.geo"),
                i18n.t("menu.info.revdns"),
                i18n.t("menu.info.subenum"),
                i18n.t("menu.info.ssl"),
                i18n.t("menu.info.httpfp"),
                i18n.t("menu.info.internetdb"),
                i18n.t("menu.info.hibp"),
                i18n.t("menu.info.macvendor"),
                i18n.t("menu.info.traceroute"),
            ])

            if sub_choice == 1:
                domain = input(_cyan("prompt.domain"))
                with ui.status(i18n.t("status.whois", d=domain)):
                    result = whois_lookup(domain)
                print(f"\n{Fore.GREEN}{i18n.t('label.result')}{Style.RESET_ALL}")
                print(result)
                if not isinstance(result, str):
                    _offer_export({"domain": domain, "whois": str(result)},
                                  f"whois-{domain}", f"WHOIS {domain}")

            elif sub_choice == 2:
                domain = sanitize_input(input(_cyan("prompt.domain")), r"[A-Za-z0-9.-]")

                rtype = escolher_tipo_dns()
                if not rtype:
                    continue

                ns = input(f"{Fore.CYAN}{i18n.t('prompt.dns_server')}{Style.RESET_ALL}") or None

                with ui.status(i18n.t("status.dns", t=rtype, d=domain)):
                    records = dns_lookup(domain, rtype.upper(), ns)
                ui.print_list(i18n.t("label.dns_records", t=rtype, d=domain), records)
                _offer_export({"domain": domain, "type": rtype, "records": records},
                              f"dns-{domain}-{rtype}", f"DNS {rtype} {domain}")

            elif sub_choice == 3:
                target = sanitize_input(input(_cyan("prompt.ip_or_domain")), r"[A-Za-z0-9.:-]")
                with ui.status(i18n.t("status.geo", t=target)):
                    info = geo_ip(target)
                if "erro" in info:
                    ui.error(info["erro"])
                else:
                    label_map = {
                        "query": i18n.t("geo.ip"), "country": i18n.t("geo.country"),
                        "regionName": i18n.t("geo.region"), "city": i18n.t("geo.city"),
                        "zip": i18n.t("geo.zip"), "lat": i18n.t("geo.lat"),
                        "lon": i18n.t("geo.lon"), "timezone": i18n.t("geo.timezone"),
                        "isp": i18n.t("geo.isp"), "org": i18n.t("geo.org"),
                        "as": i18n.t("geo.as"), "reverse": i18n.t("geo.reverse"),
                        "mobile": i18n.t("geo.mobile"), "proxy": i18n.t("geo.proxy"),
                        "hosting": i18n.t("geo.hosting"),
                    }
                    shown = {label: info[key] for key, label in label_map.items() if key in info}
                    ui.print_kv(i18n.t("label.geo", t=target), shown)
                    _offer_export(info, f"geoip-{target}", f"Geo IP {target}")

            elif sub_choice == 4:
                target = sanitize_input(input(_cyan("prompt.ip_or_domain")), r"[A-Za-z0-9.:-]")
                with ui.status(i18n.t("status.revdns", t=target)):
                    r = reverse_dns(target)
                ui.print_kv(i18n.t("label.revdns", t=target), r)
                _offer_export(r, f"revdns-{target}", f"Reverse DNS {target}")

            elif sub_choice == 5:
                domain = sanitize_input(input(_cyan("prompt.root_domain")), r"[A-Za-z0-9.-]")
                with ui.status(i18n.t("status.subenum")):
                    subs = subdomain_enum(domain, timeout=CONFIG["recon"]["subdomain_timeout"])
                if not subs:
                    ui.error(i18n.t("msg.no_subdomains"))
                else:
                    ui.print_list(i18n.t("label.subdomains", d=domain, n=len(subs)), subs)
                    _offer_export({"domain": domain, "total": len(subs), "subdomains": subs},
                                  f"subdomains-{domain}", f"Subdomínios {domain}")

            elif sub_choice == 6:
                host = sanitize_input(input(_cyan("prompt.host")), r"[A-Za-z0-9.-]")
                port = int(input(f"{Fore.CYAN}{i18n.t('prompt.port_443')}{Style.RESET_ALL}") or 443)
                with ui.status(i18n.t("status.ssl", h=host, p=port)):
                    info = ssl_inspect(host, port, timeout=CONFIG["recon"]["ssl_timeout"])
                if "erro" in info:
                    ui.error(info["erro"])
                else:
                    ui.print_kv(
                        i18n.t("label.ssl", h=host, p=port), info,
                        warn_keys={"dias_para_expirar": lambda v: isinstance(v, int) and v < 30},
                    )
                    _offer_export(info, f"ssl-{host}", f"SSL {host}:{port}")

            elif sub_choice == 7:
                url = input(f"\n{Fore.CYAN}{i18n.t('prompt.url_http')}{Style.RESET_ALL}").strip()
                with ui.status(i18n.t("status.httpfp", u=url)):
                    info = http_fingerprint(url, timeout=CONFIG["recon"]["http_timeout"])
                if "erro" in info:
                    ui.error(info["erro"])
                else:
                    ui.print_kv(i18n.t("label.httpfp", u=url), info)
                    _offer_export(info, f"httpfp-{url}", f"HTTP Fingerprint {url}")

            elif sub_choice == 8:
                target = sanitize_input(input(_cyan("prompt.ip_or_domain")), r"[A-Za-z0-9.:-]")
                with ui.status(i18n.t("status.internetdb")):
                    info = internetdb_lookup(target)
                if "erro" in info:
                    ui.error(info["erro"])
                elif "info" in info:
                    ui.notice(info["info"])
                else:
                    shown = {
                        i18n.t("idb.ip"): info.get("ip"),
                        i18n.t("idb.hostnames"): info.get("hostnames", []),
                        i18n.t("idb.ports"): info.get("ports", []),
                        i18n.t("idb.tags"): info.get("tags", []),
                        i18n.t("idb.cpes"): info.get("cpes", [])[:10],
                        i18n.t("idb.cves"): info.get("vulns", [])[:15],
                    }
                    ui.print_kv(i18n.t("label.internetdb", t=target), shown)
                    _offer_export(info, f"internetdb-{target}", f"InternetDB {target}")

            elif sub_choice == 9:
                domain = sanitize_input(input(_cyan("prompt.domain_simple")), r"[A-Za-z0-9.-]")
                with ui.status(i18n.t("status.hibp", d=domain)):
                    breaches = hibp_breaches(domain)
                if not breaches:
                    ui.success(i18n.t("msg.no_breaches", d=domain))
                elif breaches and "erro" in breaches[0]:
                    ui.error(breaches[0]["erro"])
                else:
                    rows = [
                        (b.get("Name"), b.get("BreachDate"), b.get("PwnCount"),
                         ", ".join(b.get("DataClasses", [])))
                        for b in breaches
                    ]
                    ui.print_table(i18n.t("label.breaches", d=domain),
                                   i18n.t("table.breaches").split("|"), rows)
                    _offer_export(breaches, f"hibp-{domain}", f"HIBP {domain}")

            elif sub_choice == 10:
                mac = input(f"\n{Fore.CYAN}{i18n.t('prompt.mac')}{Style.RESET_ALL}").strip()
                with ui.status(i18n.t("status.macvendor")):
                    vendor = mac_vendor(mac)
                ui.print_kv(i18n.t("label.macvendor"),
                            {i18n.t("kv.mac"): mac, i18n.t("kv.vendor"): vendor})

            elif sub_choice == 11:
                target = sanitize_input(input(_cyan("prompt.target")), r"[A-Za-z0-9.-]")
                max_hops = int(input(f"{Fore.CYAN}{i18n.t('prompt.max_hops', n=CONFIG['recon']['traceroute_max_hops'])}{Style.RESET_ALL}")
                               or CONFIG["recon"]["traceroute_max_hops"])
                dport = int(input(f"{Fore.CYAN}{i18n.t('prompt.dest_port', n=CONFIG['recon']['traceroute_dport'])}{Style.RESET_ALL}")
                            or CONFIG["recon"]["traceroute_dport"])
                with ui.status(i18n.t("status.traceroute", t=target, p=dport)):
                    hops = traceroute(target, max_hops=max_hops, dport=dport)
                if hops and "erro" in hops[0]:
                    ui.error(hops[0]["erro"])
                else:
                    rows = [(h["ttl"], h["ip"], f"{h['rtt_ms']} ms" if h["rtt_ms"] is not None else "*")
                            for h in hops]
                    ui.print_table(i18n.t("label.traceroute", t=target, p=dport),
                                   i18n.t("table.traceroute").split("|"), rows)
                    _offer_export({"target": target, "dport": dport, "hops": hops},
                                  f"traceroute-{target}", f"Traceroute {target}")

        elif choice == 2:  # Brute Force
            b = CONFIG["brute"]
            sub_choice = show_menu(i18n.t("menu.brute.title"), [
                i18n.t("menu.brute.cupp"),
                i18n.t("menu.brute.ssh"),
                i18n.t("menu.brute.http"),
            ])

            if sub_choice == 1:
                cupp_generate()

            elif sub_choice == 2:
                if not print_ethical_warning("Brute-force SSH"):
                    ui.error(i18n.t("msg.auth_not_confirmed"))
                    _pause()
                    continue
                host = sanitize_input(input(_cyan("prompt.target_host")))
                port = int(input(f"{Fore.CYAN}{i18n.t('prompt.port_22')}{Style.RESET_ALL}") or 22)
                user_default = f" [{b['users_wordlist']}]" if b["users_wordlist"] else ""
                user_input = (input(f"{Fore.CYAN}{i18n.t('prompt.user_or_users_wl', default=user_default)}{Style.RESET_ALL}").strip()
                              or b["users_wordlist"])
                users = load_wordlist(user_input) if Path(user_input).is_file() else [user_input]
                pass_default = f" [{b['passwords_wordlist']}]" if b["passwords_wordlist"] else ""
                pass_path = (input(f"{Fore.CYAN}{i18n.t('prompt.pass_wl', default=pass_default)}{Style.RESET_ALL}").strip()
                             or b["passwords_wordlist"])
                passwords = load_wordlist(pass_path)
                if not users or not users[0] or not passwords:
                    ui.error(i18n.t("msg.empty_wordlist"))
                    _pause()
                    continue
                workers = int(input(f"{Fore.CYAN}{i18n.t('prompt.workers', n=b['ssh_workers'])}{Style.RESET_ALL}") or b["ssh_workers"])
                ui.notice(i18n.t("msg.ssh_start", h=host, p=port, u=len(users), pw=len(passwords), c=len(users)*len(passwords)))
                results = await ssh_bruteforce(host, users, passwords, port=port, workers=workers,
                                               delay=b["delay"], timeout=b["ssh_timeout"])
                if results:
                    ui.print_table(i18n.t("label.creds_found"), i18n.t("table.creds").split("|"), results)
                else:
                    ui.error(i18n.t("msg.no_valid_creds"))

            elif sub_choice == 3:
                if not print_ethical_warning("Brute-force HTTP"):
                    ui.error(i18n.t("msg.auth_not_confirmed"))
                    _pause()
                    continue
                url = input(f"\n{Fore.CYAN}{i18n.t('prompt.url_target')}{Style.RESET_ALL}").strip()
                mode = (input(f"{Fore.CYAN}{i18n.t('prompt.mode')}{Style.RESET_ALL}").strip().lower() or "basic")
                user_field = pass_field = fail_sig = ""
                if mode == "form":
                    user_field = input(f"{Fore.CYAN}{i18n.t('prompt.user_field')}{Style.RESET_ALL}").strip() or "username"
                    pass_field = input(f"{Fore.CYAN}{i18n.t('prompt.pass_field')}{Style.RESET_ALL}").strip() or "password"
                    fail_sig = input(f"{Fore.CYAN}{i18n.t('prompt.fail_sig')}{Style.RESET_ALL}").strip()
                user_default = f" [{b['users_wordlist']}]" if b["users_wordlist"] else ""
                user_input = (input(f"{Fore.CYAN}{i18n.t('prompt.user_or_wl', default=user_default)}{Style.RESET_ALL}").strip()
                              or b["users_wordlist"])
                users = load_wordlist(user_input) if Path(user_input).is_file() else [user_input]
                pass_default = f" [{b['passwords_wordlist']}]" if b["passwords_wordlist"] else ""
                pass_path = (input(f"{Fore.CYAN}{i18n.t('prompt.pass_wl', default=pass_default)}{Style.RESET_ALL}").strip()
                             or b["passwords_wordlist"])
                passwords = load_wordlist(pass_path)
                if not users or not users[0] or not passwords:
                    ui.error(i18n.t("msg.empty_wordlist"))
                    _pause()
                    continue
                workers = int(input(f"{Fore.CYAN}{i18n.t('prompt.workers', n=b['http_workers'])}{Style.RESET_ALL}") or b["http_workers"])
                ui.notice(i18n.t("msg.http_start", u=url, c=len(users)*len(passwords)))
                results = await http_bruteforce(
                    url, users, passwords, mode=mode,
                    user_field=user_field, pass_field=pass_field,
                    fail_signature=fail_sig, workers=workers,
                    delay=b["delay"], timeout=b["http_timeout"],
                )
                if results:
                    ui.print_table(i18n.t("label.creds_found"), i18n.t("table.creds").split("|"), results)
                else:
                    ui.error(i18n.t("msg.no_valid_creds"))

        elif choice == 3:  # Varredura Avançada
            default_type = CONFIG["scan"]["default_type"]
            target = sanitize_input(input(_cyan("prompt.target_net")))
            scan_type = _normalize_scan_type(
                input(i18n.t("prompt.scan_type", d=default_type)), default_type
            )

            if '/' in target:
                with ui.status(i18n.t("status.discover")):
                    hosts = network_discovery(target)
                if not hosts:
                    ui.error(i18n.t("msg.no_host_responded"))
                    _pause()
                    continue
                ui.print_list(i18n.t("label.hosts_found", n=len(hosts)),
                              [f"{i}. {h}" for i, h in enumerate(hosts, 1)])
                selection = input(i18n.t("prompt.select_host")).strip()
                if selection:
                    try:
                        targets = [hosts[int(selection) - 1]]
                    except (ValueError, IndexError):
                        ui.error(i18n.t("msg.invalid_selection"))
                        continue
                else:
                    targets = hosts
            else:
                targets = [target]

            report = {}
            scan_concurrency = CONFIG["scan"].get("concurrency", 100)
            nvd_key = CONFIG.get("api_keys", {}).get("nvd", "")
            for host in targets:
                with ui.status(i18n.t("status.scanning", h=host)):
                    results = await perform_scan(
                        host, scan_type, concurrency=scan_concurrency, nvd_api_key=nvd_key
                    )
                report[host] = results
                rows = [
                    (port, _scan_service_label(data["service"]), _scan_risk_label(data["risco"]),
                     (data["banner"] or "")[:60],
                     ", ".join(data["vulnerabilidades"]) or "—")
                    for port, data in results.items()
                ]
                row_styles = ["red" if data["risco"] == "high" else "green" for data in results.values()]
                if rows:
                    ui.print_table(i18n.t("label.scan_results", h=host),
                                   i18n.t("table.scan").split("|"),
                                   rows, row_styles=row_styles)
                else:
                    ui.notice(i18n.t("msg.no_open_ports", h=host))
            _offer_export(report, f"scan-{targets[0]}", f"Scan {', '.join(targets)}")

        elif choice == 4:  # Utilitários
            sub_choice = show_menu(i18n.t("menu.utils.title"), [
                i18n.t("menu.utils.hashtext"),
                i18n.t("menu.utils.hashfile"),
                i18n.t("menu.utils.b64enc"),
                i18n.t("menu.utils.b64dec"),
                i18n.t("menu.utils.jwt"),
            ])

            if sub_choice == 1:
                text = input(_cyan("prompt.text"))
                algo = (input(f"{Fore.CYAN}{i18n.t('prompt.algo')}{Style.RESET_ALL}").strip().lower() or "sha256")
                try:
                    ui.print_kv(i18n.t("label.hash"), {algo: hash_text(text, algo)})
                except ValueError as e:
                    ui.error(i18n.t("msg.invalid_algo", err=e))

            elif sub_choice == 2:
                path = input(f"\n{Fore.CYAN}{i18n.t('prompt.file_path')}{Style.RESET_ALL}").strip()
                algo = (input(f"{Fore.CYAN}{i18n.t('prompt.algo')}{Style.RESET_ALL}").strip().lower() or "sha256")
                try:
                    ui.print_kv(i18n.t("label.file_hash"), {algo: hash_file(path, algo)})
                except ValueError as e:
                    ui.error(i18n.t("msg.invalid_algo", err=e))

            elif sub_choice == 3:
                text = input(_cyan("prompt.text"))
                ui.print_kv(i18n.t("label.b64enc"), {"b64": b64_encode(text)})

            elif sub_choice == 4:
                text = input(f"\n{Fore.CYAN}{i18n.t('prompt.base64')}{Style.RESET_ALL}")
                ui.print_kv(i18n.t("label.b64dec"), {"decoded": b64_decode(text)})

            elif sub_choice == 5:
                token = input(f"\n{Fore.CYAN}{i18n.t('prompt.jwt')}{Style.RESET_ALL}").strip()
                r = jwt_decode(token)
                if "erro" in r:
                    ui.error(r["erro"])
                else:
                    print(f"\n {Fore.YELLOW}header:{Style.RESET_ALL} {json.dumps(r['header'], indent=2)}")
                    print(f" {Fore.YELLOW}payload:{Style.RESET_ALL} {json.dumps(r['payload'], indent=2)}")
                    print(f" {Fore.YELLOW}signature:{Style.RESET_ALL} {r['signature']}")

        _pause()


def main_entry() -> None:
    """Entry point CLI (usado por pyproject scripts).

    Com subcomando (``gyntoolkit recon dns ...``) roda a CLI não-interativa e
    sai. Sem subcomando, abre o menu interativo clássico.
    """
    from . import commands

    rc = commands.run()
    if rc != -1:  # subcomando executado (ou erro) → não abre o menu
        sys.exit(rc)

    # Sem subcomando: menu interativo. i18n já foi resolvido em commands.run().
    try:
        if os.name == 'posix' and os.geteuid() != 0:
            print(f"\n{Fore.RED}{i18n.t('warn.need_root')}{Style.RESET_ALL}")
        elif os.name == 'nt' and not is_admin_windows():
            print(f"\n{Fore.RED}{i18n.t('warn.need_admin')}{Style.RESET_ALL}")

        asyncio.run(main_flow())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}{i18n.t('common.interrupted')}{Style.RESET_ALL}")
        sys.exit(1)
