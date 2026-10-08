#!/usr/bin/env python3
"""CLI não-interativa (scriptável).

Sem subcomando, a aplicação abre o menu interativo clássico. Com subcomando,
executa uma única ação e imprime o resultado como JSON em stdout (pipe-friendly),
opcionalmente salvando um relatório em disco (``--output`` / ``--format``).

Exemplos::

    gyntoolkit recon dns example.com --type MX
    gyntoolkit recon axfr example.com
    gyntoolkit scan 127.0.0.1 --type fast
    gyntoolkit utils hash "texto" --algo sha1
    gyntoolkit scan scanme.example.com -o reports -f md
"""

import argparse
import asyncio
import json
import sys
from typing import Any

from . import __version__, i18n
from .config import CONFIG
from .export import save_report


def _print_result(data: Any, quiet: bool = False) -> None:
    """Imprime ``data`` como JSON indentado em stdout."""
    if quiet:
        return
    json.dump(data, sys.stdout, indent=2, ensure_ascii=False, default=str)
    sys.stdout.write("\n")


def _maybe_save(data: Any, basename: str, title: str, args: argparse.Namespace) -> None:
    """Salva relatório se ``--output`` foi passado."""
    if not getattr(args, "output", None):
        return
    path = save_report(data, basename, fmt=args.format, out_dir=args.output, title=title)
    print(f"[+] {i18n.t('msg.report_saved', path=path)}", file=sys.stderr)


# --------------------------------------------------------------------------
# Handlers: cada um retorna (data, basename, title) JSON-serializável.
# --------------------------------------------------------------------------
def _h_recon(args: argparse.Namespace) -> tuple[Any, str, str]:
    from . import recon

    a = args.action
    if a == "whois":
        r = recon.whois_lookup(args.target)
        return ({"domain": args.target, "whois": str(r)}, f"whois-{args.target}", f"WHOIS {args.target}")
    if a == "dns":
        records = recon.dns_lookup(args.target, args.type.upper(), args.nameserver)
        return ({"domain": args.target, "type": args.type.upper(), "records": records},
                f"dns-{args.target}-{args.type}", f"DNS {args.type.upper()} {args.target}")
    if a == "axfr":
        r = recon.zone_transfer(args.target)
        return (r, f"axfr-{args.target}", f"Zone Transfer {args.target}")
    if a == "webscan":
        from pathlib import Path as _P

        from .brute import load_wordlist
        from .web import web_discovery

        custom = load_wordlist(args.wordlist) if args.wordlist and _P(args.wordlist).is_file() else None
        r = asyncio.run(web_discovery(args.target, paths=custom))
        return (r, f"webscan-{args.target}", f"Web Discovery {args.target}")
    if a == "geo":
        return (recon.geo_ip(args.target), f"geoip-{args.target}", f"Geo IP {args.target}")
    if a == "revdns":
        return (recon.reverse_dns(args.target), f"revdns-{args.target}", f"Reverse DNS {args.target}")
    if a == "subenum":
        subs = recon.subdomain_enum(args.target, timeout=CONFIG["recon"]["subdomain_timeout"])
        return ({"domain": args.target, "total": len(subs), "subdomains": subs},
                f"subdomains-{args.target}", f"Subdomains {args.target}")
    if a == "ssl":
        return (recon.ssl_inspect(args.target, args.port, timeout=CONFIG["recon"]["ssl_timeout"]),
                f"ssl-{args.target}", f"SSL {args.target}:{args.port}")
    if a == "httpfp":
        return (recon.http_fingerprint(args.target, timeout=CONFIG["recon"]["http_timeout"]),
                f"httpfp-{args.target}", f"HTTP Fingerprint {args.target}")
    if a == "internetdb":
        return (recon.internetdb_lookup(args.target), f"internetdb-{args.target}", f"InternetDB {args.target}")
    if a == "shodan":
        key = CONFIG.get("api_keys", {}).get("shodan", "")
        return (recon.shodan_host(args.target, api_key=key), f"shodan-{args.target}", f"Shodan {args.target}")
    if a == "hibp":
        return (recon.hibp_breaches(args.target), f"hibp-{args.target}", f"HIBP {args.target}")
    if a == "mac":
        return ({"mac": args.target, "vendor": recon.mac_vendor(args.target)},
                f"macvendor-{args.target}", "MAC Vendor")
    if a == "traceroute":
        hops = recon.traceroute(args.target, max_hops=args.max_hops, dport=args.dport)
        return ({"target": args.target, "dport": args.dport, "hops": hops},
                f"traceroute-{args.target}", f"Traceroute {args.target}")
    raise ValueError(f"unknown recon action: {a}")


def _h_scan(args: argparse.Namespace) -> tuple[Any, str, str]:
    from .scan import network_discovery, perform_scan

    if "/" in args.target:  # CIDR → descoberta de hosts
        hosts = network_discovery(args.target)
        return ({"network": args.target, "hosts": hosts}, f"discovery-{args.target.replace('/', '_')}",
                f"Host discovery {args.target}")
    concurrency = args.concurrency or CONFIG["scan"].get("concurrency", 100)
    nvd_key = CONFIG.get("api_keys", {}).get("nvd", "")
    results = asyncio.run(perform_scan(args.target, args.type, concurrency=concurrency, nvd_api_key=nvd_key))
    # chaves int → str p/ JSON estável
    report = {str(port): data for port, data in results.items()}
    return ({args.target: report}, f"scan-{args.target}", f"Scan {args.target}")


def _h_utils(args: argparse.Namespace) -> tuple[Any, str, str]:
    from .utils import b64_decode, b64_encode, hash_file, hash_text, jwt_decode

    a = args.action
    if a == "hash":
        return ({"algo": args.algo, "hash": hash_text(args.value, args.algo)}, "hash", "Hash")
    if a == "hashfile":
        return ({"algo": args.algo, "path": args.value, "hash": hash_file(args.value, args.algo)},
                "filehash", "File hash")
    if a == "b64enc":
        return ({"input": args.value, "b64": b64_encode(args.value)}, "b64enc", "Base64 encode")
    if a == "b64dec":
        return ({"input": args.value, "decoded": b64_decode(args.value)}, "b64dec", "Base64 decode")
    if a == "jwt":
        return (jwt_decode(args.value), "jwt", "JWT decode")
    raise ValueError(f"unknown utils action: {a}")


def _h_brute(args: argparse.Namespace) -> tuple[Any, str, str]:
    from pathlib import Path

    from .brute import http_bruteforce, load_wordlist, ssh_bruteforce

    if not args.authorize:
        print(i18n.t("brute.warn_authorized"), file=sys.stderr)
        print("[!] Non-interactive brute requires --authorize (you confirm written authorization).",
              file=sys.stderr)
        sys.exit(2)

    users = load_wordlist(args.users) if Path(args.users).is_file() else [args.users]
    passwords = load_wordlist(args.passwords)
    if not users or not users[0] or not passwords:
        print(i18n.t("msg.empty_wordlist"), file=sys.stderr)
        sys.exit(2)

    b = CONFIG["brute"]
    if args.action == "ssh":
        found = asyncio.run(ssh_bruteforce(
            args.target, users, passwords, port=args.port,
            workers=args.workers or b["ssh_workers"], delay=b["delay"], timeout=b["ssh_timeout"],
        ))
    else:  # http
        found = asyncio.run(http_bruteforce(
            args.target, users, passwords, mode=args.mode,
            user_field=args.user_field, pass_field=args.pass_field,
            fail_signature=args.fail_signature or "",
            workers=args.workers or b["http_workers"], delay=b["delay"], timeout=b["http_timeout"],
        ))
    creds = [{"user": u, "password": p} for u, p in found]
    return ({"target": args.target, "found": creds}, f"brute-{args.action}", f"Brute {args.action}")


def _run_wordlist(args: argparse.Namespace) -> int:
    """Gera wordlist e imprime linhas em stdout (ou salva com --save)."""
    from .wordlist import generate_wordlist

    terms = [t for t in (args.terms or "").split(",") if t.strip()]
    years = [y for y in (args.years or "").split(",") if y.strip()]
    if not terms:
        print("[!] --terms is required (comma-separated base words).", file=sys.stderr)
        return 2
    words = generate_wordlist(
        terms, years=years, use_leet=args.leet, use_special=not args.no_special,
        combine=not args.no_combine, min_len=args.min_len, max_len=args.max_len,
    )
    if args.save:
        from pathlib import Path as _P

        p = _P(args.save).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(words) + "\n", encoding="utf-8")
        print(f"[+] {len(words)} words -> {p}", file=sys.stderr)
    if not args.quiet:
        sys.stdout.write("\n".join(words) + ("\n" if words else ""))
    return 0


_DISPATCH = {"recon": _h_recon, "scan": _h_scan, "utils": _h_utils, "brute": _h_brute}


def build_parser() -> argparse.ArgumentParser:
    # Opções de saída compartilhadas: herdadas por cada subcomando-folha, então
    # podem aparecer DEPOIS do subcomando (ex.: `gyntoolkit scan x -o dir -f md`).
    io = argparse.ArgumentParser(add_help=False)
    io.add_argument("-o", "--output", metavar="DIR", help="Also save a report into this directory.")
    io.add_argument("-f", "--format", choices=("json", "html", "csv", "md"), default="json",
                    help="Report format when --output is used (default: json).")
    io.add_argument("-q", "--quiet", action="store_true", help="Do not print JSON to stdout.")
    io.add_argument("--lang", choices=("en", "pt"), help="UI/message language override.")

    p = argparse.ArgumentParser(
        prog="gyntoolkit",
        description="GynToolkit — security toolkit. Run with no subcommand for the interactive menu.",
    )
    p.add_argument("--version", action="version", version=f"gyntoolkit {__version__}")

    sub = p.add_subparsers(dest="group")

    # recon
    recon_p = sub.add_parser("recon", help="Reconnaissance modules.")
    recon_sub = recon_p.add_subparsers(dest="action", required=True)
    for name in ("whois", "geo", "revdns", "subenum", "internetdb", "hibp", "mac", "axfr", "shodan"):
        sp = recon_sub.add_parser(name, parents=[io])
        sp.add_argument("target")
    dns_p = recon_sub.add_parser("dns", parents=[io])
    dns_p.add_argument("target")
    dns_p.add_argument("--type", default="A", help="Record type (A, AAAA, MX, NS, TXT, ...).")
    dns_p.add_argument("--nameserver", default=None, help="DNS server to query.")
    ssl_p = recon_sub.add_parser("ssl", parents=[io])
    ssl_p.add_argument("target")
    ssl_p.add_argument("--port", type=int, default=443)
    httpfp_p = recon_sub.add_parser("httpfp", parents=[io])
    httpfp_p.add_argument("target", help="URL with http/https.")
    web_p = recon_sub.add_parser("webscan", parents=[io])
    web_p.add_argument("target", help="Base URL to enumerate.")
    web_p.add_argument("--wordlist", default=None, help="Path to a custom paths wordlist.")
    tr_p = recon_sub.add_parser("traceroute", parents=[io])
    tr_p.add_argument("target")
    tr_p.add_argument("--max-hops", dest="max_hops", type=int,
                      default=CONFIG["recon"]["traceroute_max_hops"])
    tr_p.add_argument("--dport", type=int, default=CONFIG["recon"]["traceroute_dport"])

    # scan
    scan_p = sub.add_parser("scan", parents=[io],
                            help="Port scan + CVE lookup (or host discovery for a CIDR).")
    scan_p.add_argument("target", help="IP/host, or CIDR (e.g. 192.168.0.0/24) for discovery.")
    scan_p.add_argument("--type", choices=("fast", "full"), default=CONFIG["scan"]["default_type"])
    scan_p.add_argument("--concurrency", type=int, default=0, help="Simultaneous probes (0 = config default).")

    # utils
    utils_p = sub.add_parser("utils", help="Crypto helpers.")
    utils_sub = utils_p.add_subparsers(dest="action", required=True)
    for name in ("hash", "hashfile"):
        sp = utils_sub.add_parser(name, parents=[io])
        sp.add_argument("value")
        sp.add_argument("--algo", default="sha256")
    for name in ("b64enc", "b64dec", "jwt"):
        sp = utils_sub.add_parser(name, parents=[io])
        sp.add_argument("value")

    # brute (requires --authorize)
    brute_p = sub.add_parser("brute", help="Active attacks (requires --authorize).")
    brute_sub = brute_p.add_subparsers(dest="action", required=True)
    ssh_p = brute_sub.add_parser("ssh", parents=[io])
    ssh_p.add_argument("target")
    ssh_p.add_argument("--users", required=True, help="Single user or path to users wordlist.")
    ssh_p.add_argument("--passwords", required=True, help="Path to passwords wordlist.")
    ssh_p.add_argument("--port", type=int, default=22)
    ssh_p.add_argument("--workers", type=int, default=0)
    ssh_p.add_argument("--authorize", action="store_true", help="Confirm you have written authorization.")
    http_p = brute_sub.add_parser("http", parents=[io])
    http_p.add_argument("target", help="Target URL.")
    http_p.add_argument("--users", required=True)
    http_p.add_argument("--passwords", required=True)
    http_p.add_argument("--mode", choices=("basic", "form"), default="basic")
    http_p.add_argument("--user-field", dest="user_field", default="username")
    http_p.add_argument("--pass-field", dest="pass_field", default="password")
    http_p.add_argument("--fail-signature", dest="fail_signature", default="")
    http_p.add_argument("--workers", type=int, default=0)
    http_p.add_argument("--authorize", action="store_true", help="Confirm you have written authorization.")

    # wordlist (gerador nativo; saída em linhas, não JSON)
    wl_p = sub.add_parser("wordlist", help="Generate a custom wordlist (CUPP-style, offline).")
    wl_p.add_argument("--terms", required=True, help="Comma-separated base words (name, pet, company, ...).")
    wl_p.add_argument("--years", default="", help="Comma-separated years/numbers to append.")
    wl_p.add_argument("--leet", action="store_true", help="Also emit leet variants (a->4/@, e->3, ...).")
    wl_p.add_argument("--no-special", dest="no_special", action="store_true", help="Skip common suffixes.")
    wl_p.add_argument("--no-combine", dest="no_combine", action="store_true", help="Do not combine term pairs.")
    wl_p.add_argument("--min-len", dest="min_len", type=int, default=4)
    wl_p.add_argument("--max-len", dest="max_len", type=int, default=32)
    wl_p.add_argument("--save", default=None, help="Write the wordlist to this file.")
    wl_p.add_argument("-q", "--quiet", action="store_true", help="Do not print to stdout.")

    return p


def run(argv: list[str] | None = None) -> int:
    """Executa a CLI não-interativa. Retorna exit code.

    Levanta :class:`SystemExit` com código 0 e ``group is None`` quando nenhum
    subcomando foi dado — o chamador deve então abrir o menu interativo.
    """
    args = build_parser().parse_args(argv)
    lang_override = getattr(args, "lang", None)
    i18n.set_lang(i18n.resolve_lang(lang_override or CONFIG.get("ui", {}).get("lang")))

    if args.group is None:
        return -1  # sinaliza "sem subcomando" → menu interativo

    if args.group == "wordlist":
        return _run_wordlist(args)

    handler = _DISPATCH[args.group]
    data, basename, title = handler(args)
    _print_result(data, quiet=args.quiet)
    _maybe_save(data, basename, title, args)
    return 0
