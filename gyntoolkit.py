#!/usr/bin/env python3
# coding: utf-8

import sys
import os
import re
import asyncio
import ipaddress
import logging
import shutil
import subprocess
import socket
import requests
import whois
import dns.resolver
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from colorama import Fore, Style, init
from scapy.all import ARP, Ether, srp, TCP, IP, sr1

# Inicialização do Colorama
init(autoreset=True)

# Logging estruturado (arquivo + stderr silencioso p/ não poluir UI)
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler("gyntoolkit.log", encoding="utf-8")],
)
log = logging.getLogger("gyntoolkit")

# --------------------------
# Configurações e Constantes
# --------------------------
LOGO = f"""{Fore.GREEN}
 ██████╗██╗   ██╗███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝╚██╗ ██╔╝████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
██║  ███╗╚████╔╝ ██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
██║   ██║ ╚██╔╝  ██║╚██╗██║       ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   v1.2
╚██████╔╝  ██║   ██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║ by: PH,Fl4vs
 ╚═════╝   ╚═╝   ╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
{Style.RESET_ALL}"""

PROMPT = f"{Fore.RED}gyntoolkit:~# {Style.RESET_ALL}"
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
MAX_THREADS = 100

# --------------------------
# Funções Utilitárias
# --------------------------
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def is_admin_windows():
    """Verifica se é administrador no Windows"""
    try:
        from ctypes import windll
        return windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def sanitize_input(input_str: str, pattern: str = r"[A-Za-z0-9./:-]") -> str:
    """Remove caracteres não permitidos da entrada"""
    return ''.join(re.findall(pattern, input_str))

def show_menu(title: str, options: list) -> int:
    """Exibe menu interativo com tratamento de erros"""
    while True:
        clear_screen()
        print(LOGO)
        print(f"\n{Fore.CYAN}{title}{Style.RESET_ALL}")
        for idx, opt in enumerate(options, 1):
            print(f" {Fore.YELLOW}[{idx}]{Style.RESET_ALL} {opt}")
        print(f" {Fore.YELLOW}[0]{Style.RESET_ALL} Voltar/Sair")
        
        try:
            choice = int(input(f"\n{PROMPT}"))
            if 0 <= choice <= len(options):
                return choice
            raise ValueError
        except ValueError:
            print(f"\n{Fore.RED}Opção inválida! Tente novamente.{Style.RESET_ALL}")

# --------------------------
# Funções de Escaneamento (Corrigidas)
# --------------------------
async def syn_scan(target: str, port: int) -> Tuple[int, bool]:
    """Varredura stealth SYN (requer admin/root)"""
    try:
        pkt = IP(dst=target)/TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=2, verbose=0)
        if response is None:
            return (port, False)
        return (port, response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12)
    except (OSError, PermissionError) as e:
        log.warning("syn_scan %s:%s falhou: %s", target, port, e)
        return (port, False)

async def connect_scan(target: str, port: int) -> Tuple[int, bool]:
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

async def get_banner(target: str, port: int) -> Tuple[int, str]:
    """Obtém banner do serviço"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=3
        )
        writer.write(b"GET / HTTP/1.1\r\n\r\n")
        banner = await asyncio.wait_for(reader.read(512), timeout=2)
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return (port, banner.decode(errors='ignore').strip())
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
        log.debug("banner %s:%s vazio: %s", target, port, e)
        return (port, "Nenhum banner identificado")

def check_vulnerabilities(service: str) -> List[str]:
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

def network_discovery(cidr: str, timeout: int = 2) -> List[str]:
    """Descobre hosts ativos em rede via ARP scan (requer privilégio)."""
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        log.error("CIDR inválido '%s': %s", cidr, e)
        print(f"{Fore.RED}CIDR inválido: {e}{Style.RESET_ALL}")
        return []

    try:
        arp = ARP(pdst=cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(ether / arp, timeout=timeout, verbose=0)
        hosts = sorted({r.psrc for _, r in answered}, key=lambda ip: ipaddress.ip_address(ip))
        return hosts
    except PermissionError:
        print(f"{Fore.RED}ARP scan requer privilégio root/admin.{Style.RESET_ALL}")
        return []
    except OSError as e:
        log.error("ARP scan falhou: %s", e)
        print(f"{Fore.RED}Falha no ARP scan: {e}{Style.RESET_ALL}")
        return []

# --------------------------
# Funções Principais (Atualizadas)
# --------------------------
async def perform_scan(target: str, scan_type: str) -> Dict[int, dict]:
    """Executa varredura completa com análise de vulnerabilidades"""
    ports = TOP_PORTS if scan_type == "rápido" else range(1, 65536)
    open_ports = []
    results = {}

    # Fase 1: Varredura de portas
    tasks = []
    for port in ports:
        # Verificação de privilégios multiplataforma
        if os.name == 'posix':
            use_syn = os.geteuid() == 0  # Linux/Mac
        else:
            use_syn = is_admin_windows()  # Windows
        
        if use_syn:
            tasks.append(syn_scan(target, port))
        else:
            tasks.append(connect_scan(target, port))

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
        service = banners[port].split()[0] if banners[port] else "Desconhecido"
        vulns = check_vulnerabilities(service)
        
        results[port] = {
            'service': service,
            'banner': banners[port],
            'vulnerabilidades': vulns,
            'risco': "Alto" if vulns else "Baixo"
        }

    return results

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
               timeout: int = 5) -> List[str]:
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
    
def geo_ip(target: str) -> Dict[str, str]:
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


def print_ethical_warning(action: str) -> bool:
    """Alerta ético antes de operação intrusiva. Retorna True se autorizado."""
    print(f"\n{Fore.RED}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.RED}[!] AVISO: {action} é ataque ativo.{Style.RESET_ALL}")
    print(f"{Fore.RED}[!] Use apenas em alvos com autorização por escrito.{Style.RESET_ALL}")
    print(f"{Fore.RED}[!] Uso não autorizado é crime (Lei 12.737/12, CFAA, etc).{Style.RESET_ALL}")
    print(f"{Fore.RED}{'=' * 60}{Style.RESET_ALL}")
    confirm = input(f"{Fore.YELLOW}Confirmar autorização? (digite 'AUTORIZO'): {Style.RESET_ALL}").strip()
    return confirm == "AUTORIZO"


def load_wordlist(path: str) -> List[str]:
    """Carrega wordlist do disco, deduplicando e ignorando linhas vazias."""
    p = Path(path).expanduser()
    if not p.is_file():
        print(f"{Fore.RED}Wordlist não encontrada: {p}{Style.RESET_ALL}")
        return []
    try:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            words = [w.strip() for w in f if w.strip()]
        return list(dict.fromkeys(words))
    except OSError as e:
        log.error("Falha ao ler wordlist %s: %s", p, e)
        return []


def cupp_generate() -> None:
    """Chama CUPP interativo p/ gerar wordlist customizada."""
    cupp_paths = [
        Path(__file__).parent / "cupp" / "cupp.py",
        Path.cwd() / "cupp" / "cupp.py",
    ]
    cupp = next((p for p in cupp_paths if p.is_file()), None)
    if not cupp:
        print(f"{Fore.RED}CUPP não encontrado. Clone: git clone https://github.com/Mebus/cupp.git{Style.RESET_ALL}")
        return

    python_exe = shutil.which("python") or shutil.which("python3") or sys.executable
    try:
        subprocess.run([python_exe, str(cupp), "-i"], check=False)
    except OSError as e:
        log.error("CUPP execução falhou: %s", e)
        print(f"{Fore.RED}Erro ao rodar CUPP: {e}{Style.RESET_ALL}")


async def _ssh_try(host: str, port: int, user: str, password: str, timeout: int) -> Optional[Tuple[str, str]]:
    """Tenta uma credencial SSH. Retorna (user, pass) se sucesso."""
    import paramiko

    def _attempt() -> bool:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host, port=port, username=user, password=password,
                timeout=timeout, allow_agent=False, look_for_keys=False,
                banner_timeout=timeout, auth_timeout=timeout,
            )
            return True
        except paramiko.AuthenticationException:
            return False
        except (paramiko.SSHException, OSError, EOFError) as e:
            log.debug("SSH %s@%s:%s erro: %s", user, host, port, e)
            return False
        finally:
            client.close()

    ok = await asyncio.to_thread(_attempt)
    return (user, password) if ok else None


async def ssh_bruteforce(
    host: str,
    users: List[str],
    passwords: List[str],
    port: int = 22,
    workers: int = 8,
    delay: float = 0.1,
    timeout: int = 5,
) -> List[Tuple[str, str]]:
    """Brute-force SSH assíncrono com controle de concorrência."""
    try:
        import paramiko  # noqa: F401
    except ImportError:
        print(f"{Fore.RED}paramiko não instalado. Rode: pip install paramiko{Style.RESET_ALL}")
        return []

    sem = asyncio.Semaphore(workers)
    found: List[Tuple[str, str]] = []
    total = len(users) * len(passwords)
    tried = 0

    async def _guarded(u: str, p: str):
        nonlocal tried
        async with sem:
            await asyncio.sleep(delay)
            result = await _ssh_try(host, port, u, p, timeout)
            tried += 1
            if tried % 25 == 0:
                print(f"{Fore.CYAN}[{tried}/{total}] tentativas...{Style.RESET_ALL}")
            if result:
                found.append(result)
                print(f"{Fore.GREEN}[+] SSH válido: {u}:{p}{Style.RESET_ALL}")

    tasks = [_guarded(u, p) for u in users for p in passwords]
    await asyncio.gather(*tasks)
    return found


async def http_bruteforce(
    url: str,
    users: List[str],
    passwords: List[str],
    mode: str = "basic",
    user_field: str = "username",
    pass_field: str = "password",
    fail_signature: str = "",
    workers: int = 10,
    delay: float = 0.1,
    timeout: int = 10,
) -> List[Tuple[str, str]]:
    """Brute-force HTTP (basic-auth ou form POST)."""
    try:
        import aiohttp
    except ImportError:
        print(f"{Fore.RED}aiohttp não instalado. Rode: pip install aiohttp{Style.RESET_ALL}")
        return []

    sem = asyncio.Semaphore(workers)
    found: List[Tuple[str, str]] = []
    total = len(users) * len(passwords)
    tried = 0

    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    connector = aiohttp.TCPConnector(limit=workers, ssl=False)

    async with aiohttp.ClientSession(timeout=timeout_cfg, connector=connector) as session:
        async def _attempt(u: str, p: str):
            nonlocal tried
            async with sem:
                await asyncio.sleep(delay)
                try:
                    if mode == "basic":
                        auth = aiohttp.BasicAuth(u, p)
                        async with session.get(url, auth=auth) as r:
                            ok = r.status not in (401, 403)
                    else:
                        payload = {user_field: u, pass_field: p}
                        async with session.post(url, data=payload, allow_redirects=False) as r:
                            body = await r.text()
                            ok = r.status in (200, 302) and (not fail_signature or fail_signature not in body)
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    log.debug("HTTP %s %s:%s erro: %s", url, u, p, e)
                    ok = False

                tried += 1
                if tried % 25 == 0:
                    print(f"{Fore.CYAN}[{tried}/{total}] tentativas...{Style.RESET_ALL}")
                if ok:
                    found.append((u, p))
                    print(f"{Fore.GREEN}[+] HTTP válido: {u}:{p}{Style.RESET_ALL}")

        await asyncio.gather(*[_attempt(u, p) for u in users for p in passwords])
    return found


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

# --------------------------
# Fluxo Principal
# --------------------------
async def main_flow():
    while True:
        choice = show_menu("Menu Principal:", [
            "Obter Informações",
            "Brute Force",
            "Varredura Avançada"
        ])
        
        if choice == 0:
            print(f"\n{Fore.MAGENTA}Saindo...{Style.RESET_ALL}")
            sys.exit()
            
        elif choice == 1:  # Obter Informações
            sub_choice = show_menu("Obter Informações:", [
                "Consulta WHOIS",
                "DNS Lookup",
                "Geolocalização IP"
            ])
            
            if sub_choice == 1:
                domain = input(f"\n{Fore.CYAN}Digite o domínio: {Style.RESET_ALL}")
                print(f"\n{Fore.GREEN}Resultado:{Style.RESET_ALL}")
                print(whois_lookup(domain))

            elif sub_choice == 2:
                domain = sanitize_input(
                    input(f"\n{Fore.CYAN}Digite o domínio: {Style.RESET_ALL}"),
                    r"[A-Za-z0-9.-]",
                )

                rtype = escolher_tipo_dns()
                if not rtype:
                    continue

                ns = input(f"{Fore.CYAN}Servidor DNS (ENTER para default): {Style.RESET_ALL}") or None

                print(f"\n{Fore.GREEN}Consultando registro {rtype} para {domain}...{Style.RESET_ALL}\n")
                records = dns_lookup(domain, rtype.upper(), ns)
                for rec in records:
                    print(f" - {rec}")

            elif sub_choice == 3:
                target = sanitize_input(
                    input(f"\n{Fore.CYAN}IP ou domínio: {Style.RESET_ALL}"),
                    r"[A-Za-z0-9.:-]",
                )
                print(f"\n{Fore.GREEN}Consultando geolocalização de {target}...{Style.RESET_ALL}\n")
                info = geo_ip(target)
                if "erro" in info:
                    print(f"{Fore.RED}{info['erro']}{Style.RESET_ALL}")
                else:
                    label_map = {
                        "query": "IP", "country": "País", "regionName": "Região",
                        "city": "Cidade", "zip": "CEP", "lat": "Latitude", "lon": "Longitude",
                        "timezone": "Fuso", "isp": "ISP", "org": "Organização", "as": "ASN",
                        "reverse": "Reverse DNS", "mobile": "Mobile", "proxy": "Proxy",
                        "hosting": "Hosting",
                    }
                    for key, label in label_map.items():
                        if key in info:
                            print(f" {Fore.YELLOW}{label}:{Style.RESET_ALL} {info[key]}")

        elif choice == 2:  # Brute Force
            sub_choice = show_menu("Brute Force:", [
                "Gerar Wordlist (CUPP)",
                "Ataque SSH",
                "Ataque HTTP"
            ])

            if sub_choice == 1:
                cupp_generate()

            elif sub_choice == 2:
                if not print_ethical_warning("Brute-force SSH"):
                    print(f"{Fore.RED}Autorização não confirmada. Abortando.{Style.RESET_ALL}")
                    input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
                    continue
                host = sanitize_input(input(f"\n{Fore.CYAN}Host alvo: {Style.RESET_ALL}"))
                port = int(input(f"{Fore.CYAN}Porta [22]: {Style.RESET_ALL}") or 22)
                user_input = input(f"{Fore.CYAN}Usuário único ou path de wordlist de usuários: {Style.RESET_ALL}").strip()
                users = load_wordlist(user_input) if Path(user_input).is_file() else [user_input]
                pass_path = input(f"{Fore.CYAN}Path da wordlist de senhas: {Style.RESET_ALL}").strip()
                passwords = load_wordlist(pass_path)
                if not users or not passwords:
                    print(f"{Fore.RED}Wordlist vazia. Abortando.{Style.RESET_ALL}")
                    input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
                    continue
                workers = int(input(f"{Fore.CYAN}Workers concorrentes [8]: {Style.RESET_ALL}") or 8)
                print(f"\n{Fore.CYAN}Iniciando SSH brute em {host}:{port} ({len(users)}x{len(passwords)} = {len(users)*len(passwords)} combos)...{Style.RESET_ALL}\n")
                results = await ssh_bruteforce(host, users, passwords, port=port, workers=workers)
                if results:
                    print(f"\n{Fore.GREEN}Credenciais encontradas:{Style.RESET_ALL}")
                    for u, p in results:
                        print(f"  {u}:{p}")
                else:
                    print(f"\n{Fore.RED}Nenhuma credencial válida encontrada.{Style.RESET_ALL}")

            elif sub_choice == 3:
                if not print_ethical_warning("Brute-force HTTP"):
                    print(f"{Fore.RED}Autorização não confirmada. Abortando.{Style.RESET_ALL}")
                    input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
                    continue
                url = input(f"\n{Fore.CYAN}URL alvo (com http/https): {Style.RESET_ALL}").strip()
                mode = (input(f"{Fore.CYAN}Modo [basic/form] (default basic): {Style.RESET_ALL}").strip().lower() or "basic")
                user_field = pass_field = fail_sig = ""
                if mode == "form":
                    user_field = input(f"{Fore.CYAN}Nome do campo usuário [username]: {Style.RESET_ALL}").strip() or "username"
                    pass_field = input(f"{Fore.CYAN}Nome do campo senha [password]: {Style.RESET_ALL}").strip() or "password"
                    fail_sig = input(f"{Fore.CYAN}Trecho de texto que indica falha (ex: 'Invalid'): {Style.RESET_ALL}").strip()
                user_input = input(f"{Fore.CYAN}Usuário único ou path de wordlist: {Style.RESET_ALL}").strip()
                users = load_wordlist(user_input) if Path(user_input).is_file() else [user_input]
                pass_path = input(f"{Fore.CYAN}Path da wordlist de senhas: {Style.RESET_ALL}").strip()
                passwords = load_wordlist(pass_path)
                if not users or not passwords:
                    print(f"{Fore.RED}Wordlist vazia. Abortando.{Style.RESET_ALL}")
                    input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
                    continue
                workers = int(input(f"{Fore.CYAN}Workers concorrentes [10]: {Style.RESET_ALL}") or 10)
                print(f"\n{Fore.CYAN}Iniciando HTTP brute em {url} ({len(users)*len(passwords)} combos)...{Style.RESET_ALL}\n")
                results = await http_bruteforce(
                    url, users, passwords, mode=mode,
                    user_field=user_field, pass_field=pass_field,
                    fail_signature=fail_sig, workers=workers,
                )
                if results:
                    print(f"\n{Fore.GREEN}Credenciais encontradas:{Style.RESET_ALL}")
                    for u, p in results:
                        print(f"  {u}:{p}")
                else:
                    print(f"\n{Fore.RED}Nenhuma credencial válida encontrada.{Style.RESET_ALL}")
            
        elif choice == 3:  # Varredura Avançada
            target = sanitize_input(input(f"\n{Fore.CYAN}Alvo (IP/rede): {Style.RESET_ALL}"))
            scan_type = input("Tipo de varredura [rápido/completo]: ").lower().strip() or "rápido"

            if '/' in target:
                print(f"\n{Fore.CYAN}Descobrindo hosts ativos...{Style.RESET_ALL}")
                hosts = network_discovery(target)
                if not hosts:
                    print(f"{Fore.RED}Nenhum host respondeu.{Style.RESET_ALL}")
                    input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
                    continue
                print(f"{Fore.GREEN}Hosts encontrados: {len(hosts)}{Style.RESET_ALL}")
                for idx, host in enumerate(hosts, 1):
                    print(f"{idx}. {host}")
                selection = input("Selecione o host (ENTER para todos): ").strip()
                if selection:
                    try:
                        targets = [hosts[int(selection) - 1]]
                    except (ValueError, IndexError):
                        print(f"{Fore.RED}Seleção inválida.{Style.RESET_ALL}")
                        continue
                else:
                    targets = hosts
            else:
                targets = [target]

            for host in targets:
                print(f"\n{Fore.CYAN}Escaneando {host}...{Style.RESET_ALL}")
                results = await perform_scan(host, scan_type)
                print(f"\n{Fore.GREEN}Resultados para {host}:{Style.RESET_ALL}")
                for port, data in results.items():
                    risco_color = Fore.RED if data['risco'] == "Alto" else Fore.GREEN
                    print(f"\n{Fore.YELLOW}Porta {port}:{Style.RESET_ALL}")
                    print(f"Serviço: {data['service']}")
                    print(f"Risco: {risco_color}{data['risco']}{Style.RESET_ALL}")
                    print(f"Banner: {data['banner'][:100]}...")
                    if data['vulnerabilidades']:
                        print(f"CVEs: {', '.join(data['vulnerabilidades'])}")

        input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")

# --------------------------
# Ponto de Entrada
# --------------------------
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


if __name__ == "__main__":
    main_entry()