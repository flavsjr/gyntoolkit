#!/usr/bin/env python3
# coding: utf-8

import sys
import os
import re
import asyncio
import requests
import whois
from typing import Dict, List, Tuple
from colorama import Fore, Style, init
from scapy.all import ARP, Ether, srp, TCP, IP, sr1

# Inicialização do Colorama
init(autoreset=True)

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
        return (port, response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12)
    except:
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
    except:
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
        return (port, banner.decode(errors='ignore').strip())
    except:
        return (port, "Nenhum banner identificado")

def check_vulnerabilities(service: str) -> List[str]:
    """Verifica vulnerabilidades conhecidas usando NVD"""
    try:
        response = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service}",
            timeout=10
        )
        return [cve['cve']['CVE_data_meta']['ID'] for cve in response.json()['result']['CVE_Items'][:5]]
    except:
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

# --------------------------
# Fluxo Principal
# --------------------------
async def main_flow():
    while True:
        choice = show_menu("Menu Principal", [
            "Obter Informações",
            "Brute Force",
            "Varredura Avançada"
        ])
        
        if choice == 0:
            print(f"\n{Fore.MAGENTA}Saindo...{Style.RESET_ALL}")
            sys.exit()
            
        elif choice == 1:  # Obter Informações
            sub_choice = show_menu("Obter Informações", [
                "Consulta WHOIS",
                "DNS Lookup",
                "Geolocalização IP"
            ])
            
            if sub_choice == 1:
                domain = input(f"\n{Fore.CYAN}Digite o domínio: {Style.RESET_ALL}")
                print(f"\n{Fore.GREEN}Resultado:{Style.RESET_ALL}")
                print(whois_lookup(domain))
            
        elif choice == 2:  # Brute Force
            sub_choice = show_menu("Brute Force", [
                "Gerar Wordlist",
                "Ataque SSH",
                "Ataque HTTP"
            ])
            
        elif choice == 3:  # Varredura Avançada
            target = sanitize_input(input(f"\n{Fore.CYAN}Alvo (IP/rede): {Style.RESET_ALL}"))
            scan_type = input("Tipo de varredura [rápido/completo]: ").lower()

            if '/' in target:
                print(f"\n{Fore.CYAN}Descobrindo hosts ativos...{Style.RESET_ALL}")
                hosts = network_discovery(target)
                print(f"{Fore.GREEN}Hosts encontrados: {len(hosts)}{Style.RESET_ALL}")
                for idx, host in enumerate(hosts, 1):
                    print(f"{idx}. {host}")
                selection = input("Selecione o host (ENTER para todos): ")
                targets = [hosts[int(selection)-1] if selection else hosts]
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
if __name__ == "__main__":
    try:
        if os.name == 'posix' and os.geteuid() != 0:
            print(f"\n{Fore.RED}Aviso: Funcionalidades avançadas requerem root!{Style.RESET_ALL}")
        
        asyncio.run(main_flow())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Scan interrompido pelo usuário.{Style.RESET_ALL}")
        sys.exit(1)