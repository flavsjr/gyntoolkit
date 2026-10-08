#!/usr/bin/env python3
"""Núcleo compartilhado: constantes, logging, helpers de terminal e menu."""

import logging
import os
import re
import sys
from pathlib import Path

from colorama import Fore, Style, init

from . import i18n

# Raiz do projeto (um nível acima do pacote) — usada p/ localizar cupp/, etc.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# UTF-8 stdout/stderr no Windows (Python 3.7+)
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, OSError):
    pass

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
██║   ██║ ╚██╔╝  ██║╚██╗██║       ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   v2.3
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
    except Exception:
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
        print(f" {Fore.YELLOW}[0]{Style.RESET_ALL} {i18n.t('common.back_exit')}")

        try:
            choice = int(input(f"\n{PROMPT}"))
            if 0 <= choice <= len(options):
                return choice
            raise ValueError
        except ValueError:
            print(f"\n{Fore.RED}{i18n.t('common.invalid_option')}{Style.RESET_ALL}")
