#!/usr/bin/env python3
"""Web content discovery: robots.txt / sitemap / security.txt + path probing.

Enumera caminhos interessantes num alvo HTTP sem adivinhação cega: lê pistas
públicas (``robots.txt``, ``sitemap.xml``, ``/.well-known/security.txt``) e sonda
uma wordlist embutida de paths comuns, reportando o que não responde 404.
"""

import asyncio
from typing import Any
from urllib.parse import urljoin, urlparse

from . import i18n
from .core import log

# Wordlist embutida de paths comuns (curada, não exaustiva). O chamador pode
# passar a própria lista p/ substituir.
COMMON_PATHS: tuple[str, ...] = (
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "dashboard",
    "api", "api/v1", "graphql", "swagger", "swagger-ui", "openapi.json",
    "config", "config.php", ".env", ".git/config", ".git/HEAD", "backup",
    "backup.zip", "db.sql", "dump.sql", "phpinfo.php", "server-status",
    "robots.txt", "sitemap.xml", "status", "health", "healthz", "metrics",
    "debug", "test", "dev", "staging", "old", "tmp", "uploads", "files",
    "console", "actuator", "actuator/health", ".well-known/security.txt",
)

# Status que indicam "existe algo aqui" (tudo menos 404/ausência).
_INTERESTING = {200, 201, 202, 203, 204, 301, 302, 307, 308, 401, 403, 405, 500}


def _normalize_base(url: str) -> str:
    """Garante esquema e barra final no base URL."""
    if not urlparse(url).scheme:
        url = "http://" + url
    return url if url.endswith("/") else url + "/"


def _parse_robots(text: str) -> dict[str, list[str]]:
    """Extrai paths de Disallow/Allow e URLs de Sitemap do robots.txt."""
    paths: list[str] = []
    sitemaps: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if not value:
            continue
        if key in ("disallow", "allow"):
            paths.append(value)
        elif key == "sitemap":
            sitemaps.append(value)
    return {"paths": sorted(set(paths)), "sitemaps": sorted(set(sitemaps))}


async def web_discovery(
    base_url: str,
    paths: list[str] | None = None,
    timeout: int = 10,
    workers: int = 20,
) -> dict[str, Any]:
    """Descobre conteúdo web num alvo HTTP.

    Lê ``robots.txt`` (e seus Disallow como candidatos extras), sonda a wordlist
    e reporta paths cujo status != 404. Retorna dict serializável.
    """
    try:
        import aiohttp
    except ImportError:
        return {"erro": i18n.t("brute.aiohttp_missing")}

    base = _normalize_base(base_url)
    result: dict[str, Any] = {"base": base, "robots": {}, "found": []}

    candidates = list(paths) if paths is not None else list(COMMON_PATHS)
    sem = asyncio.Semaphore(max(1, workers))
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    connector = aiohttp.TCPConnector(limit=workers, ssl=False)
    headers = {"User-Agent": "Mozilla/5.0 gyntoolkit/2.0"}

    async with aiohttp.ClientSession(timeout=timeout_cfg, connector=connector, headers=headers) as session:
        # robots.txt: lê e adiciona Disallow como candidatos.
        try:
            async with session.get(urljoin(base, "robots.txt"), allow_redirects=True) as r:
                if r.status == 200:
                    parsed = _parse_robots(await r.text())
                    result["robots"] = {"found": True, **parsed}
                    for p in parsed["paths"]:
                        cand = p.lstrip("/")
                        if cand and cand not in candidates:
                            candidates.append(cand)
                else:
                    result["robots"] = {"found": False}
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            log.debug("robots.txt %s: %s", base, e)
            result["robots"] = {"found": False}

        async def _probe(path: str) -> dict[str, Any] | None:
            url = urljoin(base, path)
            async with sem:
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status in _INTERESTING:
                            body = await resp.read()
                            return {
                                "path": path,
                                "url": url,
                                "status": resp.status,
                                "length": len(body),
                                "location": resp.headers.get("Location"),
                            }
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    log.debug("probe %s: %s", url, e)
                return None

        probed = await asyncio.gather(*[_probe(p) for p in dict.fromkeys(candidates)])

    result["found"] = sorted(
        (f for f in probed if f),
        key=lambda f: (f["status"], f["path"]),
    )
    result["total"] = len(result["found"])
    return result
