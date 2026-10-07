#!/usr/bin/env python3
"""Internacionalização (i18n) leve por catálogo de dicionário.

Sem dependências externas e sem etapa de build (.mo). Resolução do idioma:

1. ``ui.lang`` do ``.gyntoolkit.yaml`` (quando diferente de ``auto``).
2. Variável de ambiente ``GYNTOOLKIT_LANG``.
3. Locale do SO (``locale.getlocale`` / ``$LANG``).
4. Fallback para :data:`DEFAULT_LANG` (``en``).

Uso::

    from . import i18n
    i18n.set_lang(i18n.resolve_lang(CONFIG["ui"]["lang"]))
    print(i18n.t("menu.main.title"))
    print(i18n.t("scan.hosts_found", n=3))
"""

import locale
import os

DEFAULT_LANG = "en"
SUPPORTED: tuple[str, ...] = ("en", "pt")

# Catálogo de mensagens. Chave namespaceada → string por idioma.
# Interpolação via str.format: use {name} e passe t(key, name=...).
MESSAGES: dict[str, dict[str, str]] = {
    "en": {
        # menu principal
        "menu.main.title": "Main Menu:",
        "menu.main.info": "Information Gathering",
        "menu.main.brute": "Brute Force",
        "menu.main.scan": "Advanced Scanning",
        "menu.main.utils": "Utilities",
        # submenu: information gathering
        "menu.info.title": "Information Gathering:",
        "menu.info.whois": "WHOIS Lookup",
        "menu.info.dns": "DNS Lookup",
        "menu.info.geo": "IP Geolocation",
        "menu.info.revdns": "Reverse DNS (PTR)",
        "menu.info.subenum": "Subdomain Enum (crt.sh)",
        "menu.info.ssl": "SSL/TLS Cert Inspector",
        "menu.info.httpfp": "HTTP Fingerprint",
        "menu.info.internetdb": "InternetDB (Shodan free)",
        "menu.info.hibp": "HIBP Breach Check",
        "menu.info.macvendor": "MAC Vendor Lookup",
        "menu.info.traceroute": "Traceroute (TCP)",
        # submenu: brute force
        "menu.brute.title": "Brute Force:",
        "menu.brute.cupp": "Generate Wordlist (CUPP)",
        "menu.brute.ssh": "SSH Attack",
        "menu.brute.http": "HTTP Attack",
        # submenu: utilities
        "menu.utils.title": "Utilities:",
        "menu.utils.hashtext": "Text hash (MD5/SHA1/SHA256/SHA512)",
        "menu.utils.hashfile": "File hash",
        "menu.utils.b64enc": "Base64 encode",
        "menu.utils.b64dec": "Base64 decode",
        "menu.utils.jwt": "JWT decode (no signature check)",
        # brute force (runtime)
        "brute.progress": "[{tried}/{total}] attempts...",
        "brute.ssh_valid": "[+] SSH valid: {user}:{pwd}",
        "brute.http_valid": "[+] HTTP valid: {user}:{pwd}",
        # comuns / framing
        "common.back_exit": "Back/Exit",
        "common.invalid_option": "Invalid option! Try again.",
        "common.press_enter": "Press Enter to continue...",
        "common.exiting": "Exiting...",
        "common.interrupted": "Interrupted by user.",
        # avisos de privilégio
        "warn.need_root": "Warning: advanced features require root!",
        "warn.need_admin": "Warning: advanced features require administrator!",
    },
    "pt": {
        # menu principal
        "menu.main.title": "Menu Principal:",
        "menu.main.info": "Obter Informações",
        "menu.main.brute": "Brute Force",
        "menu.main.scan": "Varredura Avançada",
        "menu.main.utils": "Utilitários",
        # submenu: obter informações
        "menu.info.title": "Obter Informações:",
        "menu.info.whois": "Consulta WHOIS",
        "menu.info.dns": "DNS Lookup",
        "menu.info.geo": "Geolocalização IP",
        "menu.info.revdns": "Reverse DNS (PTR)",
        "menu.info.subenum": "Subdomain Enum (crt.sh)",
        "menu.info.ssl": "SSL/TLS Cert Inspector",
        "menu.info.httpfp": "HTTP Fingerprint",
        "menu.info.internetdb": "InternetDB (Shodan free)",
        "menu.info.hibp": "HIBP Breach Check",
        "menu.info.macvendor": "MAC Vendor Lookup",
        "menu.info.traceroute": "Traceroute (TCP)",
        # submenu: brute force
        "menu.brute.title": "Brute Force:",
        "menu.brute.cupp": "Gerar Wordlist (CUPP)",
        "menu.brute.ssh": "Ataque SSH",
        "menu.brute.http": "Ataque HTTP",
        # submenu: utilitários
        "menu.utils.title": "Utilitários:",
        "menu.utils.hashtext": "Hash de texto (MD5/SHA1/SHA256/SHA512)",
        "menu.utils.hashfile": "Hash de arquivo",
        "menu.utils.b64enc": "Base64 encode",
        "menu.utils.b64dec": "Base64 decode",
        "menu.utils.jwt": "JWT decode (sem verificar assinatura)",
        # brute force (runtime)
        "brute.progress": "[{tried}/{total}] tentativas...",
        "brute.ssh_valid": "[+] SSH válido: {user}:{pwd}",
        "brute.http_valid": "[+] HTTP válido: {user}:{pwd}",
        # comuns / framing
        "common.back_exit": "Voltar/Sair",
        "common.invalid_option": "Opção inválida! Tente novamente.",
        "common.press_enter": "Pressione Enter para continuar...",
        "common.exiting": "Saindo...",
        "common.interrupted": "Interrompido pelo usuário.",
        # avisos de privilégio
        "warn.need_root": "Aviso: Funcionalidades avançadas requerem root!",
        "warn.need_admin": "Aviso: Funcionalidades avançadas requerem administrador!",
    },
}

_current_lang = DEFAULT_LANG


def _normalize(value: str | None) -> str | None:
    """Reduz 'pt_BR.UTF-8' / 'en-US' → 'pt' / 'en' se suportado, senão None."""
    if not value:
        return None
    code = value.strip().lower().replace("-", "_").split("_", 1)[0]
    return code if code in SUPPORTED else None


def _from_locale() -> str | None:
    for getter in (lambda: locale.getlocale()[0], locale.getdefaultlocale):
        try:
            code = _normalize(getter()[0] if getter is locale.getdefaultlocale else getter())
        except (ValueError, IndexError, TypeError):
            code = None
        if code:
            return code
    for env_var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        code = _normalize(os.environ.get(env_var))
        if code:
            return code
    return None


def resolve_lang(config_lang: str | None = None) -> str:
    """Resolve o idioma efetivo seguindo a ordem de precedência documentada."""
    cfg = _normalize(config_lang)
    if cfg and (config_lang or "").strip().lower() != "auto":
        return cfg
    env = _normalize(os.environ.get("GYNTOOLKIT_LANG"))
    if env:
        return env
    loc = _from_locale()
    if loc:
        return loc
    return DEFAULT_LANG


def set_lang(lang: str | None) -> str:
    """Define o idioma atual (normalizado). Retorna o idioma efetivo."""
    global _current_lang
    _current_lang = _normalize(lang) or DEFAULT_LANG
    return _current_lang


def get_lang() -> str:
    return _current_lang


def t(key: str, **kwargs: object) -> str:
    """Traduz ``key`` no idioma atual.

    Fallback: idioma atual → :data:`DEFAULT_LANG` → a própria chave.
    ``kwargs`` são aplicados via :meth:`str.format`.
    """
    msg = MESSAGES.get(_current_lang, {}).get(key)
    if msg is None:
        msg = MESSAGES.get(DEFAULT_LANG, {}).get(key, key)
    if kwargs:
        try:
            return msg.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            return msg
    return msg
