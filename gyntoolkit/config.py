#!/usr/bin/env python3
"""Configuração central via ``.gyntoolkit.yaml`` com fallback nos defaults.

Ordem de resolução do arquivo:
1. Caminho explícito passado a :func:`load_config`.
2. Variável de ambiente ``GYNTOOLKIT_CONFIG``.
3. ``.gyntoolkit.yaml`` no diretório atual.
4. ``.gyntoolkit.yaml`` na raiz do projeto.

Sem arquivo, usa apenas os defaults. Valores do arquivo fazem *deep-merge*
por cima dos defaults, então basta declarar as chaves que quer sobrescrever.
"""

import copy
import os
from pathlib import Path
from typing import Any

from .core import PROJECT_ROOT, log

# Defaults espelham os valores hardcoded originais da CLI.
DEFAULTS: dict[str, Any] = {
    "scan": {
        "default_type": "fast",     # "fast" ou "full"
        "concurrency": 100,         # sondas simultâneas (limita o full scan)
    },
    "brute": {
        "ssh_workers": 8,
        "http_workers": 10,
        "delay": 0.1,
        "ssh_timeout": 5,
        "http_timeout": 10,
        "users_wordlist": "",       # path default sugerido no prompt (opcional)
        "passwords_wordlist": "",   # idem
    },
    "recon": {
        "subdomain_timeout": 30,
        "ssl_timeout": 8,
        "http_timeout": 10,
        "traceroute_max_hops": 20,
        "traceroute_dport": 80,
    },
    "export": {
        "dir": "reports",           # diretório de saída dos relatórios
        "auto": False,              # exportar sem perguntar
        "format": "json",           # formato default quando auto=True: json|html
    },
    "ui": {
        "lang": "auto",             # idioma da UI: auto | en | pt
    },
    "api_keys": {
        "hibp": "",                 # reservado (endpoints atuais são públicos)
        "shodan": "",
        "nvd": "",                  # opcional: eleva o rate-limit do NVD CVE lookup
    },
}

CONFIG_FILENAME = ".gyntoolkit.yaml"


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Merge recursivo de ``override`` sobre ``base`` (não muta os originais)."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _candidate_paths(explicit: str | None) -> list:
    paths = []
    if explicit:
        paths.append(Path(explicit).expanduser())
    env = os.environ.get("GYNTOOLKIT_CONFIG")
    if env:
        paths.append(Path(env).expanduser())
    paths.append(Path.cwd() / CONFIG_FILENAME)
    paths.append(PROJECT_ROOT / CONFIG_FILENAME)
    return paths


def load_config(path: str | None = None) -> dict[str, Any]:
    """Carrega config do primeiro arquivo existente, mesclado sobre os defaults."""
    config_file = next((p for p in _candidate_paths(path) if p.is_file()), None)
    if not config_file:
        return copy.deepcopy(DEFAULTS)

    try:
        import yaml
    except ImportError:
        log.warning("pyyaml não instalado; usando defaults. Rode: pip install pyyaml")
        return copy.deepcopy(DEFAULTS)

    try:
        with config_file.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            log.warning("Config %s não é um mapeamento; usando defaults.", config_file)
            return copy.deepcopy(DEFAULTS)
        merged = _deep_merge(DEFAULTS, data)
        log.info("Config carregada de %s", config_file)
        return merged
    except Exception as e:  # OSError, yaml.YAMLError, etc.
        log.warning("Falha ao ler config %s: %s; usando defaults.", config_file, e)
        return copy.deepcopy(DEFAULTS)


# Config resolvida uma vez na importação; a CLI lê daqui.
CONFIG: dict[str, Any] = load_config()
