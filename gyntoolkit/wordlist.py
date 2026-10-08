#!/usr/bin/env python3
"""Gerador de wordlist nativo (estilo CUPP), offline e sem dependências.

A partir de termos-base (nome, apelido, parceiro, pet, empresa, palavras-chave)
e opcionalmente anos, produz candidatos com transformações comuns: variações de
caixa, leet, concatenações, prefixo/sufixo de anos e de sufixos frequentes.

Substitui o wrapper externo do CUPP (clone sob demanda) para o caso comum.
"""

from itertools import permutations

# Substituições leet aplicadas opcionalmente (cada letra → alternativas).
_LEET = {
    "a": ("4", "@"),
    "e": ("3",),
    "i": ("1", "!"),
    "o": ("0",),
    "s": ("5", "$"),
    "t": ("7",),
}

# Sufixos frequentes anexados aos termos.
_COMMON_SUFFIXES = ("", "1", "12", "123", "1234", "!", "@", "#", "01", "007", "2023", "2024", "2025")

# Separadores usados ao combinar dois termos.
_SEPARATORS = ("", "_", ".", "-")


def _case_variants(word: str) -> set[str]:
    """Variações de caixa de um termo."""
    if not word:
        return set()
    return {word.lower(), word.upper(), word.capitalize()}


def _leet_variants(word: str) -> set[str]:
    """Aplica uma rodada de substituições leet (não combinatória total)."""
    out = {word}
    lower = word.lower()
    for ch, subs in _LEET.items():
        if ch in lower:
            for sub in subs:
                out.add(lower.replace(ch, sub))
    return out


def generate_wordlist(
    terms: list[str],
    years: list[str] | None = None,
    use_leet: bool = False,
    use_special: bool = True,
    combine: bool = True,
    min_len: int = 4,
    max_len: int = 32,
    limit: int = 100_000,
) -> list[str]:
    """Gera uma wordlist a partir de ``terms``.

    :param terms: termos-base (nome, apelido, pet, empresa, ...).
    :param years: anos/números relevantes (ex.: nascimento) anexados aos termos.
    :param use_leet: também gera variações leet (a→4/@, e→3, ...).
    :param use_special: anexa sufixos comuns (123, !, @, anos, ...).
    :param combine: combina pares de termos com separadores.
    :param min_len/max_len: filtro de comprimento.
    :param limit: teto de itens (evita explosão combinatória).
    :return: lista ordenada e deduplicada.
    """
    years = years or []
    clean = [t.strip() for t in terms if t and t.strip()]
    if not clean:
        return []

    base: set[str] = set()
    for t in clean:
        base |= _case_variants(t)
    if combine:
        for a, b in permutations(clean, 2):
            for sep in _SEPARATORS:
                base.add(f"{a}{sep}{b}")
                base.add(f"{a.capitalize()}{sep}{b.capitalize()}")

    candidates: set[str] = set(base)

    # Sufixos: anos sempre; sufixos comuns se use_special.
    suffixes = list(years)
    if use_special:
        suffixes += list(_COMMON_SUFFIXES)
    suffixes = list(dict.fromkeys(suffixes))

    for word in list(base):
        for suf in suffixes:
            if suf:
                candidates.add(f"{word}{suf}")
        for yr in years:
            candidates.add(f"{yr}{word}")

    if use_leet:
        for word in list(candidates):
            candidates |= _leet_variants(word)

    result = sorted(w for w in candidates if min_len <= len(w) <= max_len)
    return result[:limit]
