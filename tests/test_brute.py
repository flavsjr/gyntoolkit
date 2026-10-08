"""Testes offline de brute.py (confirmação ética; sem rede/alvo real)."""
import builtins

from gyntoolkit import brute, i18n


def _confirm_with(monkeypatch, typed: str) -> bool:
    monkeypatch.setattr(builtins, "input", lambda *a, **k: typed)
    return brute.print_ethical_warning("test")


def test_confirm_accepts_localized_word_en(monkeypatch):
    i18n.set_lang("en")
    try:
        assert _confirm_with(monkeypatch, "AUTHORIZE") is True
        assert _confirm_with(monkeypatch, "authorize") is True  # case-insensitive
    finally:
        i18n.set_lang("en")


def test_confirm_accepts_legacy_autorizo_alias(monkeypatch):
    i18n.set_lang("en")
    # "AUTORIZO" (pt legado) segue válido mesmo com UI em inglês.
    assert _confirm_with(monkeypatch, "AUTORIZO") is True


def test_confirm_rejects_other(monkeypatch):
    i18n.set_lang("en")
    assert _confirm_with(monkeypatch, "yes") is False
    assert _confirm_with(monkeypatch, "") is False
