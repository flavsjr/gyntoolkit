"""Testes unitários do i18n (offline, sem rede)."""
import pytest

from gyntoolkit import i18n


@pytest.fixture(autouse=True)
def _reset_lang():
    before = i18n.get_lang()
    yield
    i18n.set_lang(before)


def test_default_lang_is_en():
    assert i18n.DEFAULT_LANG == "en"


def test_set_and_get_lang():
    assert i18n.set_lang("pt") == "pt"
    assert i18n.get_lang() == "pt"
    assert i18n.t("menu.main.title") == "Menu Principal:"
    i18n.set_lang("en")
    assert i18n.t("menu.main.title") == "Main Menu:"


def test_set_lang_normalizes_and_falls_back():
    assert i18n.set_lang("pt_BR.UTF-8") == "pt"
    assert i18n.set_lang("en-US") == "en"
    assert i18n.set_lang("xx") == "en"      # não suportado → default
    assert i18n.set_lang(None) == "en"


def test_t_missing_key_returns_key():
    i18n.set_lang("pt")
    assert i18n.t("does.not.exist") == "does.not.exist"


def test_t_falls_back_to_default_lang_when_key_absent_in_current(monkeypatch):
    # chave só no inglês → idioma atual pt cai no en
    monkeypatch.setitem(i18n.MESSAGES["en"], "only.en", "only english")
    i18n.set_lang("pt")
    assert i18n.t("only.en") == "only english"


def test_t_format_kwargs():
    monkeypatch_key = "fmt.sample"
    i18n.MESSAGES["en"][monkeypatch_key] = "found {n} hosts"
    try:
        i18n.set_lang("en")
        assert i18n.t(monkeypatch_key, n=3) == "found 3 hosts"
    finally:
        i18n.MESSAGES["en"].pop(monkeypatch_key, None)


def test_resolve_lang_config_wins(monkeypatch):
    monkeypatch.delenv("GYNTOOLKIT_LANG", raising=False)
    assert i18n.resolve_lang("pt") == "pt"
    assert i18n.resolve_lang("en") == "en"


def test_resolve_lang_auto_uses_env(monkeypatch):
    monkeypatch.setenv("GYNTOOLKIT_LANG", "pt")
    assert i18n.resolve_lang("auto") == "pt"
    assert i18n.resolve_lang(None) == "pt"


def test_resolve_lang_env_invalid_falls_through(monkeypatch):
    monkeypatch.setenv("GYNTOOLKIT_LANG", "zz")
    # env inválido ignorado; sem locale detectável vira default en
    monkeypatch.setattr(i18n, "_from_locale", lambda: None)
    assert i18n.resolve_lang("auto") == "en"
