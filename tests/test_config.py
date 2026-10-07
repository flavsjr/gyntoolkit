"""Testes unitários do loader de config (offline, sem rede)."""
import textwrap

from gyntoolkit import config


def test_load_config_defaults_without_file(tmp_path, monkeypatch):
    monkeypatch.delenv("GYNTOOLKIT_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)  # sem .gyntoolkit.yaml aqui
    cfg = config.load_config()
    assert cfg["scan"]["default_type"] == config.DEFAULTS["scan"]["default_type"]
    assert cfg["brute"]["ssh_workers"] == config.DEFAULTS["brute"]["ssh_workers"]


def test_deep_merge_overrides_only_given_keys():
    merged = config._deep_merge(
        config.DEFAULTS, {"brute": {"ssh_workers": 99}}
    )
    assert merged["brute"]["ssh_workers"] == 99
    # chaves não sobrescritas mantêm o default
    assert merged["brute"]["http_workers"] == config.DEFAULTS["brute"]["http_workers"]
    assert merged["scan"]["default_type"] == config.DEFAULTS["scan"]["default_type"]


def test_deep_merge_does_not_mutate_base():
    before = config.DEFAULTS["brute"]["ssh_workers"]
    config._deep_merge(config.DEFAULTS, {"brute": {"ssh_workers": 1}})
    assert config.DEFAULTS["brute"]["ssh_workers"] == before


def test_load_config_from_explicit_file(tmp_path):
    f = tmp_path / "custom.yaml"
    f.write_text(
        textwrap.dedent(
            """
            brute:
              ssh_workers: 3
            export:
              auto: true
            """
        ),
        encoding="utf-8",
    )
    cfg = config.load_config(str(f))
    assert cfg["brute"]["ssh_workers"] == 3
    assert cfg["export"]["auto"] is True
    # resto segue default
    assert cfg["export"]["format"] == config.DEFAULTS["export"]["format"]
