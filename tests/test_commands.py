"""Testes da CLI não-interativa (offline: só utils + parsing)."""
import json

import pytest

from gyntoolkit import commands


def test_no_subcommand_signals_interactive():
    # Sem subcomando, run() devolve -1 → chamador abre o menu interativo.
    assert commands.run([]) == -1


def test_utils_hash_prints_json(capsys):
    rc = commands.run(["utils", "hash", "abc", "--algo", "sha256"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["algo"] == "sha256"
    assert out["hash"] == __import__("hashlib").sha256(b"abc").hexdigest()


def test_utils_b64_roundtrip_via_cli(capsys):
    commands.run(["utils", "b64enc", "hello"])
    enc = json.loads(capsys.readouterr().out)["b64"]
    commands.run(["utils", "b64dec", enc])
    assert json.loads(capsys.readouterr().out)["decoded"] == "hello"


def test_quiet_suppresses_stdout(capsys):
    commands.run(["utils", "hash", "abc", "-q"])
    assert capsys.readouterr().out == ""


def test_output_saves_report(tmp_path, capsys):
    rc = commands.run(["utils", "hash", "abc", "-o", str(tmp_path), "-f", "md", "-q"])
    assert rc == 0
    files = list(tmp_path.glob("*.md"))
    assert len(files) == 1
    assert files[0].read_text(encoding="utf-8").startswith("# Hash")


def test_brute_requires_authorize(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("x\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        commands.run(["brute", "ssh", "127.0.0.1", "--users", "root",
                      "--passwords", str(wl)])
    assert exc.value.code == 2  # sem --authorize, aborta


def test_parser_builds():
    p = commands.build_parser()
    ns = p.parse_args(["scan", "127.0.0.1", "--type", "full"])
    assert ns.group == "scan"
    assert ns.target == "127.0.0.1"
    assert ns.type == "full"
