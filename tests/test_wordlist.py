"""Testes do gerador de wordlist nativo (offline)."""
from gyntoolkit import commands
from gyntoolkit.wordlist import generate_wordlist


def test_empty_terms_returns_empty():
    assert generate_wordlist([]) == []
    assert generate_wordlist(["", "  "]) == []


def test_case_variants_present():
    out = generate_wordlist(["alice"], use_special=False, combine=False)
    assert "alice" in out
    assert "Alice" in out
    assert "ALICE" in out


def test_years_appended_and_prepended():
    out = generate_wordlist(["alice"], years=["1990"], use_special=False, combine=False)
    assert "alice1990" in out
    assert "1990alice" in out


def test_special_suffixes():
    out = generate_wordlist(["alice"], use_special=True, combine=False)
    assert "alice123" in out
    assert "alice!" in out


def test_leet_variants():
    out = generate_wordlist(["alice"], use_leet=True, use_special=False, combine=False)
    # 'a'->4/@, 'i'->1/!, 'e'->3
    assert any("4" in w or "@" in w for w in out)


def test_length_filter():
    out = generate_wordlist(["bob"], min_len=5, max_len=8, use_special=True, combine=False)
    assert all(5 <= len(w) <= 8 for w in out)


def test_combine_pairs():
    out = generate_wordlist(["alice", "bob"], use_special=False, combine=True, min_len=1)
    assert "alice_bob" in out or "alicebob" in out


def test_result_sorted_and_deduped():
    out = generate_wordlist(["alice", "alice"], use_special=False, combine=False)
    assert out == sorted(set(out))


def test_cli_wordlist_prints_lines(capsys):
    rc = commands.run(["wordlist", "--terms", "alice", "--no-special", "--no-combine"])
    assert rc == 0
    lines = capsys.readouterr().out.splitlines()
    assert "alice" in lines
    assert "Alice" in lines


def test_cli_wordlist_requires_terms(capsys):
    rc = commands.run(["wordlist", "--terms", ""])
    assert rc == 2


def test_cli_wordlist_save(tmp_path, capsys):
    f = tmp_path / "wl.txt"
    rc = commands.run(["wordlist", "--terms", "alice", "--save", str(f), "-q"])
    assert rc == 0
    assert capsys.readouterr().out == ""        # -q suprime stdout
    assert "alice" in f.read_text(encoding="utf-8").splitlines()
