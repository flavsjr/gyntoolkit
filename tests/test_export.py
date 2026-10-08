"""Testes unitários dos exporters JSON/HTML (offline, sem rede)."""
import json
from pathlib import Path

from gyntoolkit import export


def test_export_json_valid_and_utf8(tmp_path):
    data = {"target": "127.0.0.1", "ports": [22, 80], "nota": "serviço"}
    path = export.export_json(data, str(tmp_path / "r.json"))
    loaded = json.loads(Path(path).read_text(encoding="utf-8"))
    assert loaded == data


def test_export_html_escapes_and_contains_values(tmp_path):
    data = {"xss": "<script>alert(1)</script>", "port": 443}
    path = export.export_html(data, "Report <b>", str(tmp_path / "r.html"))
    doc = Path(path).read_text(encoding="utf-8")
    assert "<!doctype html>" in doc.lower()
    assert "&lt;script&gt;" in doc           # escapado
    assert "<script>alert(1)</script>" not in doc
    assert "443" in doc


def test_save_report_json_naming(tmp_path):
    path = export.save_report({"a": 1}, "scan/../weird name", fmt="json", out_dir=str(tmp_path))
    assert path.endswith(".json")
    # slug remove separadores perigosos do basename
    assert "/" not in Path(path).name
    assert json.loads(Path(path).read_text(encoding="utf-8")) == {"a": 1}


def test_save_report_unknown_format_falls_back_to_json(tmp_path):
    path = export.save_report({"a": 1}, "x", fmt="xml", out_dir=str(tmp_path))
    assert path.endswith(".json")


def test_save_report_html(tmp_path):
    path = export.save_report({"a": 1}, "x", fmt="html", out_dir=str(tmp_path), title="T")
    assert path.endswith(".html")
    assert "<h1>" in Path(path).read_text(encoding="utf-8")


def test_export_csv_list_of_dicts(tmp_path):
    data = [
        {"name": "A", "date": "2020", "classes": ["Email", "Password"]},
        {"name": "B", "date": "2021"},
    ]
    path = export.export_csv(data, str(tmp_path / "r.csv"))
    rows = Path(path).read_text(encoding="utf-8").splitlines()
    assert rows[0] == "name,date,classes"
    # lista vira célula "a; b"; coluna ausente fica vazia
    assert "A,2020,Email; Password" in rows[1]
    assert rows[2].startswith("B,2021,")


def test_export_csv_flat_dict(tmp_path):
    path = export.export_csv({"ip": "1.1.1.1", "ports": [80, 443]}, str(tmp_path / "r.csv"))
    text = Path(path).read_text(encoding="utf-8")
    assert "field,value" in text
    assert "ports,80; 443" in text


def test_save_report_md(tmp_path):
    path = export.save_report({"host": "x", "open": [22]}, "scan", fmt="md",
                              out_dir=str(tmp_path), title="Scan X")
    assert path.endswith(".md")
    doc = Path(path).read_text(encoding="utf-8")
    assert doc.startswith("# Scan X")
    assert "**host**" in doc


def test_save_report_csv(tmp_path):
    path = export.save_report({"a": 1}, "x", fmt="csv", out_dir=str(tmp_path))
    assert path.endswith(".csv")
    assert "field,value" in Path(path).read_text(encoding="utf-8")
