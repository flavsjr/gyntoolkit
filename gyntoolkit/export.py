#!/usr/bin/env python3
"""Exportação de resultados: JSON e relatório HTML (tema dark)."""

import csv
import html
import io
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from . import i18n
from .core import log


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _slug(name: str) -> str:
    """Basename seguro para nome de arquivo."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip()) or "report"
    return name.strip("_.") or "report"


def _ensure_dir(out_dir: str) -> Path:
    d = Path(out_dir).expanduser()
    d.mkdir(parents=True, exist_ok=True)
    return d


def export_json(data: Any, path: str) -> str:
    """Serializa ``data`` como JSON indentado (UTF-8). Retorna o path escrito."""
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    return str(p)


def _flatten_scalar(value: Any) -> str:
    """Converte um valor em célula de texto plano (listas viram 'a; b; c')."""
    if isinstance(value, (list, tuple)):
        return "; ".join(_flatten_scalar(v) for v in value)
    if isinstance(value, dict):
        return "; ".join(f"{k}={_flatten_scalar(v)}" for k, v in value.items())
    if value is None:
        return ""
    return str(value)


def export_csv(data: Any, path: str) -> str:
    """Serializa ``data`` como CSV. Retorna o path escrito.

    - lista de dicts → uma linha por item, colunas = união das chaves;
    - dict plano → duas colunas (campo, valor);
    - outros → coluna única ``value``.
    """
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    buf = io.StringIO()

    if isinstance(data, list) and data and all(isinstance(r, dict) for r in data):
        fields: list[str] = []
        for row in data:
            for k in row:
                if k not in fields:
                    fields.append(k)
        dict_writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
        dict_writer.writeheader()
        for row in data:
            dict_writer.writerow({k: _flatten_scalar(row.get(k)) for k in fields})
    else:
        writer = csv.writer(buf)
        if isinstance(data, dict):
            writer.writerow(["field", "value"])
            for k, v in data.items():
                writer.writerow([k, _flatten_scalar(v)])
        else:
            writer.writerow(["value"])
            for item in (data if isinstance(data, (list, tuple)) else [data]):
                writer.writerow([_flatten_scalar(item)])

    with p.open("w", encoding="utf-8", newline="") as f:
        f.write(buf.getvalue())
    return str(p)


def _render_md_value(value: Any, depth: int = 0) -> str:
    """Renderiza recursivamente um valor como Markdown."""
    pad = "  " * depth
    if isinstance(value, dict):
        if not value:
            return "_{}_"
        lines = [f"\n{pad}- **{k}**: {_render_md_value(v, depth + 1)}" for k, v in value.items()]
        return "".join(lines)
    if isinstance(value, (list, tuple)):
        if not value:
            return "_[]_"
        return "".join(f"\n{pad}- {_render_md_value(v, depth + 1)}" for v in value)
    if value is None:
        return "—"
    return str(value).replace("\n", " ")


def export_md(data: Any, title: str, path: str) -> str:
    """Renderiza ``data`` em relatório Markdown. Retorna o path escrito."""
    from . import __version__

    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    doc = (
        f"# {title}\n\n"
        f"> {i18n.t('report.generated_by', version=f'v{__version__}')} · {generated}\n\n"
        f"{_render_md_value(data).lstrip()}\n\n"
        f"---\n_{i18n.t('report.footer')}_\n"
    )
    with p.open("w", encoding="utf-8") as f:
        f.write(doc)
    return str(p)


def _render_html_value(value: Any) -> str:
    """Renderiza recursivamente um valor como fragmento HTML seguro."""
    if isinstance(value, dict):
        if not value:
            return "<span class='muted'>{}</span>"
        rows = "".join(
            f"<tr><th>{html.escape(str(k))}</th><td>{_render_html_value(v)}</td></tr>"
            for k, v in value.items()
        )
        return f"<table>{rows}</table>"
    if isinstance(value, (list, tuple)):
        if not value:
            return "<span class='muted'>[]</span>"
        items = "".join(f"<li>{_render_html_value(v)}</li>" for v in value)
        return f"<ul>{items}</ul>"
    if value is None:
        return "<span class='muted'>—</span>"
    return html.escape(str(value))


_HTML_TEMPLATE = """<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{
    background:#0d0f0d; color:#c8ffc8; margin:0; padding:24px;
    font-family: "JetBrains Mono", "Consolas", ui-monospace, monospace;
    font-size:14px; line-height:1.5;
  }}
  h1 {{ color:#00ff5f; border-bottom:1px solid #143f14; padding-bottom:8px; font-size:20px; }}
  .meta {{ color:#6fbf6f; margin-bottom:20px; font-size:12px; }}
  table {{ border-collapse:collapse; width:100%; margin:4px 0; }}
  th, td {{ border:1px solid #143f14; padding:6px 10px; text-align:left; vertical-align:top; }}
  th {{ color:#ffd700; background:#111511; white-space:nowrap; width:1%; }}
  ul {{ margin:4px 0; padding-left:20px; }}
  li {{ margin:2px 0; }}
  .muted {{ color:#4d6b4d; }}
  footer {{ margin-top:24px; color:#4d6b4d; font-size:12px; border-top:1px solid #143f14; padding-top:8px; }}
  a {{ color:#00ff5f; }}
</style>
</head>
<body>
  <h1>{title}</h1>
  <div class="meta">{generated_by} &middot; {generated}</div>
  {body}
  <footer>{footer}</footer>
</body>
</html>
"""


def export_html(data: Any, title: str, path: str) -> str:
    """Renderiza ``data`` em relatório HTML dark. Retorna o path escrito."""
    from . import __version__

    body = _render_html_value(data)
    lang = "pt-br" if i18n.get_lang() == "pt" else "en"
    doc = _HTML_TEMPLATE.format(
        lang=lang,
        title=html.escape(title),
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        generated_by=html.escape(i18n.t("report.generated_by", version=f"v{__version__}")),
        footer=html.escape(i18n.t("report.footer")),
        body=body,
    )
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        f.write(doc)
    return str(p)


def save_report(
    data: Any,
    basename: str,
    fmt: str = "json",
    out_dir: str = "reports",
    title: str | None = None,
) -> str:
    """Grava ``data`` em ``out_dir/<basename>-<timestamp>.<fmt>``.

    ``fmt`` aceita ``json``, ``html``, ``csv`` ou ``md``. Retorna o path escrito.
    """
    fmt = (fmt or "json").lower().strip()
    d = _ensure_dir(out_dir)
    filename = f"{_slug(basename)}-{_timestamp()}.{fmt}"
    path = str(d / filename)

    if fmt == "html":
        return export_html(data, title or basename, path)
    if fmt == "csv":
        return export_csv(data, path)
    if fmt == "md":
        return export_md(data, title or basename, path)
    if fmt == "json":
        return export_json(data, path)

    log.warning("Formato de export desconhecido '%s'; usando json.", fmt)
    path = str(d / f"{_slug(basename)}-{_timestamp()}.json")
    return export_json(data, path)
