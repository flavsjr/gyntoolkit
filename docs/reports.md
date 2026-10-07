# Reports

After scans and recon lookups the CLI offers to export the result.

## Formats

- **JSON** — valid UTF-8, indented, `ensure_ascii=False`. Stable and easy to
  consume for automation.
- **HTML** — dark-themed, self-contained report (inline CSS). Nested dicts/lists
  render as tables/lists; all values are HTML-escaped.

## Location & naming

Files are written to:

```
reports/<module>-<timestamp>.<fmt>
```

- `<timestamp>` format: `YYYYMMDD-HHMMSS`.
- The base name is slugified (unsafe characters → `_`).
- The output directory defaults to `reports/` and is configurable.

## Configuration

In `.gyntoolkit.yaml`:

```yaml
export:
  dir: reports      # output directory
  auto: false       # true = export without prompting
  format: json      # default format when auto=true: json | html
```

See [configuration.md](configuration.md).

## Programmatic use

```python
from gyntoolkit import export

export.export_json({"target": "127.0.0.1", "ports": [22, 80]}, "out.json")
export.export_html({"target": "127.0.0.1"}, "Scan report", "out.html")
export.save_report(data, "scan-127.0.0.1", fmt="html", out_dir="reports", title="Scan")
```

The JSON contract is intentionally stable — avoid breaking it for downstream
automation.
