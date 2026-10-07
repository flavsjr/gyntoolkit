# Development

## Setup

```bash
git clone https://github.com/flavsjr/gyntoolkit.git
cd gyntoolkit
python -m venv .venv
source .venv/bin/activate        # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

Dev extras (`ruff`, `mypy`, `pytest`) are declared in `pyproject.toml` under
`[project.optional-dependencies]`.

## Lint & types

```bash
ruff check .            # lint (rules E, F, W, I, UP, B, SIM)
ruff check . --fix      # autofix
mypy gyntoolkit         # optional type check
```

## Tests

```bash
pytest                  # offline unit tests (utils, config, export)
python lab/run_e2e.py   # end-to-end lab suite (local mocks)
```

Unit tests must **not** depend on the network, external services, or real targets.

## Package layout

```
gyntoolkit/
├── __init__.py   re-exports the public API
├── __main__.py   enables `python -m gyntoolkit`
├── core.py       constants, logging, terminal/menu helpers
├── scan.py       port scan, banner, CVE lookup, host discovery
├── recon.py      WHOIS, DNS, geo, TLS, fingerprint, breaches, traceroute
├── brute.py      ethical warning, wordlists, CUPP, SSH & HTTP brute
├── utils.py      hash, base64, JWT decode
├── config.py     .gyntoolkit.yaml loader (deep-merge over defaults)
├── export.py     JSON + HTML report export
├── ui.py         rich layer with colorama fallback
└── cli.py        interactive flow + entry point (main_entry)
```

## CI

Two GitHub Actions workflows run on every push/PR:

- `.github/workflows/tests.yml` — unit tests (Python 3.10–3.13) + e2e lab.
- `.github/workflows/lint.yml` — `ruff check`.

## Releasing

1. Update `CHANGELOG.md`.
2. Bump `version` in `pyproject.toml` and `gyntoolkit/__init__.py` (keep in sync).
3. Tag: `git tag v2.0.0 && git push --tags`.
4. Build & publish (maintainer): see [installation.md](installation.md#maintainer-publishing-to-pypi).
5. Create a GitHub Release from the tag.
