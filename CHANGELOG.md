# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- i18n: interactive menus in English or Portuguese via `gyntoolkit/i18n.py`
  (dict catalog). Language resolves from `ui.lang` config → `GYNTOOLKIT_LANG`
  env → OS locale → English default. Menu strings translated (phase 1).
- English `README.md` (primary) with `README.pt-BR.md` kept in Portuguese.
- `docs/` guides: installation, quickstart, reconnaissance, scanning, reports,
  configuration, security-lab, development.
- Unit test suite (`tests/`) for utils, config and exporters (offline).
- GitHub Actions CI: `tests.yml` (unit matrix + e2e lab) and `lint.yml` (ruff).
- Community health files: `SECURITY.md`, `CODE_OF_CONDUCT.md`, PR template,
  security issue template, Dependabot config, repository settings guide.
- PyPI-ready packaging metadata and `demo.tape` for the demo GIF.

## [2.0.0] - 2025

### Added
- Package split from the original monolith into `core`, `scan`, `recon`,
  `brute`, `utils`, `config`, `export`, `ui`, `cli` — run with `python -m gyntoolkit`.
- Advanced recon: subdomain enum (crt.sh), SSL/TLS inspector, HTTP fingerprint,
  InternetDB (Shodan free), HIBP breach check, MAC vendor lookup, TCP traceroute.
- Advanced scanning: SYN/connect port scan, banner grabbing, CVE lookup via
  NVD API v2.0, ARP host discovery.
- Brute force: SSH (`paramiko`), HTTP Basic/Form (`aiohttp`), CUPP wordlist wrapper.
- Utilities: text/file hashing, base64, JWT decode.
- `rich` UI with `colorama` fallback.
- JSON and dark-themed HTML report export.
- `.gyntoolkit.yaml` configuration with deep-merge over defaults.
- Local security lab (mock SSH/HTTP servers) with an end-to-end runner.

[Unreleased]: https://github.com/flavsjr/gyntoolkit/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/flavsjr/gyntoolkit/releases/tag/v2.0.0
