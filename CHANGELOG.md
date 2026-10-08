# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.1.1] - 2026-10-07

### Added
- Automated PyPI publishing: `.github/workflows/publish.yml` builds and uploads
  on a GitHub Release using Trusted Publishing (OIDC) — no stored secrets.
- First release available via `pip install gyntoolkit`.

### Changed
- HTML export report is now localized (en/pt) and uses the dynamic package
  version and `<html lang>` instead of hardcoded Portuguese and a stale "v2.0".
- Internal scan values are language-neutral tokens (`fast`/`full`, `high`/`low`,
  `unknown`); the UI still localizes them via i18n. Legacy config input is
  still accepted.
- Docs lead with `pip install gyntoolkit`; source checkout kept for development.

### Removed
- Stopped vendoring third-party CUPP; it is cloned on demand. Removed dead
  Portuguese DNS-type descriptions (display comes from i18n).

## [2.1.0] - 2026-10-07

### Fixed
- Scan service detection: empty banners now map to the "unknown" service
  (skips a spurious NVD lookup) instead of parsing a localized placeholder word.

### Added
- i18n: full interactive UI in English or Portuguese via `gyntoolkit/i18n.py`
  (dict catalog). Language resolves from `ui.lang` config → `GYNTOOLKIT_LANG`
  env → OS locale → English default. Translated: menus, prompts, status
  spinners, result labels, table headers, and error messages across cli/recon/
  scan/brute/utils. Data values and JSON export keys stay stable. A test enforces
  en/pt key parity.
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

[Unreleased]: https://github.com/flavsjr/gyntoolkit/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/flavsjr/gyntoolkit/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/flavsjr/gyntoolkit/releases/tag/v2.0.0
