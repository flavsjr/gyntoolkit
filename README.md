# GynToolkit

**🌐 Language / Idioma:** **English** · [Português (BR)](README.pt-BR.md)

```
 ██████╗██╗   ██╗███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝╚██╗ ██╔╝████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
██║  ███╗╚████╔╝ ██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║
██║   ██║ ╚██╔╝  ██║╚██╗██║       ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   v2.0
╚██████╔╝  ██║   ██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   by: PH,Fl4vs
 ╚═════╝   ╚═╝   ╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝
```

> All-in-one Python security toolkit for reconnaissance, network scanning,
> vulnerability analysis and **authorized** penetration testing — in a single
> dark-themed interactive CLI (`gyntoolkit:~#`).

[![CI](https://github.com/flavsjr/gyntoolkit/actions/workflows/tests.yml/badge.svg)](https://github.com/flavsjr/gyntoolkit/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/gyntoolkit.svg?style=flat-square&color=00ff00&labelColor=1a1a1a&logo=pypi&logoColor=white)](https://pypi.org/project/gyntoolkit/)
![Python](https://img.shields.io/badge/python-3.10+-00ff00.svg?style=flat-square&logo=python&logoColor=white&labelColor=1a1a1a)
![License](https://img.shields.io/badge/license-MIT-00ff00.svg?style=flat-square&labelColor=1a1a1a)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20MacOS-1a1a1a.svg?style=flat-square)
![Purpose](https://img.shields.io/badge/purpose-pentest%20%7C%20recon-red.svg?style=flat-square&labelColor=1a1a1a)

<!-- Demo: generate the GIF with `vhs demo.tape` (see demo.tape at the repo root). -->
![GynToolkit Demo](docs/demo.gif)

> `[!] WARNING:` Use **only** against targets you are **authorized in writing** to test.
> Unauthorized use is a crime — Lei 12.737/12 (BR), CFAA (US) and equivalents.

---

## Table of Contents

- [Why GynToolkit?](#why-gyntoolkit)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Example](#example)
- [Security Lab](#security-lab)
- [Reports](#reports)
- [Configuration](#configuration)
- [Documentation](#documentation)
- [Development](#development)
- [Testing](#testing)
- [Contributing](#contributing)
- [Security](#security)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Why GynToolkit?

- **One CLI, many tools** — recon, port scanning, TLS/HTTP fingerprinting, CVE
  lookup and SSH/HTTP auth testing, without juggling a dozen separate commands.
- **Safe to try** — ships with a local lab (`127.0.0.1`) and an end-to-end runner,
  so you can exercise every brute-force module without touching a real target.
- **Readable output** — `rich` tables/panels when available, graceful fallback to
  plain colored text; export any result to JSON or a dark-themed HTML report.
- **Authorization-first** — every attack module requires explicit confirmation.
- **Zero mandatory API keys** — recon sources used (crt.sh, ip-api, InternetDB,
  HIBP, NVD) work on their public/free tiers.

---

## Features

### `[1]` Information Gathering — passive & active recon

| # | Module | Source / technique |
|---|--------|--------------------|
| 1 | **WHOIS** | `python-whois` — registrar, dates, contacts |
| 2 | **DNS Lookup** | `dnspython` — A, AAAA, MX, NS, CNAME, TXT, SOA |
| 3 | **IP Geolocation** | `ip-api.com` (free) — country, ISP, ASN, proxy/hosting flags |
| 4 | **Reverse DNS (PTR)** | `socket.gethostbyaddr` |
| 5 | **Subdomain Enum** | Certificate Transparency via `crt.sh` |
| 6 | **SSL/TLS Cert Inspector** | `cryptography` — subject, issuer, SANs, expiry, cipher, SHA-256 |
| 7 | **HTTP Fingerprint** | nginx, Apache, IIS, Cloudflare, PHP, WordPress, Laravel, ASP.NET, Django, Rails, Node |
| 8 | **InternetDB (Shodan free)** | Open ports, CPEs, known CVEs — no API key |
| 9 | **HIBP Breach Check** | Domain → known breaches via Have I Been Pwned |
| 10 | **MAC Vendor Lookup** | `api.macvendors.com` — OUI → vendor |
| 11 | **Traceroute (TCP)** | `scapy` — hops + RTT (needs privilege) |

### `[2]` Brute Force

| # | Module | Details |
|---|--------|---------|
| 1 | **CUPP wordlist** | Wrapper for `cupp.py -i` — custom wordlist generator |
| 2 | **SSH brute** | `paramiko`, async via `asyncio.to_thread`, concurrency `Semaphore`, delay |
| 3 | **HTTP brute** | `aiohttp` — Basic Auth or form POST with configurable `fail_signature` |

> Every attack requires typing `AUTORIZO` to confirm — no silent bypass.

### `[3]` Advanced Scanning

- **Port scan** — fast (Top 21 common ports) or full (1–65535)
- **SYN scan** (stealth) when privileged, automatic fallback to **TCP connect**
- **Banner grabbing** — async, parallel
- **CVE analysis** per service via **NVD API v2.0**
- **Host discovery** (ARP scan) by CIDR — e.g. `192.168.0.0/24`
- Automatic risk classification based on CVEs found

### `[4]` Utilities

| # | Module | Details |
|---|--------|---------|
| 1 | **Text hash** | MD5, SHA1, SHA256, SHA512 |
| 2 | **File hash** | Streamed (does not load the whole file in memory) |
| 3 | **Base64 encode** | UTF-8 → base64 |
| 4 | **Base64 decode** | base64 → UTF-8 with auto-padding |
| 5 | **JWT decode** | Header + payload without signature verification |

---

## Installation

**Requirements:** Python 3.10+ and `pip`.

### From source (current method)

```bash
git clone https://github.com/flavsjr/gyntoolkit.git
cd gyntoolkit
pip install -r requirements.txt

# Optional: custom wordlist generator for brute-force
git clone https://github.com/Mebus/cupp.git
```

### As a CLI (editable install)

```bash
pip install -e .
gyntoolkit          # entry point installed via pyproject
```

> **PyPI:** the package metadata is ready for publishing. Once released, install
> with `pip install gyntoolkit`. See [`docs/installation.md`](docs/installation.md)
> for the maintainer publish procedure.

**Windows note:** for SYN scan and traceroute (raw sockets) install
[Npcap](https://npcap.com) and run in an **admin** terminal. Without Npcap, SYN
scan degrades to TCP connect scan automatically.

---

## Quick Start

```bash
python -m gyntoolkit     # run from source
# or, after `pip install -e .`
gyntoolkit
```

An interactive dark CLI opens with a numbered menu. Commands are entered at the
`gyntoolkit:~#` prompt. Output degrades gracefully to plain colored text if
[`rich`](https://github.com/Textualize/rich) is not installed.

---

## Example

Target: the **local security lab** (never a third-party system).

```bash
# 1. Launch GynToolkit
python -m gyntoolkit

# 2. Pick [3] Advanced Scanning → scan 127.0.0.1
# 3. Inspect discovered services / banners
# 4. When prompted, export the result as JSON or HTML report
```

To exercise the brute-force modules end to end against local mocks:

```bash
python lab/run_e2e.py
```

See [Security Lab](#security-lab) below.

---

## Security Lab

The project includes a local lab so you can test GynToolkit **without targeting
external systems** — no Docker, no VMs.

```text
GynToolkit  →  Security Lab  →  127.0.0.1  →  Recon / Scan / Auth testing  →  Report
```

| Service | Address | Valid credentials (intentionally weak) |
|---------|---------|-----------------------------------------|
| SSH mock (`paramiko`) | `127.0.0.1:2222` | `admin:hunter2`, `root:toor` |
| HTTP mock (`aiohttp`) | `127.0.0.1:8080` | Basic `admin:letmein` · Form `admin:s3cret` |

Run the full automated suite (starts mocks, attacks, validates, tears down):

```bash
python lab/run_e2e.py     # exit code 0 = all green
```

Full walkthrough: [`docs/security-lab.md`](docs/security-lab.md) and
[`lab/README.md`](lab/README.md).

> The mocks accept weak credentials **on purpose**. Run only on `127.0.0.1` and
> never expose them on a public network.

---

## Reports

After scans and recon lookups, the CLI offers to export results as **JSON** or a
dark-themed **HTML report**. Files are written to
`reports/<module>-<timestamp>.<fmt>` (configurable via `export.dir`; set
`export.auto: true` to export without prompting). Details in
[`docs/reports.md`](docs/reports.md).

---

## Configuration

Optional. Copy `.gyntoolkit.example.yaml` to `.gyntoolkit.yaml` and override only
the keys you want — everything else falls back to defaults.

```bash
cp .gyntoolkit.example.yaml .gyntoolkit.yaml
```

Resolution order: `GYNTOOLKIT_CONFIG` env var → `.gyntoolkit.yaml` in the current
directory → `.gyntoolkit.yaml` in the project root. Full reference:
[`docs/configuration.md`](docs/configuration.md).

---

## Documentation

| Doc | Content |
|-----|---------|
| [`docs/installation.md`](docs/installation.md) | Install from source, editable install, PyPI publish |
| [`docs/quickstart.md`](docs/quickstart.md) | First run, menu walkthrough |
| [`docs/reconnaissance.md`](docs/reconnaissance.md) | Recon modules (WHOIS, DNS, TLS, fingerprint, …) |
| [`docs/scanning.md`](docs/scanning.md) | Port scan, banners, CVE lookup, host discovery |
| [`docs/reports.md`](docs/reports.md) | JSON / HTML report formats |
| [`docs/configuration.md`](docs/configuration.md) | `.gyntoolkit.yaml` reference |
| [`docs/security-lab.md`](docs/security-lab.md) | Local lab + end-to-end tests |
| [`docs/development.md`](docs/development.md) | Dev setup, lint, tests |

---

## Development

```bash
git clone https://github.com/flavsjr/gyntoolkit.git
cd gyntoolkit
python -m venv .venv && source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

Lint and type-check (config in `pyproject.toml`):

```bash
ruff check .
ruff check . --fix
mypy gyntoolkit
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`docs/development.md`](docs/development.md).

---

## Testing

Unit tests (offline — no network, no external services, no real targets):

```bash
pytest
```

End-to-end lab suite (local mocks):

```bash
python lab/run_e2e.py
```

Both run in CI on every push/PR (see the CI badge above).

---

## Contributing

```text
Fork → Branch → Changes → Tests → Pull Request
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
Full guide (dev setup, `ruff`, running the lab): [`CONTRIBUTING.md`](CONTRIBUTING.md).
Report bugs and request features with the
[issue templates](.github/ISSUE_TEMPLATE/).

---

## Security

GynToolkit is intended for **authorized** security testing, security research,
CTFs and controlled lab environments. To report a vulnerability **in GynToolkit
itself**, see [`SECURITY.md`](SECURITY.md) — please do not open a public issue
for sensitive reports.

---

## Disclaimer

GynToolkit is intended **exclusively** for:

- Security testing **authorized in writing**
- Academic research in controlled environments
- Ethical pentest practice (CTF, HackTheBox, TryHackMe, your own labs)

Any use against systems or networks **without explicit authorization** is
strictly prohibited and constitutes a crime under most jurisdictions. The authors
are not liable for misuse or damage caused by this software.

---

## License

MIT — see [`LICENSE`](LICENSE).

---

## Star History

If this project helped you, drop a ⭐ — it really boosts visibility!

[![Star History Chart](https://api.star-history.com/svg?repos=flavsjr/gyntoolkit&type=Date)](https://star-history.com/#flavsjr/gyntoolkit&Date)
