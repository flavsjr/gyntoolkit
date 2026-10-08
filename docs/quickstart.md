# Quick Start

## Launch

```bash
gyntoolkit               # after `pip install gyntoolkit`
# or, from a source checkout:
python -m gyntoolkit
```

A dark interactive CLI opens with the `gyntoolkit:~#` prompt and a numbered menu.

## Main menu

```
[1] Information Gathering   recon: WHOIS, DNS, geo, subdomains, TLS, HTTP, breaches…
[2] Brute Force            CUPP wordlist, SSH, HTTP (Basic/Form)
[3] Advanced Scanning      port scan, banners, CVE lookup, host discovery
[4] Utilities              hash, base64, JWT decode
[0] Exit
```

Navigate by typing the number and pressing Enter. Sub-menus follow the same pattern.

## A safe first run

Point everything at the local lab (`127.0.0.1`) — never a third-party system:

1. Start the lab mocks (optional, for brute-force):
   ```bash
   python lab/mock_ssh_server.py &
   python lab/mock_http_server.py &
   ```
2. Launch GynToolkit, pick `[3] Advanced Scanning`, scan `127.0.0.1`.
3. Inspect discovered services / banners.
4. When prompted, export the result as JSON or an HTML report.

Or run the whole brute-force flow automatically:

```bash
python lab/run_e2e.py
```

See [security-lab.md](security-lab.md) for details.

## Output

Results render as `rich` tables/panels when `rich` is installed, and fall back to
plain colored text otherwise. See [reports.md](reports.md) for exporting.
