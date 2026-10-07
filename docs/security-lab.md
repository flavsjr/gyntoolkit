# Security Lab

The `lab/` directory is an **isolated, local** environment (`127.0.0.1`) for
testing GynToolkit's brute-force modules without touching real targets — no
Docker, no VMs. It uses Python mock servers (`paramiko` + `aiohttp`).

```text
GynToolkit  →  Security Lab  →  127.0.0.1  →  Auth testing  →  Report
```

## Services

| Service | Address | Valid credentials (intentionally weak) |
|---------|---------|-----------------------------------------|
| SSH mock (`paramiko`) | `127.0.0.1:2222` | `admin:hunter2`, `root:toor` |
| HTTP mock (`aiohttp`) — Basic auth | `127.0.0.1:8080` | `admin:letmein` |
| HTTP mock (`aiohttp`) — Form POST | `127.0.0.1:8080` | `admin:s3cret` |

> The mocks accept weak credentials **on purpose**. Run only on `127.0.0.1` and
> never expose them on a public network. Stop them with `Ctrl+C`.

## Prerequisites

```bash
pip install -r requirements.txt
# run all commands from the project root
```

## Automated end-to-end run

```bash
python lab/run_e2e.py
```

This starts both mocks, runs `ssh_bruteforce` + `http_bruteforce` (Basic and
Form), validates the found credentials against the expected set, and tears
everything down. **Exit code `0` means all green.**

## Manual walkthrough

1. Start a mock:
   ```bash
   python lab/mock_ssh_server.py      # or mock_http_server.py
   ```
2. Launch GynToolkit → `[2] Brute Force` → pick SSH or HTTP.
3. Target `127.0.0.1`, port `2222` (SSH) or `8080` (HTTP).
4. Use the wordlists in `lab/wordlists/` (`users.txt`, `passwords.txt`).
5. Confirm the attack by typing `AUTORIZO` when prompted.

See [`lab/README.md`](../lab/README.md) for the per-lab details.
