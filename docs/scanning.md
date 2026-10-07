# Scanning

Menu `[3] Advanced Scanning`.

## Port scan

- **Fast** — Top 21 common ports.
- **Full** — 1–65535.
- **SYN scan** (stealth) when running privileged; automatic fallback to **TCP
  connect** scan otherwise.
- Scans run asynchronously (`asyncio`).

## Banner grabbing

Async, parallel banner collection on open ports to identify services/versions.

## CVE analysis

For a detected service, GynToolkit queries the **NVD API v2.0**
(`check_vulnerabilities`) for associated CVEs and classifies risk based on what is
found. No API key is required for basic NVD queries (rate limits apply).

## Host discovery

ARP-based discovery of live hosts on a CIDR range, e.g.:

```
192.168.0.0/24
```

Requires raw-socket privilege (root / admin + Npcap on Windows).

## Privilege summary

| Feature | Needs privilege? |
|---------|------------------|
| TCP connect scan | No |
| SYN scan | Yes (else falls back to connect) |
| Banner grabbing | No |
| ARP host discovery | Yes |

## Example (local lab)

```bash
python -m gyntoolkit
# [3] Advanced Scanning → 127.0.0.1 → fast scan → inspect → export
```

> Scan only hosts/networks you are authorized to test. Use `127.0.0.1` / your own
> lab for practice.
