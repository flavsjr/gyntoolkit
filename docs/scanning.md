# Scanning

Menu `[3] Advanced Scanning`.

## Port scan

- **Fast** — Top 21 common ports.
- **Full** — 1–65535.
- **SYN scan** (stealth) when running privileged; automatic fallback to **TCP
  connect** scan otherwise.
- Scans run asynchronously (`asyncio`) with bounded concurrency (`scan.concurrency`,
  default 100) so a full scan does not exhaust sockets. On the CLI: `--concurrency N`.

## Banner grabbing

Async, parallel banner collection on open ports to identify services/versions.

## CVE analysis & risk scoring

For a detected service, GynToolkit parses the product + version from the banner
and queries the **NVD API v2.0** (`check_vulnerabilities`). The match is done by
**CPE** (`virtualMatchString`) when a version is known — far more precise than a
keyword search — with a keyword fallback otherwise. NVD calls are rate-limited and
deduplicated per banner; no API key is required (an optional `api_keys.nvd` raises
the limit).

Each CVE is then **enriched**:

- **CVSS** — base score and severity, taken from the NVD response (v3.1 > v3.0 > v2).
- **EPSS** — exploitation probability, in one batched call to `first.org`.
- **CISA KEV** — whether the CVE is in the Known Exploited Vulnerabilities catalog
  (cached locally in `~/.gyntoolkit/kev.json`, 24h TTL, graceful offline fallback).

Host risk is the **highest severity** found (`critical`/`high`/`medium`/`low`); a
KEV CVE forces `critical`. Filter what is shown (collection is unchanged):

```bash
gyntoolkit scan 10.0.0.5 --min-cvss 7.0      # only CVSS >= 7.0
gyntoolkit scan 10.0.0.5 --kev-only          # only actively-exploited CVEs
```

EPSS and KEV degrade gracefully — if those sources are unreachable the CVSS-based
result still stands.

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
