# Audit

Menu `[5] Audit` and the `gyntoolkit audit` CLI. One target, one consolidated
report: the audit runs a pipeline of recon stages (and, when explicitly
authorized, the active port scan) and aggregates everything with an executive
summary.

## Stages

| Stage | Kind | Notes |
|-------|------|-------|
| `whois` | passive | domain only |
| `dns` | passive | A, MX, NS, TXT |
| `geo` | passive | IP geolocation |
| `subdomains` | passive | crt.sh; domain only |
| `ssl` | passive | TLS certificate |
| `httpfp` | passive | HTTP fingerprint (`https://` for domains, `http://` for IPs) |
| `internetdb` | passive | Shodan InternetDB (no key) |
| `hibp` | passive | breach check; domain only |
| `mailsec` | passive | SPF/DKIM/DMARC/DNSSEC/CAA; domain only |
| `scan` | **active** | port scan + CVE enrichment; needs `--active --authorize` |

Domain-only stages are skipped automatically for an IP literal.

## Safety

- **Passive by default.** The active port scan runs only with **both**
  `--active` and `--authorize`. Requesting `--active` without `--authorize` is
  reported and the scan is skipped.
- The interactive menu entry runs **passive stages only**; use the CLI for the
  active scan.
- Brute force is never part of the audit.

## Usage

```bash
gyntoolkit audit example.com                            # passive profile → JSON
gyntoolkit audit example.com -o reports -f html         # consolidated HTML report
gyntoolkit audit 10.0.0.5 --active --authorize          # include the port scan
gyntoolkit audit example.com --only dns,ssl,mailsec     # just these stages
gyntoolkit audit example.com --skip subdomains          # everything but one
gyntoolkit audit 10.0.0.5 --active --authorize --type full
```

| Flag | Effect |
|------|--------|
| `--active` | Include the active port scan (needs `--authorize`) |
| `--authorize` | Confirm written authorization for the active scan |
| `--type {fast,full}` | Scan type for the active stage (default `fast`) |
| `--only a,b` | Run exactly these stages |
| `--skip a,b` | Run everything except these |

Plus the global report flags (`-o/-f/-q`, see [cli.md](cli.md)).

## Output shape

```json
{
  "target": "example.com",
  "is_ip": false,
  "active": false,
  "generated": "2026-10-08 12:00:00 UTC",
  "summary": { "subdomains": 12, "mailsec_weak": 1 },
  "stages": { "whois": { ... }, "dns": { ... }, "mailsec": { ... } }
}
```

- Each stage is isolated: if one fails its section becomes `{"error": "..."}` and
  the rest still runs.
- `summary` carries quick counts (open ports, CVEs, KEV CVEs, subdomains, weak
  mail-security items) when the relevant stages ran.

> A full audit can take a while (several network sources). Run active stages only
> against authorized targets.
