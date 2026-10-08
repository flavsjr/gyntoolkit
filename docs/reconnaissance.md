# Reconnaissance

Menu `[1] Information Gathering`. Passive and active recon modules. Most use free
public sources and need no API key.

| Module | Source / technique | Notes |
|--------|--------------------|-------|
| WHOIS | `python-whois` | registrar, dates, contacts |
| DNS Lookup | `dnspython` | A, AAAA, MX, NS, CNAME, TXT, SOA; optional custom resolver |
| IP Geolocation | `ip-api.com` (free) | country, ISP, ASN, proxy/hosting flags |
| Reverse DNS (PTR) | `socket.gethostbyaddr` | IP → hostname |
| Subdomain Enum | Certificate Transparency via `crt.sh` | passive, no scanning of the target |
| SSL/TLS Cert Inspector | `cryptography` | subject, issuer, SANs, expiry, cipher, SHA-256 |
| HTTP Fingerprint | header/body signatures | nginx, Apache, IIS, Cloudflare, PHP, WordPress, Laravel, ASP.NET, Django, Rails, Node |
| InternetDB (Shodan free) | `internetdb.shodan.io` | open ports, CPEs, known CVEs — no API key |
| HIBP Breach Check | Have I Been Pwned | domain → known breaches |
| MAC Vendor Lookup | `api.macvendors.com` | OUI → vendor |
| Traceroute (TCP) | `scapy` | hops + RTT; needs raw-socket privilege |
| DNS Zone Transfer (AXFR) | `dnspython` | tries AXFR against each authoritative NS; flags any that allow it |
| Web Content Discovery | `aiohttp` | robots.txt / sitemap / security.txt + built-in path wordlist |
| Shodan Host | `api.shodan.io` | full host record (ports, CPEs, CVEs, tags) — needs `api_keys.shodan` |
| Email Security | `dnspython` | SPF, DKIM, DMARC, DNSSEC, CAA analyzer with per-item verdict |

CLI: `gyntoolkit recon <action> <target>` (see [cli.md](cli.md)).

## New modules in detail

- **DNS Zone Transfer (AXFR)** — resolves the domain's `NS` records and attempts
  a zone transfer against each. A successful AXFR exposes the full internal zone
  and is a classic misconfiguration; the result flags it as `vulnerable`.
  `gyntoolkit recon axfr example.com`
- **Web Content Discovery** — reads public hints (`robots.txt` Disallow/Allow and
  Sitemap, a curated path wordlist) and probes each candidate, reporting anything
  that is not a 404 (status, length, redirect location). Pass a custom list with
  `--wordlist`. `gyntoolkit recon webscan http://example.com`
- **Shodan Host** — full `/shodan/host/{ip}` lookup; needs `api_keys.shodan` in
  the config. Without a key it returns a hint pointing to the key-free InternetDB
  module. `gyntoolkit recon shodan 1.1.1.1`
- **Email Security** — analyzes SPF (presence, `all` qualifier, DNS-lookup count
  vs the RFC limit), DMARC (`p=none` is weak, `quarantine`/`reject` ok), DKIM
  (tests a selector list — absence is not proof of no DKIM), DNSSEC (DNSKEY/DS
  presence) and CAA. Each check gets a verdict: `ok` / `weak` / `missing`.
  `gyntoolkit recon mailsec example.com [--selectors google,default]`

## Notes

- **Passive vs active:** subdomain enum (crt.sh), breach checks, Shodan, AXFR and
  email-security are passive — they query third-party datasets or public DNS, not
  the target's services. Web content discovery sends HTTP requests to the target.
  Traceroute sends packets toward the target and requires privilege.
- **Privilege:** TCP traceroute needs raw sockets (root on Linux/macOS, admin +
  Npcap on Windows).
- **Export:** after each lookup the CLI offers JSON / HTML / CSV / Markdown export
  — see [reports.md](reports.md).

> Only run active recon against targets you are authorized to test.
