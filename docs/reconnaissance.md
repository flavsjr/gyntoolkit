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

## Notes

- **Passive vs active:** subdomain enum (crt.sh) and breach checks are passive —
  they query third-party datasets, not the target. DNS/WHOIS/geo touch public
  infrastructure. Traceroute sends packets toward the target and requires privilege.
- **Privilege:** TCP traceroute needs raw sockets (root on Linux/macOS, admin +
  Npcap on Windows).
- **Export:** after each lookup the CLI offers JSON / HTML export — see
  [reports.md](reports.md).

> Only run active recon against targets you are authorized to test.
