# Non-interactive CLI

Run a single action and print the result as JSON on stdout (pipe-friendly) — no
menu. Omit the subcommand to open the interactive menu instead.

```bash
gyntoolkit <group> <action> [args] [flags]
```

## Global flags

Place these **after** the subcommand (they are inherited per subcommand):

| Flag | Effect |
|------|--------|
| `-o, --output DIR` | Also save a report into `DIR` |
| `-f, --format {json,html,csv,md}` | Report format when `--output` is used (default `json`) |
| `-q, --quiet` | Do not print JSON to stdout |
| `--lang {en,pt}` | Override the UI/message language |

`--version` and `--help` are available at every level (`gyntoolkit --help`,
`gyntoolkit recon --help`, `gyntoolkit recon dns --help`).

## Groups and actions

### `recon`

```bash
gyntoolkit recon whois example.com
gyntoolkit recon dns example.com --type MX [--nameserver 8.8.8.8]
gyntoolkit recon geo 1.1.1.1
gyntoolkit recon revdns 1.1.1.1
gyntoolkit recon subenum example.com
gyntoolkit recon ssl example.com --port 443
gyntoolkit recon httpfp https://example.com
gyntoolkit recon internetdb 1.1.1.1
gyntoolkit recon hibp example.com
gyntoolkit recon mac 00:1A:2B:3C:4D:5E
gyntoolkit recon traceroute example.com --max-hops 20 --dport 80
gyntoolkit recon axfr example.com                       # zone transfer attempt
gyntoolkit recon webscan http://example.com [--wordlist paths.txt]
gyntoolkit recon shodan 1.1.1.1                         # needs api_keys.shodan
gyntoolkit recon mailsec example.com [--selectors google,default]
```

See [reconnaissance.md](reconnaissance.md) for what each module does.

### `scan`

```bash
gyntoolkit scan 127.0.0.1 --type fast
gyntoolkit scan 10.0.0.5 --type full --concurrency 200
gyntoolkit scan 10.0.0.5 --min-cvss 7.0 --kev-only      # risk filters
gyntoolkit scan 192.168.0.0/24                          # CIDR → host discovery
```

CVEs are enriched with CVSS / EPSS / CISA KEV — see [scanning.md](scanning.md).

### `utils`

```bash
gyntoolkit utils hash "text" --algo sha256
gyntoolkit utils hashfile ./file.bin --algo sha1
gyntoolkit utils b64enc "text"
gyntoolkit utils b64dec aGVsbG8=
gyntoolkit utils jwt <token>
```

### `audit`

```bash
gyntoolkit audit example.com                            # passive profile
gyntoolkit audit 10.0.0.5 --active --authorize          # + port scan
```

See [audit.md](audit.md).

### `wordlist`

Native CUPP-style generator; emits one word per line (not JSON).

```bash
gyntoolkit wordlist --terms alice,fluffy,acme --years 1990,2020 --leet --save wl.txt
```

See [brute.md](brute.md).

### `brute` (requires `--authorize`)

```bash
gyntoolkit brute ssh HOST --users users.txt --passwords pass.txt --authorize
gyntoolkit brute http URL --users admin --passwords pass.txt --mode form \
  --user-field user --pass-field pass --fail-signature "Invalid" --authorize
```

Without `--authorize` the brute subcommands abort. See [brute.md](brute.md).

## Saving reports

```bash
gyntoolkit scan scanme.example.com -o reports -f md     # Markdown report
gyntoolkit recon geo 1.1.1.1 -o reports -f csv -q       # CSV only, no stdout
```

Formats and layout: [reports.md](reports.md).

## Automation

- stdout is clean JSON (unless `--quiet`), so pipe into `jq`, files or other tools.
- Exit code is `0` on success, non-zero on a usage/authorization error.

```bash
gyntoolkit recon dns example.com --type A | jq -r '.records[]'
```

> Only run active actions (`scan`, `brute`, `audit --active`) against targets you
> are authorized to test.
