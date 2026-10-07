# Configuration

Configuration is **optional** — without a file, GynToolkit uses built-in defaults.

## Create a config

```bash
cp .gyntoolkit.example.yaml .gyntoolkit.yaml
```

Override only the keys you care about; the rest deep-merge over the defaults.

## Resolution order

1. Path passed explicitly to `load_config()`.
2. `GYNTOOLKIT_CONFIG` environment variable.
3. `.gyntoolkit.yaml` in the current working directory.
4. `.gyntoolkit.yaml` in the project root.

The first existing file wins.

## Keys (defaults)

```yaml
scan:
  default_type: "rápido"      # "rápido" (fast) or "completo" (full)

brute:
  ssh_workers: 8
  http_workers: 10
  delay: 0.1
  ssh_timeout: 5
  http_timeout: 10
  users_wordlist: ""          # optional default suggested at the prompt
  passwords_wordlist: ""

recon:
  subdomain_timeout: 30
  ssl_timeout: 8
  http_timeout: 10
  traceroute_max_hops: 20
  traceroute_dport: 80

export:
  dir: reports
  auto: false
  format: json                # json | html

api_keys:
  hibp: ""                    # reserved — current endpoints are public/free
  shodan: ""
```

## Notes

- Values from the file are deep-merged over defaults, so a partial file is valid.
- If `pyyaml` is not installed, GynToolkit logs a warning and falls back to defaults.
- API keys are reserved for future use; the current recon sources work on their
  public/free tiers.
