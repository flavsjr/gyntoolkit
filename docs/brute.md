# Brute force & wordlists

Menu `[2] Brute Force` and the `gyntoolkit brute` / `gyntoolkit wordlist` CLI.

> Every attack requires explicit authorization. In the menu you type the
> authorization word (`AUTHORIZE` / `AUTORIZO`); on the CLI you pass `--authorize`.
> Run only against targets you are authorized **in writing** to test.

## Native wordlist generator

A built-in, offline CUPP-style generator — no external clone required.

```bash
gyntoolkit wordlist --terms alice,fluffy,acme --years 1990,2020 --leet --save wl.txt
```

| Flag | Effect |
|------|--------|
| `--terms a,b,c` | Base words (name, nickname, pet, company, keywords) — required |
| `--years 1990,2020` | Years/numbers appended and prepended |
| `--leet` | Also emit leet variants (`a`→`4`/`@`, `e`→`3`, `i`→`1`/`!`, `o`→`0`, `s`→`5`/`$`, `t`→`7`) |
| `--no-special` | Skip the common suffixes (`123`, `!`, `@`, years, …) |
| `--no-combine` | Do not combine pairs of terms |
| `--min-len N` / `--max-len N` | Length filter (default 4–32) |
| `--save FILE` | Write the wordlist to a file |
| `-q, --quiet` | Do not print to stdout |

Output is one candidate per line (pipe-friendly), deduplicated and sorted. The
optional [CUPP](https://github.com/Mebus/cupp) wrapper remains available in the
menu as an alternative.

## SSH brute (`paramiko`)

Async with bounded concurrency (`Semaphore`) and a per-attempt delay.

```bash
gyntoolkit brute ssh HOST --users users.txt --passwords pass.txt \
  --port 22 --workers 8 --authorize
```

`--users` accepts a single username or a path to a users wordlist.

## HTTP brute (`aiohttp`)

Basic Auth or form POST.

```bash
# Basic Auth — success = HTTP 2xx
gyntoolkit brute http https://HOST/ --users admin --passwords pass.txt \
  --mode basic --authorize

# Form POST — success = 200/302 and the fail signature absent from the body
gyntoolkit brute http https://HOST/login --users admin --passwords pass.txt \
  --mode form --user-field username --pass-field password \
  --fail-signature "Invalid credentials" --authorize
```

| Flag | Effect |
|------|--------|
| `--mode {basic,form}` | Auth mode (default `basic`) |
| `--user-field` / `--pass-field` | Form field names (form mode) |
| `--fail-signature` | Text in the body that indicates a failed login (form mode) |
| `--workers N` | Concurrent workers |

## Tuning

Defaults for workers, delay and timeouts live under `brute:` in
`.gyntoolkit.yaml` — see [configuration.md](configuration.md).

## Practice safely

Exercise every brute module against the bundled local lab (never a real target):

```bash
python lab/run_e2e.py
```

See [security-lab.md](security-lab.md).
