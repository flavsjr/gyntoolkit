# GynToolkit v2.0

```
 ██████╗██╗   ██╗███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝╚██╗ ██╔╝████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
██║  ███╗╚████╔╝ ██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║
██║   ██║ ╚██╔╝  ██║╚██╗██║       ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   v2.0
╚██████╔╝  ██║   ██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   by: PH,Fl4vs
 ╚═════╝   ╚═╝   ╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝
```

![Python](https://img.shields.io/badge/python-3.10+-00ff00.svg?style=flat-square&logo=python&logoColor=white&labelColor=1a1a1a)
![License](https://img.shields.io/badge/license-MIT-00ff00.svg?style=flat-square&labelColor=1a1a1a)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20MacOS-1a1a1a.svg?style=flat-square)
![Purpose](https://img.shields.io/badge/purpose-pentest%20%7C%20recon-red.svg?style=flat-square&labelColor=1a1a1a)

**Canivete suíço de pentest.** Recon passivo, port scanning, fingerprinting HTTP/TLS, brute-force
SSH/HTTP e utilitários crypto — tudo em um único CLI dark com interface `gyntoolkit:~#`.

> `[!] AVISO:` Use **apenas** em alvos com autorização escrita.
> Uso não autorizado é crime — Lei 12.737/12 (BR), CFAA (US) e equivalentes.

---

## Índice

- [Instalação](#instalação)
- [Uso](#uso)
- [Módulos](#módulos)
- [Lab local de testes](#lab-local-de-testes)
- [Estrutura](#estrutura)
- [Roadmap](#roadmap)
- [Contribuição](#contribuição)
- [Disclaimer](#disclaimer)
- [Licença](#licença)

---

## Instalação

**Pré-requisitos:** Python 3.10+ e `pip`.

```bash
git clone https://github.com/flavsjr/gyntoolkit.git
cd gyntoolkit
pip install -r requirements.txt

# Opcional (recon avançado / brute-force)
git clone https://github.com/Mebus/cupp.git    # gerador de wordlist customizada
```

No **Windows**, para SYN scan e traceroute com privilégio raw socket, instale
[Npcap](https://npcap.com) e rode o `gyntoolkit` em terminal **admin**. Sem Npcap,
o SYN scan degrada para TCP connect scan automaticamente.

---

## Uso

```bash
python gyntoolkit.py
```

Interface interativa dark com menu numérico. Comandos entram via `gyntoolkit:~#`.

**Instalação como CLI system-wide (opcional):**

```bash
pip install -e .
gyntoolkit    # entry point instalado via pyproject
```

---

## Módulos

### `[1]` Obter Informações — recon passivo e ativo

| # | Módulo | Fonte / técnica |
|---|--------|-----------------|
| 1 | **WHOIS** | `python-whois` — registrar, datas, contatos |
| 2 | **DNS Lookup** | `dnspython` — A, AAAA, MX, NS, CNAME, TXT, SOA |
| 3 | **Geolocalização IP** | `ip-api.com` (free) — país, ISP, ASN, flags proxy/hosting |
| 4 | **Reverse DNS (PTR)** | `socket.gethostbyaddr` |
| 5 | **Subdomain Enum** | Certificate Transparency via `crt.sh` |
| 6 | **SSL/TLS Cert Inspector** | `cryptography` — subject, issuer, SANs, expiry, cipher, SHA-256 |
| 7 | **HTTP Fingerprint** | Detecta nginx, Apache, IIS, Cloudflare, PHP, WordPress, Laravel, ASP.NET, Django, Rails, Node |
| 8 | **InternetDB (Shodan free)** | Portas abertas, CPEs, CVEs conhecidos — sem API key |
| 9 | **HIBP Breach Check** | Domínio → breaches conhecidos via Have I Been Pwned |
| 10 | **MAC Vendor Lookup** | `api.macvendors.com` — OUI → fabricante |
| 11 | **Traceroute TCP** | `scapy` — hops + RTT (requer privilégio) |

### `[2]` Brute Force

| # | Módulo | Detalhes |
|---|--------|----------|
| 1 | **CUPP wordlist** | Wrapper para `cupp.py -i` — gerador personalizado |
| 2 | **SSH brute** | `paramiko` async via `asyncio.to_thread`, `Semaphore` p/ concorrência, delay |
| 3 | **HTTP brute** | `aiohttp` — Basic Auth ou form POST com `fail_signature` configurável |

> Todo ataque exige confirmação explícita digitando `AUTORIZO` — sem bypass silencioso.

### `[3]` Varredura Avançada

- **Port scan** rápido (Top 21 portas comuns) ou completo (1–65535)
- **SYN scan** stealth quando roda com privilégio, fallback para **TCP connect**
- **Banner grabbing** async paralelo
- **Análise CVE** por serviço via **NVD API v2.0**
- **Descoberta de hosts ativos** (ARP scan) com CIDR — `192.168.0.0/24`
- Classificação automática de risco (Alto/Baixo) baseada em CVEs encontrados

### `[4]` Utilitários

| # | Módulo | Detalhes |
|---|--------|----------|
| 1 | **Hash de texto** | MD5, SHA1, SHA256, SHA512 |
| 2 | **Hash de arquivo** | Streaming (não carrega tudo em memória) |
| 3 | **Base64 encode** | UTF-8 → base64 |
| 4 | **Base64 decode** | Base64 → UTF-8 com auto-padding |
| 5 | **JWT decode** | Header + payload sem verificar assinatura |

---

## Lab local de testes

O diretório `lab/` traz um ambiente **isolado em 127.0.0.1** para validar os módulos
de brute-force sem tocar em alvos reais — sem Docker, sem VM.

**Rodada completa automatizada:**

```bash
python lab/run_e2e.py
```

Sobe mocks SSH (paramiko em `:2222`) e HTTP (aiohttp em `:8080`), executa
`ssh_bruteforce` + `http_bruteforce` (Basic + Form), valida credenciais
encontradas contra o esperado, encerra tudo. Exit code `0` = tudo verde.

Ver **`lab/README.md`** para passo-a-passo manual de cada laboratório (SSH, HTTP Basic, HTTP Form).

---

## Estrutura

```
gyntoolkit/
├── gyntoolkit.py         # CLI monolítico, entry point
├── pyproject.toml        # build system + deps + ruff config
├── requirements.txt      # deps pinadas
├── cupp/                 # gerador de wordlist customizada (opcional)
├── lab/                  # ambiente de testes local
│   ├── README.md
│   ├── mock_ssh_server.py
│   ├── mock_http_server.py
│   ├── run_e2e.py
│   └── wordlists/
├── gyntoolkit.log        # log runtime (gitignored)
└── README.md
```

---

## Roadmap

- [x] **v1.2** — Port scan, WHOIS, DNS lookup, NVD API v1.0
- [x] **v2.0 Fase 1** — Fix NVD API v2.0, ARP discovery, logging estruturado
- [x] **v2.0 Fase 2** — Geo IP, CUPP wire-in, SSH brute, HTTP brute, lab local
- [x] **v2.0 Fase 3** — Recon avançado (crt.sh, SSL, HTTP fingerprint, InternetDB,
      HIBP, MAC, traceroute) + Utilitários (hash, base64, JWT)
- [ ] **v2.1** — UI com `rich` (tabelas, spinners cyberpunk)
- [ ] **v2.2** — Export resultados JSON / HTML report
- [ ] **v2.3** — Config `.gyntoolkit.yaml` (timeouts, wordlists default, API keys)
- [ ] **v2.4** — Refactor split em `modules/recon/`, `modules/brute/`, `modules/utils/`

---

## Contribuição

1. Fork o projeto
2. Crie branch: `git checkout -b feature/minha-feature`
3. Commit: `git commit -m 'feat: descrição da feature'`
4. Push: `git push origin feature/minha-feature`
5. Abra Pull Request

**Estilo de commit:** Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`).

---

## Disclaimer

Esta ferramenta é destinada **exclusivamente** a:

- Testes de segurança **autorizados por escrito**
- Pesquisa acadêmica em ambientes controlados
- Práticas de pentest ético (CTF, HackTheBox, TryHackMe, labs próprios)

Qualquer uso em sistemas sem permissão explícita é **estritamente proibido** e
constitui crime nas legislações da maioria dos países. Os desenvolvedores não se
responsabilizam por uso indevido ou danos causados por esta ferramenta.

---

## Licença

MIT — veja `LICENSE`.
