# GynToolkit

**🌐 Idioma / Language:** **Português (BR)** · [English](README.md)

```
 ██████╗██╗   ██╗███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝╚██╗ ██╔╝████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
██║  ███╗╚████╔╝ ██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║
██║   ██║ ╚██╔╝  ██║╚██╗██║       ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   v2.2
╚██████╔╝  ██║   ██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   by: PH,Fl4vs
 ╚═════╝   ╚═╝   ╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝
```

> Canivete suíço de segurança em Python para reconhecimento, varredura de rede,
> análise de vulnerabilidades e teste de intrusão **autorizado** — tudo em uma
> única CLI interativa de tema dark (`gyntoolkit:~#`).

[![CI](https://github.com/flavsjr/gyntoolkit/actions/workflows/tests.yml/badge.svg)](https://github.com/flavsjr/gyntoolkit/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/gyntoolkit.svg?style=flat-square&color=00ff00&labelColor=1a1a1a&logo=pypi&logoColor=white)](https://pypi.org/project/gyntoolkit/)
![Python](https://img.shields.io/badge/python-3.10+-00ff00.svg?style=flat-square&logo=python&logoColor=white&labelColor=1a1a1a)
![License](https://img.shields.io/badge/license-MIT-00ff00.svg?style=flat-square&labelColor=1a1a1a)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20MacOS-1a1a1a.svg?style=flat-square)
![Purpose](https://img.shields.io/badge/purpose-pentest%20%7C%20recon-red.svg?style=flat-square&labelColor=1a1a1a)

<!-- Demonstração: gere o GIF com `vhs demo.tape` (ver demo.tape na raiz). -->
![GynToolkit Demo](docs/demo.gif)

> `[!] AVISO:` Use **apenas** em alvos que você está **autorizado por escrito** a testar.
> Uso não autorizado é crime — Lei 12.737/12 (BR), CFAA (US) e equivalentes.

---

## Índice

- [Por que GynToolkit?](#por-que-gyntoolkit)
- [Funcionalidades](#funcionalidades)
- [Instalação](#instalação)
- [Início rápido](#início-rápido)
- [CLI não-interativa](#cli-não-interativa-scriptável)
- [Exemplo](#exemplo)
- [Lab de segurança](#lab-de-segurança)
- [Relatórios](#relatórios)
- [Configuração](#configuração)
- [Documentação](#documentação)
- [Desenvolvimento](#desenvolvimento)
- [Testes](#testes)
- [Contribuição](#contribuição)
- [Segurança](#segurança)
- [Disclaimer](#disclaimer)
- [Licença](#licença)

---

## Por que GynToolkit?

- **Uma CLI, várias ferramentas** — recon, port scanning, fingerprinting TLS/HTTP,
  consulta de CVE e teste de autenticação SSH/HTTP, sem malabarismo com uma dúzia
  de comandos separados.
- **Seguro de experimentar** — acompanha um lab local (`127.0.0.1`) e um runner
  ponta-a-ponta, então você exercita todo módulo de brute-force sem tocar num alvo real.
- **Saída legível** — tabelas/painéis com `rich` quando disponível, fallback gracioso
  para texto colorido puro; exporte qualquer resultado em JSON ou relatório HTML dark.
- **Autorização em primeiro lugar** — todo módulo de ataque exige confirmação explícita.
- **Zero API keys obrigatórias** — as fontes de recon usadas (crt.sh, ip-api,
  InternetDB, HIBP, NVD) funcionam nos seus tiers públicos/gratuitos.

---

## Funcionalidades

### `[1]` Obter Informações — recon passivo e ativo

| # | Módulo | Fonte / técnica |
|---|--------|-----------------|
| 1 | **WHOIS** | `python-whois` — registrar, datas, contatos |
| 2 | **DNS Lookup** | `dnspython` — A, AAAA, MX, NS, CNAME, TXT, SOA |
| 3 | **Geolocalização IP** | `ip-api.com` (free) — país, ISP, ASN, flags proxy/hosting |
| 4 | **Reverse DNS (PTR)** | `socket.gethostbyaddr` |
| 5 | **Subdomain Enum** | Certificate Transparency via `crt.sh` |
| 6 | **SSL/TLS Cert Inspector** | `cryptography` — subject, issuer, SANs, expiry, cipher, SHA-256 |
| 7 | **HTTP Fingerprint** | nginx, Apache, IIS, Cloudflare, PHP, WordPress, Laravel, ASP.NET, Django, Rails, Node |
| 8 | **InternetDB (Shodan free)** | Portas abertas, CPEs, CVEs conhecidos — sem API key |
| 9 | **HIBP Breach Check** | Domínio → breaches conhecidos via Have I Been Pwned |
| 10 | **MAC Vendor Lookup** | `api.macvendors.com` — OUI → fabricante |
| 11 | **Traceroute (TCP)** | `scapy` — hops + RTT (requer privilégio) |
| 12 | **DNS Zone Transfer (AXFR)** | `dnspython` — tenta AXFR contra cada NS autoritativo |
| 13 | **Web Content Discovery** | `aiohttp` — robots.txt / sitemap / security.txt + wordlist embutida de paths |
| 14 | **Shodan Host** | Lookup completo em `api.shodan.io` (portas, CPEs, CVEs, tags) — requer `api_keys.shodan`; sem key, orienta p/ o InternetDB |
| 15 | **Email Security** | `dnspython` — analyzer de SPF, DKIM, DMARC, DNSSEC e CAA com veredito por item (`ok`/`weak`/`missing`) |

### `[2]` Brute Force

| # | Módulo | Detalhes |
|---|--------|----------|
| 1 | **Wordlist nativa** | Gerador embutido estilo CUPP (offline, sem clone externo) — variações de caixa/leet, anos, sufixos, combinação de termos |
| 2 | **CUPP wordlist** | Wrapper opcional para `cupp.py -i` |
| 3 | **SSH brute** | `paramiko`, async via `asyncio.to_thread`, `Semaphore` p/ concorrência, delay |
| 4 | **HTTP brute** | `aiohttp` — Basic Auth ou form POST com `fail_signature` configurável |

> Todo ataque exige digitar a palavra de autorização (`AUTHORIZE` / `AUTORIZO`)
> para confirmar — sem bypass silencioso.

### `[3]` Varredura Avançada

- **Port scan** — rápido (Top 21 portas comuns) ou completo (1–65535)
- **SYN scan** (stealth) quando com privilégio, fallback automático para **TCP connect**
- **Banner grabbing** — async, paralelo
- **Análise de CVE** por serviço via **NVD API v2.0** — parseia produto + versão
  do banner e casa por **CPE** (`virtualMatchString`), com fallback de keyword;
  rate-limited e deduplicado por banner
- **Risk scoring** — cada CVE é enriquecido com **CVSS** (base score/severidade),
  probabilidade de exploração **EPSS** e flag **CISA KEV**; o risco do host é a
  maior severidade encontrada (KEV força crítico). Filtre com `--min-cvss` / `--kev-only`
- **Descoberta de hosts** (ARP scan) por CIDR — ex. `192.168.0.0/24`
- Classificação automática de risco baseada nos CVEs encontrados

### `[4]` Utilitários

| # | Módulo | Detalhes |
|---|--------|----------|
| 1 | **Hash de texto** | MD5, SHA1, SHA256, SHA512 |
| 2 | **Hash de arquivo** | Streaming (não carrega o arquivo todo em memória) |
| 3 | **Base64 encode** | UTF-8 → base64 |
| 4 | **Base64 decode** | base64 → UTF-8 com auto-padding |
| 5 | **JWT decode** | Header + payload sem verificar a assinatura |

### `[5]` Audit — um alvo, perfil consolidado

Orquestra os módulos de recon (e, com `--active --authorize`, o port scan) num
**único relatório** com resumo executivo. Passivo por padrão; seleção de etapas
via `--only` / `--skip`. Veja os [exemplos de CLI](#cli-não-interativa-scriptável).

---

## Instalação

**Pré-requisitos:** Python 3.10+ e `pip`.

### Via PyPI (recomendado)

```bash
pip install gyntoolkit
gyntoolkit          # abre a CLI interativa
```

Instala o comando `gyntoolkit` e todas as dependências.

### A partir do código-fonte (desenvolvimento)

```bash
git clone https://github.com/flavsjr/gyntoolkit.git
cd gyntoolkit
pip install -e .
gyntoolkit          # ou: python -m gyntoolkit
```

> **Opcional — wordlists de brute-force:** o módulo "CUPP wordlist" é um wrapper
> do [CUPP](https://github.com/Mebus/cupp). Clone-o ao lado de onde você roda o
> GynToolkit (`git clone https://github.com/Mebus/cupp.git`); não é dependência
> Python e não é instalado pelo pip.

**Nota Windows:** para SYN scan e traceroute (raw sockets) instale
[Npcap](https://npcap.com) e rode em terminal **admin**. Sem Npcap, o SYN scan
degrada para TCP connect scan automaticamente.

---

## Início rápido

```bash
gyntoolkit               # após `pip install gyntoolkit`
# ou, a partir do código-fonte:
python -m gyntoolkit
```

Abre uma CLI dark interativa com menu numérico. Comandos entram no prompt
`gyntoolkit:~#`. A saída degrada graciosamente para texto colorido puro se o
[`rich`](https://github.com/Textualize/rich) não estiver instalado.

---

## CLI não-interativa (scriptável)

Passe um subcomando para executar uma única ação e imprimir o resultado como JSON
no stdout (pipe-friendly) — sem menu. Sem subcomando, abre o menu interativo.

```bash
gyntoolkit recon dns example.com --type MX        # DNS lookup
gyntoolkit recon axfr example.com                 # tentativa de zone transfer
gyntoolkit recon webscan http://example.com       # web content discovery
gyntoolkit recon shodan 1.1.1.1                   # Shodan host (requer api_keys.shodan)
gyntoolkit recon mailsec example.com              # postura de segurança de e-mail
gyntoolkit recon ssl example.com --port 443       # cert TLS
gyntoolkit scan 127.0.0.1 --type fast             # port scan + CVEs (CVSS/EPSS/KEV)
gyntoolkit scan 10.0.0.5 --min-cvss 7.0 --kev-only # só alto risco / exploração ativa
gyntoolkit scan 192.168.0.0/24                    # descoberta de hosts (CIDR)
gyntoolkit audit example.com                      # perfil passivo completo → 1 relatório
gyntoolkit audit 10.0.0.5 --active --authorize    # + port scan ativo (autorizado)
gyntoolkit utils hash "texto" --algo sha1
gyntoolkit utils jwt <token>
gyntoolkit wordlist --terms alice,fluffy,acme --years 1990,2020 --leet --save wl.txt
```

O `audit` roda um pipeline sobre um alvo e consolida tudo num único relatório com
resumo executivo. É **passivo por padrão** (WHOIS, DNS, geo, subdomínios, TLS,
HTTP fingerprint, InternetDB, HIBP, email security); o port scan ativo só roda com
`--active --authorize`. Refine com `--only a,b` ou `--skip a,b`.

Flags globais (coloque após o subcomando): `-o/--output DIR` salva um relatório,
`-f/--format {json,html,csv,md}` escolhe o formato, `-q/--quiet` silencia o stdout,
`--lang {en,pt}` força o idioma.

```bash
gyntoolkit scan scanme.example.com -o reports -f md     # salva também relatório Markdown
gyntoolkit recon geo 1.1.1.1 -o reports -f csv -q       # só CSV, sem stdout
```

Ataques ativos estão disponíveis, mas exigem autorização explícita:

```bash
gyntoolkit brute ssh HOST --users users.txt --passwords pass.txt --authorize
gyntoolkit brute http URL  --users admin --passwords pass.txt --mode form \
  --user-field user --pass-field pass --fail-signature "Invalid" --authorize
```

Sem `--authorize`, os subcomandos de brute abortam — você confirma que tem
**autorização por escrito** para o alvo.

---

## Exemplo

Alvo: o **lab de segurança local** (nunca um sistema de terceiros).

```bash
# 1. Abra o GynToolkit
gyntoolkit

# 2. Escolha [3] Varredura Avançada → scan 127.0.0.1
# 3. Inspecione serviços/banners descobertos
# 4. Quando perguntado, exporte o resultado em JSON ou relatório HTML
```

Para exercitar os módulos de brute-force ponta-a-ponta contra os mocks locais:

```bash
python lab/run_e2e.py
```

Veja [Lab de segurança](#lab-de-segurança) abaixo.

---

## Lab de segurança

O projeto inclui um lab local para testar o GynToolkit **sem mirar sistemas
externos** — sem Docker, sem VMs.

```text
GynToolkit  →  Lab de segurança  →  127.0.0.1  →  Recon / Scan / Teste de auth  →  Relatório
```

| Serviço | Endereço | Credenciais válidas (fracas de propósito) |
|---------|----------|-------------------------------------------|
| Mock SSH (`paramiko`) | `127.0.0.1:2222` | `admin:hunter2`, `root:toor` |
| Mock HTTP (`aiohttp`) | `127.0.0.1:8080` | Basic `admin:letmein` · Form `admin:s3cret` |

Rode a suíte automatizada completa (sobe mocks, ataca, valida, encerra):

```bash
python lab/run_e2e.py     # exit code 0 = tudo verde
```

Passo-a-passo completo: [`docs/security-lab.md`](docs/security-lab.md) e
[`lab/README.md`](lab/README.md).

> Os mocks aceitam credenciais fracas **de propósito**. Rode apenas em `127.0.0.1`
> e nunca os exponha numa rede pública.

---

## Relatórios

Após scans e consultas de recon, a CLI oferece exportar o resultado em **JSON**,
um **relatório HTML** dark, **CSV** ou **Markdown**. Arquivos vão para
`reports/<módulo>-<timestamp>.<fmt>` (configurável em `export.dir`; defina
`export.auto: true` para exportar sem perguntar). Detalhes em
[`docs/reports.md`](docs/reports.md).

---

## Configuração

Opcional. Copie `.gyntoolkit.example.yaml` para `.gyntoolkit.yaml` e sobrescreva
apenas as chaves que quiser — o resto cai nos defaults.

```bash
cp .gyntoolkit.example.yaml .gyntoolkit.yaml
```

Ordem de resolução: env `GYNTOOLKIT_CONFIG` → `.gyntoolkit.yaml` no diretório
atual → `.gyntoolkit.yaml` na raiz do projeto. Referência completa:
[`docs/configuration.md`](docs/configuration.md).

**Idioma da UI:** os menus rodam em inglês ou português. Defina `ui.lang: auto|en|pt`
na config, ou `GYNTOOLKIT_LANG=pt` / `=en` por execução; `auto` detecta o locale do
SO e cai para inglês.

---

## Documentação

| Doc | Conteúdo |
|-----|----------|
| [`docs/installation.md`](docs/installation.md) | Instalar via PyPI ou código-fonte, e o fluxo de publicação no PyPI |
| [`docs/quickstart.md`](docs/quickstart.md) | Primeira execução, passeio pelo menu |
| [`docs/reconnaissance.md`](docs/reconnaissance.md) | Módulos de recon (WHOIS, DNS, TLS, fingerprint, …) |
| [`docs/scanning.md`](docs/scanning.md) | Port scan, banners, CVE lookup, host discovery |
| [`docs/reports.md`](docs/reports.md) | Formatos de relatório JSON / HTML |
| [`docs/configuration.md`](docs/configuration.md) | Referência do `.gyntoolkit.yaml` |
| [`docs/security-lab.md`](docs/security-lab.md) | Lab local + testes ponta-a-ponta |
| [`docs/development.md`](docs/development.md) | Setup de dev, lint, testes |

---

## Desenvolvimento

```bash
git clone https://github.com/flavsjr/gyntoolkit.git
cd gyntoolkit
python -m venv .venv && source .venv/bin/activate   # .venv\Scripts\activate no Windows
pip install -e ".[dev]"
```

Lint e type-check (config no `pyproject.toml`):

```bash
ruff check .
ruff check . --fix
mypy gyntoolkit
```

Veja [`CONTRIBUTING.md`](CONTRIBUTING.md) e [`docs/development.md`](docs/development.md).

---

## Testes

Testes unitários (offline — sem rede, sem serviços externos, sem alvos reais):

```bash
pytest
```

Suíte ponta-a-ponta do lab (mocks locais):

```bash
python lab/run_e2e.py
```

Ambos rodam no CI a cada push/PR (veja o badge de CI acima).

---

## Contribuição

```text
Fork → Branch → Mudanças → Testes → Pull Request
```

Commits seguem [Conventional Commits](https://www.conventionalcommits.org/).
Guia completo (setup de dev, `ruff`, execução do lab): [`CONTRIBUTING.md`](CONTRIBUTING.md).
Reporte bugs e peça features com os
[templates de issue](.github/ISSUE_TEMPLATE/).

---

## Segurança

O GynToolkit é destinado a testes de segurança **autorizados**, pesquisa de
segurança, CTFs e ambientes de laboratório controlados. Para reportar uma
vulnerabilidade **no próprio GynToolkit**, veja [`SECURITY.md`](SECURITY.md) —
por favor não abra uma issue pública para relatos sensíveis.

---

## Disclaimer

O GynToolkit é destinado **exclusivamente** a:

- Testes de segurança **autorizados por escrito**
- Pesquisa acadêmica em ambientes controlados
- Prática de pentest ético (CTF, HackTheBox, TryHackMe, labs próprios)

Qualquer uso contra sistemas ou redes **sem autorização explícita** é
estritamente proibido e constitui crime na maioria das jurisdições. Os autores
não se responsabilizam por uso indevido ou danos causados por este software.

---

## Licença

MIT — veja [`LICENSE`](LICENSE).

---

## Star History

Se este projeto te ajudou, deixe uma ⭐ — ajuda muito na visibilidade!

[![Star History Chart](https://api.star-history.com/svg?repos=flavsjr/gyntoolkit&type=Date)](https://star-history.com/#flavsjr/gyntoolkit&Date)
