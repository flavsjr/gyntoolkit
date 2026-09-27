# Lab de testes local — gyntoolkit

Ambiente isolado (127.0.0.1) para validar módulos de brute-force do `gyntoolkit`
sem tocar em alvos reais. Usa mocks Python (paramiko + aiohttp) — sem Docker,
sem VMs, sem containers.

> **AVISO:** os mocks aceitam credenciais fracas de propósito. Rode apenas em
> `127.0.0.1` e **nunca** exponha em rede pública. Encerre com `Ctrl+C` quando
> terminar.

## Pré-requisitos

- Python 3.10+
- Deps instaladas: `pip install -r requirements.txt`
- Rodar todos os comandos a partir da raiz do projeto (`gyntoolkit/`)

## Estrutura

```
lab/
├── mock_ssh_server.py       # SSH fake em 127.0.0.1:2222
├── mock_http_server.py      # HTTP fake em 127.0.0.1:8080
├── run_e2e.py               # Runner automatizado (sobe mocks + ataca + valida)
└── wordlists/
    ├── users.txt            # 5 users de teste
    └── passwords.txt        # 8 senhas de teste
```

## Credenciais válidas dos mocks

| Alvo | Endpoint | Cred válida |
|------|----------|-------------|
| SSH | `127.0.0.1:2222` | `admin:hunter2`, `root:toor` |
| HTTP Basic Auth | `http://127.0.0.1:8080/basic` | `admin:letmein` |
| HTTP Form POST | `http://127.0.0.1:8080/login` | `admin:s3cret` |

---

## Modo A — Automatizado (recomendado)

Um comando faz tudo: sobe mocks, roda os 3 ataques, valida credenciais
encontradas contra o esperado, encerra mocks.

```powershell
python lab/run_e2e.py
```

**Saída esperada** (resumo):

```
[E2E] === SSH brute-force ===
[+] SSH válido: admin:hunter2
[+] SSH válido: root:toor
[E2E] [OK] SSH PASS

[E2E] === HTTP basic-auth brute-force ===
[+] HTTP válido: admin:letmein
[E2E] [OK] HTTP basic PASS

[E2E] === HTTP form brute-force ===
[+] HTTP válido: admin:s3cret
[E2E] [OK] HTTP form PASS

[E2E] TODOS OS TESTES PASSARAM. [OK]
```

Exit code `0` = sucesso, `1` = alguma falha. Bom p/ CI.

---

## Modo B — Manual, cada lab isolado

Use quando quiser testar via a UI do `gyntoolkit` ou debugar um ataque
específico. Abra **dois terminais** para cada lab: um para o mock, outro
para o `gyntoolkit`.

### Lab 1 — SSH brute-force

**Terminal 1 (mock SSH):**

```powershell
python lab/mock_ssh_server.py
```

Log esperado:
```
Mock SSH escutando em 127.0.0.1:2222 (creds: {'admin': 'hunter2', 'root': 'toor'})
```

Deixe rodando.

**Terminal 2 (gyntoolkit):**

```powershell
python gyntoolkit.py
```

Fluxo do menu:

1. `[2]` Brute Force
2. `[2]` Ataque SSH
3. Ao aviso ético, digitar exatamente: `AUTORIZO`
4. Host alvo: `127.0.0.1`
5. Porta: `2222`
6. Usuário único ou path: `lab/wordlists/users.txt`
7. Path da wordlist de senhas: `lab/wordlists/passwords.txt`
8. Workers: `5` (ou ENTER para default 8)

**Resultado esperado:**
```
[+] SSH válido: admin:hunter2
[+] SSH válido: root:toor
Credenciais encontradas:
  admin:hunter2
  root:toor
```

`Ctrl+C` no Terminal 1 para encerrar mock.

---

### Lab 2 — HTTP Basic Auth brute-force

**Terminal 1 (mock HTTP):**

```powershell
python lab/mock_http_server.py
```

Log esperado:
```
Mock HTTP: /basic (admin:letmein) | /login form (admin:s3cret) em 127.0.0.1:8080
```

**Terminal 2 (gyntoolkit):**

```powershell
python gyntoolkit.py
```

Fluxo do menu:

1. `[2]` Brute Force
2. `[3]` Ataque HTTP
3. `AUTORIZO`
4. URL alvo: `http://127.0.0.1:8080/basic`
5. Modo: `basic` (ou ENTER para default)
6. Usuário único ou path: `lab/wordlists/users.txt`
7. Path da wordlist de senhas: `lab/wordlists/passwords.txt`
8. Workers: ENTER (default 10)

**Resultado esperado:**
```
[+] HTTP válido: admin:letmein
Credenciais encontradas:
  admin:letmein
```

---

### Lab 3 — HTTP Form POST brute-force

Mesmo mock HTTP do Lab 2 (deixe rodando).

**Terminal 2 (gyntoolkit):**

```powershell
python gyntoolkit.py
```

Fluxo do menu:

1. `[2]` Brute Force
2. `[3]` Ataque HTTP
3. `AUTORIZO`
4. URL alvo: `http://127.0.0.1:8080/login`
5. Modo: `form`
6. Campo usuário: `username`
7. Campo senha: `password`
8. Trecho que indica falha: `Invalid credentials`
9. Usuário único ou path: `lab/wordlists/users.txt`
10. Path da wordlist de senhas: `lab/wordlists/passwords.txt`
11. Workers: ENTER

**Resultado esperado:**
```
[+] HTTP válido: admin:s3cret
Credenciais encontradas:
  admin:s3cret
```

`Ctrl+C` no Terminal 1 para encerrar mock.

---

## Adicionar novos labs

Editar os mocks para expor mais serviços ou credenciais:

- **Adicionar cred SSH:** editar `VALID_CREDS` em `mock_ssh_server.py`.
- **Adicionar cred HTTP:** editar `BASIC_USER/BASIC_PASS` ou `FORM_USER/FORM_PASS`
  em `mock_http_server.py`.
- **Novo endpoint HTTP:** adicionar rota em `build_app()` de `mock_http_server.py`.
- **Aumentar wordlist:** adicionar linhas em `lab/wordlists/`.

Atualizar `EXPECTED_*` em `run_e2e.py` sempre que mudar creds válidas.

## Troubleshooting

| Sintoma | Causa | Fix |
|---------|-------|-----|
| `[Errno 10048]` bind | Porta 2222 ou 8080 já em uso | Matar processo antigo (`Get-NetTCPConnection -LocalPort 2222`) |
| `paramiko não instalado` | Deps não instaladas | `pip install -r requirements.txt` |
| Mocks somem sozinhos após `run_e2e` | Comportamento correto — `run_e2e.py` mata os mocks no fim | Rodar manualmente no Modo B para deixar rodando |
| Console mostra `S�o Paulo` | Encoding cp1252 do terminal Windows | Cosmético. `gyntoolkit.log` está UTF-8 |
| SSH brute demora muito | Muitos combos, poucos workers | Aumentar `workers` ou reduzir wordlist |
