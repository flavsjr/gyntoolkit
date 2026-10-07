# Contribuindo com o GynToolkit

Obrigado pelo interesse em contribuir! Este guia cobre o fluxo de trabalho,
padrões de código e como validar suas mudanças antes de abrir um Pull Request.

> **Aviso ético:** o GynToolkit é uma ferramenta de pentest. Contribua apenas
> com funcionalidades destinadas a testes de segurança **autorizados**. PRs que
> visem facilitar uso ofensivo contra alvos sem permissão serão rejeitados.

---

## Sumário

- [Código de conduta](#código-de-conduta)
- [Setup do ambiente de dev](#setup-do-ambiente-de-dev)
- [Fluxo de contribuição](#fluxo-de-contribuição)
- [Padrão de commits](#padrão-de-commits)
- [Style guide](#style-guide)
- [Testes](#testes)
- [Abrindo o Pull Request](#abrindo-o-pull-request)

---

## Código de conduta

Seja respeitoso e objetivo. Discussões técnicas são bem-vindas; ataques pessoais
não. Reporte comportamento inadequado via issue privada ou contato com os mantenedores.

---

## Setup do ambiente de dev

Requer **Python 3.10+**.

```bash
# 1. Fork e clone
git clone https://github.com/<seu-usuario>/gyntoolkit.git
cd gyntoolkit

# 2. Ambiente virtual
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows PowerShell

# 3. Instale em modo editável com as dependências de dev
pip install -e ".[dev]"
```

As dependências de dev (`ruff`, `mypy`, `pytest`) estão declaradas em
`[project.optional-dependencies]` no `pyproject.toml`.

Rode a ferramenta localmente:

```bash
python -m gyntoolkit
```

---

## Fluxo de contribuição

1. Fork o projeto.
2. Crie uma branch descritiva a partir de `master`:
   ```bash
   git checkout -b feature/minha-feature
   ```
3. Implemente a mudança mantendo o estilo do código existente.
4. Rode linter e testes (ver abaixo).
5. Faça commits seguindo Conventional Commits.
6. Abra o Pull Request.

---

## Padrão de commits

Usamos **[Conventional Commits](https://www.conventionalcommits.org/)**. Formato:

```
<tipo>(<escopo opcional>): <descrição no imperativo>
```

Tipos aceitos:

| Tipo       | Uso                                                        |
|------------|------------------------------------------------------------|
| `feat`     | Nova funcionalidade ou módulo                              |
| `fix`      | Correção de bug                                            |
| `docs`     | Mudanças só em documentação                                |
| `test`     | Adição ou ajuste de testes                                 |
| `refactor` | Refatoração sem mudança de comportamento                   |
| `chore`    | Build, deps, tooling, tarefas de manutenção                |
| `style`    | Formatação (sem alterar lógica)                            |
| `perf`     | Melhoria de performance                                    |

Exemplos:

```
feat(recon): adiciona enumeração de buckets S3
fix(scan): corrige timeout do SYN scan em alvos lentos
docs(readme): atualiza matriz de módulos
```

---

## Style guide

O código é padronizado via **[ruff](https://docs.astral.sh/ruff/)** (lint + import sort),
configurado no `pyproject.toml` (`line-length = 100`, regras `E, F, W, I, UP, B, SIM`).

Antes de commitar:

```bash
# Checar problemas
ruff check .

# Corrigir automaticamente o que for possível
ruff check . --fix

# (Opcional) checagem de tipos
mypy gyntoolkit
```

Diretrizes:

- Type hints em funções novas.
- Docstrings curtas explicando intenção (padrão do projeto: português).
- Sem segredos, IPs reais ou credenciais no código ou nos testes.

---

## Testes

### Suite E2E do lab local

O repositório inclui um lab local com servidores mock (SSH/HTTP) e um runner E2E
que exercita os módulos de brute-force ponta a ponta:

```bash
python lab/run_e2e.py
```

O runner sobe os mocks, roda os ataques contra `127.0.0.1`, valida as credenciais
esperadas e encerra. Saída esperada: todos os testes com `[OK]` e exit code `0`.

Rode-o **sempre** antes de abrir um PR que toque em `brute`, `scan` ou no core.

### Testes unitários

```bash
pytest
```

---

## Abrindo o Pull Request

- Descreva **o quê** e **por quê** (não só o quê).
- Referencie a issue relacionada (`Closes #123`).
- Garanta que `ruff check .` passa e que `python lab/run_e2e.py` termina com sucesso.
- Mantenha o PR focado — um objetivo por PR.

Obrigado por contribuir! 🐧
