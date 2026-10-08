# Contributing to GynToolkit

Thanks for your interest in contributing! This guide covers the workflow, code
standards, and how to validate your changes before opening a Pull Request.

> **Ethical notice:** GynToolkit is a pentest tool. Only contribute features
> intended for **authorized** security testing. PRs that aim to facilitate
> offensive use against targets without permission will be rejected.

---

## Table of Contents

- [Code of conduct](#code-of-conduct)
- [Dev environment setup](#dev-environment-setup)
- [Contribution workflow](#contribution-workflow)
- [Commit convention](#commit-convention)
- [Style guide](#style-guide)
- [Tests](#tests)
- [Opening the Pull Request](#opening-the-pull-request)

---

## Code of conduct

Be respectful and objective. Technical discussion is welcome; personal attacks
are not. Report inappropriate behavior via a private issue or by contacting the
maintainers. See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

---

## Dev environment setup

Requires **Python 3.10+**.

```bash
# 1. Fork and clone
git clone https://github.com/<your-username>/gyntoolkit.git
cd gyntoolkit

# 2. Virtual environment
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows PowerShell

# 3. Install in editable mode with the dev dependencies
pip install -e ".[dev]"

# 4. Enable the pre-commit hooks (ruff + mypy on each commit)
pre-commit install
```

The dev dependencies (`ruff`, `mypy`, `pytest`, `pre-commit`) are declared under
`[project.optional-dependencies]` in `pyproject.toml`.

The pre-commit hooks run `ruff check --fix` and `mypy gyntoolkit` before each
commit (same tools as CI). Run them manually on everything with
`pre-commit run --all-files`.

Run the tool locally:

```bash
python -m gyntoolkit
```

---

## Contribution workflow

1. Fork the project.
2. Create a descriptive branch off `master`:
   ```bash
   git checkout -b feature/my-feature
   ```
3. Implement the change, matching the existing code style.
4. Run the linter and tests (see below).
5. Commit following Conventional Commits.
6. Open the Pull Request.

---

## Commit convention

We use **[Conventional Commits](https://www.conventionalcommits.org/)**. Format:

```
<type>(<optional scope>): <imperative description>
```

Accepted types:

| Type       | Use                                                        |
|------------|------------------------------------------------------------|
| `feat`     | New feature or module                                      |
| `fix`      | Bug fix                                                    |
| `docs`     | Documentation-only changes                                 |
| `test`     | Adding or adjusting tests                                  |
| `refactor` | Refactoring with no behavior change                        |
| `chore`    | Build, deps, tooling, maintenance tasks                    |
| `style`    | Formatting (no logic change)                               |
| `perf`     | Performance improvement                                    |

Examples:

```
feat(recon): add S3 bucket enumeration
fix(scan): fix SYN scan timeout on slow targets
docs(readme): update module matrix
```

---

## Style guide

Code is standardized with **[ruff](https://docs.astral.sh/ruff/)** (lint + import
sort), configured in `pyproject.toml` (`line-length = 100`, rules `E, F, W, I,
UP, B, SIM`).

Before committing:

```bash
# Check for issues
ruff check .

# Auto-fix what is possible
ruff check . --fix

# (Optional) type checking
mypy gyntoolkit
```

Guidelines:

- Type hints on new functions.
- Short docstrings explaining intent. The existing codebase uses Portuguese
  docstrings — match the surrounding style within a file.
- No secrets, real IPs, or credentials in code or tests.

---

## Tests

### Local lab E2E suite

The repository includes a local lab with mock servers (SSH/HTTP) and an E2E
runner that exercises the brute-force modules end to end:

```bash
python lab/run_e2e.py
```

The runner starts the mocks, runs the attacks against `127.0.0.1`, validates the
expected credentials, and shuts down. Expected output: all tests `[OK]` and exit
code `0`.

Run it **always** before opening a PR that touches `brute`, `scan`, or the core.

### Unit tests

```bash
pytest
```

Tests are offline (no network, no real targets). CI enforces a coverage gate on
the core logic (display layers `cli.py`/`ui.py` are excluded, exercised by the
e2e lab). Check it locally:

```bash
pytest --cov=gyntoolkit --cov-report=term-missing --cov-fail-under=60
```

---

## Opening the Pull Request

- Describe **what** and **why** (not just what).
- Reference the related issue (`Closes #123`).
- Make sure `ruff check .` passes and `python lab/run_e2e.py` finishes
  successfully.
- Keep the PR focused — one goal per PR.

Thanks for contributing! 🐧
