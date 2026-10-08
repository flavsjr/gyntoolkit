# Installation

**Requirements:** Python 3.10+ and `pip`.

## From PyPI (recommended)

```bash
pip install gyntoolkit
gyntoolkit
```

This installs the `gyntoolkit` command and all runtime dependencies.

## From source (development)

```bash
git clone https://github.com/flavsjr/gyntoolkit.git
cd gyntoolkit
pip install -e .
gyntoolkit            # or: python -m gyntoolkit
```

The entry point `gyntoolkit` is defined in `pyproject.toml`
(`[project.scripts] gyntoolkit = "gyntoolkit.cli:main_entry"`).

## Optional: CUPP wordlist generator

```bash
git clone https://github.com/Mebus/cupp.git
```

Used by the brute-force "CUPP wordlist" module (wrapper for `cupp.py -i`). It is
third-party code cloned on demand — not a Python dependency, not installed by pip.

## Windows: raw sockets (SYN scan / traceroute)

Install [Npcap](https://npcap.com) and run GynToolkit in an **administrator**
terminal. Without Npcap the SYN scan degrades to a TCP connect scan automatically.

## Maintainer: publishing to PyPI

Releases are published automatically by the
[`publish.yml`](../.github/workflows/publish.yml) workflow via PyPI
**Trusted Publishing** (OIDC) — no token or secret is stored in the repository.

One-time setup (web): register this repository as a trusted publisher for the
`gyntoolkit` project at <https://pypi.org/manage/account/publishing/>
(workflow: `publish.yml`, environment: `pypi`).

To cut a release, publish a GitHub Release with the version tag:

```bash
gh release create vX.Y.Z --title "vX.Y.Z" --notes "..."
```

The workflow builds the sdist + wheel, runs `twine check`, and uploads to PyPI.
