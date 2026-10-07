# Installation

**Requirements:** Python 3.10+ and `pip`.

## From source

```bash
git clone https://github.com/flavsjr/gyntoolkit.git
cd gyntoolkit
pip install -r requirements.txt
python -m gyntoolkit
```

## Editable install (CLI command)

```bash
pip install -e .
gyntoolkit
```

The entry point `gyntoolkit` is defined in `pyproject.toml`
(`[project.scripts] gyntoolkit = "gyntoolkit.cli:main_entry"`).

## Optional: CUPP wordlist generator

```bash
git clone https://github.com/Mebus/cupp.git
```

Used by the brute-force "CUPP wordlist" module (wrapper for `cupp.py -i`).

## Windows: raw sockets (SYN scan / traceroute)

Install [Npcap](https://npcap.com) and run GynToolkit in an **administrator**
terminal. Without Npcap the SYN scan degrades to a TCP connect scan automatically.

## Maintainer: publishing to PyPI

The package metadata is release-ready. To publish:

```bash
pip install build twine
python -m build            # builds sdist + wheel into dist/
twine check dist/*
twine upload dist/*        # requires a PyPI account + token
```

> `pip install gyntoolkit` works only **after** a maintainer has published the
> package. Until then, use the source or editable install above.
