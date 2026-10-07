#!/usr/bin/env python3
"""Utilitários crypto: hash de texto/arquivo, base64 e decode de JWT."""

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from . import i18n


def hash_text(data: str, algo: str = "sha256") -> str:
    """Hash de string (md5/sha1/sha256/sha512)."""
    h = hashlib.new(algo)
    h.update(data.encode("utf-8"))
    return h.hexdigest()


def hash_file(path: str, algo: str = "sha256") -> str:
    """Hash de arquivo (stream, sem carregar tudo na memória)."""
    p = Path(path).expanduser()
    if not p.is_file():
        return i18n.t("utils.file_not_found", path=p)
    h = hashlib.new(algo)
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def b64_encode(data: str) -> str:
    return base64.b64encode(data.encode("utf-8")).decode("ascii")


def b64_decode(data: str) -> str:
    try:
        # Adiciona padding se faltar
        padded = data + "=" * (-len(data) % 4)
        return base64.b64decode(padded).decode("utf-8", errors="replace")
    except (ValueError, TypeError) as e:
        return i18n.t("utils.decode_err", err=e)


def jwt_decode(token: str) -> dict[str, Any]:
    """Decodifica JWT sem verificar assinatura."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"erro": i18n.t("utils.jwt_parts")}

    def _decode_part(part: str) -> dict[str, Any]:
        padded = part + "=" * (-len(part) % 4)
        raw = base64.urlsafe_b64decode(padded)
        return json.loads(raw)

    try:
        header = _decode_part(parts[0])
        payload = _decode_part(parts[1])
        return {"header": header, "payload": payload, "signature": parts[2]}
    except (ValueError, json.JSONDecodeError) as e:
        return {"erro": i18n.t("utils.jwt_malformed", err=e)}
