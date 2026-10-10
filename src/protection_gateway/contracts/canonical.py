"""Canonical serialization and hashing.

Policy, action, output and binding digests are SHA-256 over this exact
serialization. D and other consumers use these functions unchanged.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _reject_unsupported(value: Any, path: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, (str, int)):
        return
    if isinstance(value, float):
        raise ValueError(f"{path}: floats are not canonical; use decimal strings")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path}: object keys must be strings")
            _reject_unsupported(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_unsupported(item, f"{path}[{index}]")
        return
    raise ValueError(f"{path}: unsupported type {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """UTF-8 JSON with sorted keys, no insignificant whitespace, no floats."""
    _reject_unsupported(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_digest(value: Any) -> str:
    return sha256_hex(canonical_json(value))
