"""Small strict validators built from the standard library.

Each checker is ``check(value, path) -> value`` and raises ContractError.
Objects reject unexpected fields.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from .errors import ContractError

Checker = Callable[[Any, str], Any]

ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-:.]{1,128}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")


def string(*, min_len: int = 0, max_len: int = 1024, pattern: re.Pattern | None = None) -> Checker:
    def check(value: Any, path: str) -> str:
        if not isinstance(value, str):
            raise ContractError(path, "expected string")
        if not min_len <= len(value) <= max_len:
            raise ContractError(path, f"length must be within [{min_len}, {max_len}]")
        if pattern is not None and not pattern.match(value):
            raise ContractError(path, "invalid format")
        return value

    return check


opaque_id = string(min_len=1, max_len=128, pattern=ID_PATTERN)
sha256 = string(min_len=64, max_len=64, pattern=SHA256_PATTERN)


def timestamp(value: Any, path: str) -> str:
    if not isinstance(value, str) or not TIMESTAMP_PATTERN.match(value):
        raise ContractError(path, "expected UTC ISO 8601 timestamp ending in Z")
    try:
        datetime.fromisoformat(value[:-1]).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ContractError(path, "invalid timestamp") from exc
    return value


def literal(expected: Any) -> Checker:
    def check(value: Any, path: str) -> Any:
        if value != expected or type(value) is not type(expected):
            raise ContractError(path, f"expected {expected!r}")
        return value

    return check


def enum(values: Iterable[str]) -> Checker:
    allowed = frozenset(values)

    def check(value: Any, path: str) -> str:
        if not isinstance(value, str) or value not in allowed:
            raise ContractError(path, "unsupported enum value")
        return value

    return check


def integer(*, minimum: int = 0, maximum: int = 2**53) -> Checker:
    def check(value: Any, path: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ContractError(path, "expected integer")
        if not minimum <= value <= maximum:
            raise ContractError(path, f"must be within [{minimum}, {maximum}]")
        return value

    return check


def boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(path, "expected boolean")
    return value


def list_of(item: Checker, *, min_items: int = 0, max_items: int = 100, unique: bool = False) -> Checker:
    def check(value: Any, path: str) -> list:
        if not isinstance(value, list):
            raise ContractError(path, "expected array")
        if not min_items <= len(value) <= max_items:
            raise ContractError(path, f"item count must be within [{min_items}, {max_items}]")
        result = [item(element, f"{path}[{index}]") for index, element in enumerate(value)]
        if unique:
            seen = set()
            for element in result:
                key = repr(element)
                if key in seen:
                    raise ContractError(path, "duplicate items")
                seen.add(key)
        return result

    return check


def obj(required: Mapping[str, Checker], optional: Mapping[str, Checker] | None = None) -> Checker:
    optional = optional or {}

    def check(value: Any, path: str) -> dict:
        if not isinstance(value, dict):
            raise ContractError(path, "expected object")
        unexpected = set(value) - set(required) - set(optional)
        if unexpected:
            raise ContractError(path, "unexpected fields: " + ",".join(sorted(unexpected)))
        result = {}
        for name, checker in required.items():
            if name not in value:
                raise ContractError(f"{path}.{name}", "required")
            result[name] = checker(value[name], f"{path}.{name}")
        for name, checker in optional.items():
            if name in value:
                result[name] = checker(value[name], f"{path}.{name}")
        return result

    return check


def one_of(*checkers: Checker) -> Checker:
    def check(value: Any, path: str) -> Any:
        problems = []
        for checker in checkers:
            try:
                return checker(value, path)
            except ContractError as exc:
                problems.append(exc.problem)
        raise ContractError(path, "matched no allowed shape")

    return check
