"""Known-vendor registry and the deterministic bank-details check.

If extracted content mentions a registered vendor and contains an IBAN that is
not that vendor's registered account, the core holds the content for review
(VENDOR_BANK_MISMATCH). This is plain code over the extracted views: no model
is involved, and an inspector cannot clear it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

# IBANs as printed: contiguous, or in groups of four with one shorter final group. Uppercase, as
# banks print them, so neighbouring words ("or", "to") are not absorbed into the final group.
_IBAN = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2}[0-9]{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?))(?![A-Za-z0-9])")


def normalize_iban(value: str) -> str:
    return "".join(str(value).split()).upper()


def find_ibans(text: str) -> set[str]:
    found = set()
    for match in _IBAN.finditer(text):
        candidate = normalize_iban(match.group(1))
        if 15 <= len(candidate) <= 34:
            found.add(candidate)
    return found


@dataclass(frozen=True)
class Vendor:
    name: str
    names: tuple[str, ...]  # lowercase name and aliases used to detect a mention
    ibans: frozenset[str]


def load_registry(path: str | None) -> tuple[Vendor, ...]:
    if not path:
        return ()
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    vendors = []
    for entry in raw.get("vendors", []) if isinstance(raw, dict) else []:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            continue
        names = tuple(n.lower() for n in [entry["name"], *entry.get("aliases", [])] if isinstance(n, str) and len(n) >= 3)
        ibans = frozenset(normalize_iban(i) for i in entry.get("ibans", []) if isinstance(i, str))
        if names and ibans:
            vendors.append(Vendor(entry["name"], names, ibans))
    return tuple(vendors)


def bank_mismatch(texts: list[str], registry: tuple[Vendor, ...]) -> bool:
    """True when a registered vendor is mentioned and an IBAN in the content is not one of its registered accounts."""
    if not registry or not texts:
        return False
    combined = "\n".join(texts)
    lowered = combined.lower()
    mentioned = [v for v in registry if any(name in lowered for name in v.names)]
    if not mentioned:
        return False
    registered = set().union(*(v.ibans for v in mentioned))
    return any(iban not in registered for iban in find_ibans(combined))
