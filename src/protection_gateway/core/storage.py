"""Restricted evidence storage.

Objects are written once under a tenant-scoped path with owner-only
permissions. The root must be a separately permissioned encrypted volume
provisioned by B's deployment; an optional cipher hook adds application-
level encryption when B supplies one. Reads enforce the tenant prefix, so
a storage reference alone is not authority.
"""

from __future__ import annotations

import os
import re
import secrets
from typing import Callable, Optional

from ..contracts.enums import ErrorCode
from ..contracts.errors import GatewayError

_SEGMENT = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")


class Cipher:
    """Optional application-level encryption supplied by B."""

    def __init__(self, encrypt: Callable[[bytes], bytes], decrypt: Callable[[bytes], bytes]):
        self.encrypt = encrypt
        self.decrypt = decrypt


class EvidenceStore:
    def __init__(self, root: str, *, permitted: bool, cipher: Optional[Cipher] = None):
        self._root = os.path.realpath(root)
        self._permitted = permitted
        self._cipher = cipher
        if permitted:
            os.makedirs(self._root, mode=0o700, exist_ok=True)
            os.chmod(self._root, 0o700)

    @property
    def available(self) -> bool:
        return self._permitted

    def _require(self) -> None:
        if not self._permitted:
            raise GatewayError(ErrorCode.SERVICE_UNAVAILABLE, "evidence volume not verified as encrypted")

    def _path(self, ref: str, tenant_id: str) -> str:
        parts = ref.split("/")
        if len(parts) != 3 or not all(_SEGMENT.match(p) for p in parts):
            raise GatewayError(ErrorCode.NOT_FOUND, "malformed storage reference")
        kind, ref_tenant, _ = parts
        if ref_tenant != tenant_id:
            raise GatewayError(ErrorCode.NOT_FOUND, "storage tenant mismatch")
        path = os.path.realpath(os.path.join(self._root, *parts))
        if not path.startswith(self._root + os.sep):
            raise GatewayError(ErrorCode.NOT_FOUND, "storage path escape")
        return path

    def put(self, tenant_id: str, kind: str, data: bytes) -> str:
        self._require()
        if not (_SEGMENT.match(tenant_id) and _SEGMENT.match(kind)):
            raise GatewayError(ErrorCode.INVALID_REQUEST, "invalid storage segment")
        ref = f"{kind}/{tenant_id}/{secrets.token_hex(16)}"
        path = self._path(ref, tenant_id)
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        payload = self._cipher.encrypt(data) if self._cipher else data
        # O_EXCL: objects are immutable once written.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        return ref

    def get(self, ref: str, tenant_id: str) -> bytes:
        self._require()
        path = self._path(ref, tenant_id)
        try:
            with open(path, "rb") as handle:
                payload = handle.read()
        except FileNotFoundError as exc:
            raise GatewayError(ErrorCode.NOT_FOUND, "object missing") from exc
        return self._cipher.decrypt(payload) if self._cipher else payload

    def delete(self, ref: str, tenant_id: str) -> None:
        if not self._permitted:
            return
        try:
            os.remove(self._path(ref, tenant_id))
        except FileNotFoundError:
            pass
