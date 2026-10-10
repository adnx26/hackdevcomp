"""Gateway core configuration.

B's bootstrap builds this from deployment configuration and injects secrets
from outside the repository. Defaults follow the master design's proposed
demo limits and retention periods.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Mapping

from ..contracts.canonical import canonical_digest
from ..contracts.enums import INSPECTION_ROLES, WorkerRole

MIB = 1024 * 1024


@dataclass(frozen=True)
class Limits:
    max_source_bytes: int = 1 * MIB
    max_task_bytes: int = 2 * MIB
    max_task_sources: int = 10
    max_extracted_chars: int = 100_000
    max_request_bytes: int = 1 * MIB * 4 // 3 + 64 * 1024  # base64 upload + envelope
    scan_deadline_seconds: int = 60
    worker_lease_seconds: int = 25
    worker_retries: int = 1
    max_concurrent_scans_per_user: int = 2
    model_token_budget: int = 20_000
    max_findings: int = 50
    max_artifacts: int = 20
    max_artifact_chars: int = 8_000
    evidence_view_chars: int = 4_000
    max_attachments: int = 5


@dataclass(frozen=True)
class Retention:
    evidence_seconds: int = 24 * 3600
    metadata_seconds: int = 7 * 24 * 3600
    job_token_seconds: int = 300
    browser_session_seconds: int = 8 * 3600
    task_session_seconds: int = 3600
    decision_seconds: int = 3600
    action_proposal_seconds: int = 600
    approval_seconds: int = 300
    review_exception_max_seconds: int = 3600


@dataclass(frozen=True)
class DemoIdentity:
    """Server-configured test identity. Only the token's SHA-256 is kept."""

    token_sha256: str
    user_id: str
    tenant_id: str


@dataclass(frozen=True)
class RosterEntry:
    worker_id: str
    role: str
    build_version: str
    prompt_version: str

    def as_dict(self) -> dict:
        return {
            "worker_id": self.worker_id,
            "role": self.role,
            "build_version": self.build_version,
            "prompt_version": self.prompt_version,
        }


@dataclass(frozen=True)
class GatewayConfig:
    database_path: str
    evidence_root: str
    identities: tuple[DemoIdentity, ...] = ()
    worker_roster: tuple[RosterEntry, ...] = ()
    collector_ids: frozenset[str] = frozenset()
    model_configuration: Mapping = field(default_factory=dict)
    # tenant_id -> user_id -> approved contact addresses (lowercase)
    trusted_contacts: Mapping[str, Mapping[str, frozenset[str]]] = field(default_factory=dict)
    # The evidence root must sit on a separately permissioned encrypted
    # volume (B's deployment). Development may opt out explicitly.
    evidence_volume_encrypted: bool = False
    allow_unencrypted_dev_storage: bool = False
    cookie_secure: bool = True
    public_origin: str | None = None
    limits: Limits = field(default_factory=Limits)
    retention: Retention = field(default_factory=Retention)

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def roster_entry(self, role: str) -> RosterEntry | None:
        for entry in self.worker_roster:
            if entry.role == role:
                return entry
        return None

    def roster_complete(self) -> bool:
        return all(self.roster_entry(role.value) for role in INSPECTION_ROLES) and bool(
            self.roster_entry(WorkerRole.EXTRACTOR.value)
        )

    @property
    def roster_hash(self) -> str:
        return canonical_digest(sorted((e.as_dict() for e in self.worker_roster), key=lambda e: e["role"]))

    @property
    def model_configuration_hash(self) -> str:
        return canonical_digest(dict(self.model_configuration))

    def storage_permitted(self) -> bool:
        return self.evidence_volume_encrypted or self.allow_unencrypted_dev_storage

    def is_trusted_contact(self, tenant_id: str, user_id: str, address: str) -> bool:
        return address.lower() in self.trusted_contacts.get(tenant_id, {}).get(user_id, frozenset())
