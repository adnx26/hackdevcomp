"""Durable SQLite metadata store.

Holds IDs, hashes, states, bindings and storage references. Raw content,
model output and evidence text live in the evidence store, not here (the
only exceptions are user-authored simulated action arguments and review
reasons, which belong to the user's own action/review records).
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS browser_sessions (
    session_hash TEXT PRIMARY KEY,
    csrf_hash TEXT NOT NULL,
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS labels (
    label_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    disclosure TEXT NOT NULL,
    source_resource_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resources (
    resource_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    media_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    original_hash TEXT NOT NULL,
    storage_ref TEXT,
    label_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    evidence_expires_at TEXT NOT NULL,
    deleted_at TEXT
);

CREATE TABLE IF NOT EXISTS task_sessions (
    task_session_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    scope_version INTEGER NOT NULL,
    context_version INTEGER NOT NULL,
    resource_ids_json TEXT NOT NULL,
    created_by_channel TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    canceled_at TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    task_session_id TEXT NOT NULL,
    task_scope_version INTEGER NOT NULL,
    context_version INTEGER NOT NULL,
    policy_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    resource_set_hash TEXT NOT NULL,
    resource_ids_json TEXT NOT NULL,
    model_configuration_hash TEXT NOT NULL,
    roster_hash TEXT NOT NULL,
    context_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    decision TEXT,
    reason_codes_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deadline_at TEXT NOT NULL,
    decided_at TEXT,
    decision_expires_at TEXT
);
CREATE INDEX IF NOT EXISTS scans_owner ON scans (tenant_id, owner_id, state);

CREATE TABLE IF NOT EXISTS extractions (
    scan_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    status TEXT NOT NULL,
    extractor_version TEXT,
    views_json TEXT NOT NULL DEFAULT '[]',
    unsupported_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, resource_id)
);

CREATE TABLE IF NOT EXISTS assignments (
    assignment_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    role TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    build_version TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    state TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    assignment_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS assignments_scan ON assignments (scan_id, role);

CREATE TABLE IF NOT EXISTS job_tokens (
    token_hash TEXT PRIMARY KEY,
    assignment_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS worker_results (
    assignment_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    role TEXT NOT NULL,
    nonce TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    inspection_status TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    telemetry_json TEXT NOT NULL,
    task_output_ref TEXT,
    answer_mismatch INTEGER NOT NULL DEFAULT 0,
    received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS seen_nonces (
    nonce TEXT PRIMARY KEY,
    assignment_id TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    storage_ref TEXT,
    collector_event_id TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    deleted_at TEXT
);

CREATE TABLE IF NOT EXISTS collector_events (
    event_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    operation TEXT NOT NULL,
    argument_digest TEXT NOT NULL,
    attempted_outcome TEXT NOT NULL,
    policy_check TEXT NOT NULL,
    effective_policy_check TEXT NOT NULL,
    event_timestamp TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    event_digest TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    received_at TEXT NOT NULL,
    UNIQUE (run_id, sequence)
);

CREATE TABLE IF NOT EXISTS scan_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outputs (
    scan_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    output_digest TEXT NOT NULL,
    storage_ref TEXT,
    label_ids_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    deleted_at TEXT
);

CREATE TABLE IF NOT EXISTS review_exceptions (
    exception_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    context_hash TEXT NOT NULL,
    resource_set_hash TEXT NOT NULL,
    resource_ids_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    task_session_id TEXT NOT NULL,
    task_scope_version INTEGER NOT NULL,
    context_hash TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    operation TEXT NOT NULL,
    arguments_json TEXT NOT NULL,
    attachments_json TEXT NOT NULL,
    label_ids_json TEXT NOT NULL,
    recipient_trust TEXT NOT NULL,
    digest TEXT NOT NULL,
    state TEXT NOT NULL,
    proposed_by_channel TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    outcome_json TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    recipient_selected_by_user INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS idempotency (
    scope TEXT NOT NULL,
    idem_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope, idem_key)
);

CREATE TABLE IF NOT EXISTS dummy_mailbox (
    effect_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    recipient TEXT NOT NULL,
    subject TEXT NOT NULL,
    body_sha256 TEXT NOT NULL,
    attachments_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class Database:
    """Serialized access to one SQLite database.

    ``transaction()`` takes an immediate write lock so state transitions
    (approval use, result acceptance, decisions) are atomic.
    """

    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._depth = 0
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            if path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.executescript(SCHEMA)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            outermost = self._depth == 0
            if outermost:
                self._conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield self._conn
            except BaseException:
                self._depth -= 1
                if outermost:
                    self._conn.execute("ROLLBACK")
                raise
            else:
                self._depth -= 1
                if outermost:
                    self._conn.execute("COMMIT")

    def query_one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def query_all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self.transaction() as conn:
            return conn.execute(sql, params)

    def close(self) -> None:
        with self._lock:
            self._conn.close()
