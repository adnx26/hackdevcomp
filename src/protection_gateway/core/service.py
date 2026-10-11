"""Trusted gateway core service.

Every public method takes a server-derived ``Principal`` and performs the
same authorization whether it is called over HTTP, by D's MCP adapter, or
in process. Runtime-facing methods take identities verified by B and are
re-checked against persisted assignments. Agents supply evidence; only this
module changes job state, releases content or authorizes an effect.
"""

from __future__ import annotations

import base64
import binascii
import html
import json
import logging
import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable, Mapping, Optional

from ..contracts import schemas
from ..contracts.canonical import canonical_digest, sha256_hex
from ..contracts.enums import (
    ACTIVE_JOB_STATES,
    CONTRACT_VERSION,
    INSPECTION_ROLES,
    ActionState,
    Channel,
    Decision,
    Disclosure,
    ErrorCode,
    ExtractionStatus,
    FindingCategory,
    InspectionStatus,
    JobState,
    PolicyCheck,
    ReasonCode,
    ReviewAction,
    StorageState,
    WorkerRole,
)
from ..contracts.errors import ContractError, GatewayError
from ..contracts.policies import OUTPUT_INVOICE, TaskPolicy, get_policy
from ..contracts.validation import ID_PATTERN
from .auth import Principal
from .clock import Clock, IdFactory, RandomIds, SystemClock, after, iso, parse_iso
from .config import GatewayConfig
from .db import Database
from .decisions import DecisionInputs, DecisionOutcome, RoleResult, decide, review_exception_eligible
from .runtime_api import ActionExecutor, RuntimeCallbacks
from .storage import Cipher, EvidenceStore

log = logging.getLogger("protection_gateway.core")

ALL_CHANNELS = frozenset(Channel)
WRITE_CHANNELS = frozenset({Channel.USER_INTERFACE, Channel.API, Channel.ASSISTANT})
USER_ONLY = frozenset({Channel.USER_INTERFACE})
EVIDENCE_CHANNELS = frozenset({Channel.USER_INTERFACE, Channel.API})

LIVE_ASSIGNMENT_STATES = ("ASSIGNED", "DELIVERED")


def _loads(value: str | None, default: Any = None) -> Any:
    return default if value is None else json.loads(value)


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class GatewayService:
    def __init__(
        self,
        config: GatewayConfig,
        *,
        runtime: Optional[RuntimeCallbacks] = None,
        clock: Optional[Clock] = None,
        ids: Optional[IdFactory] = None,
        db: Optional[Database] = None,
        cipher: Optional[Cipher] = None,
        executor: Optional[ActionExecutor] = None,
    ):
        self.config = config
        self.runtime = runtime
        self.clock = clock or SystemClock()
        self.ids = ids or RandomIds()
        self.db = db or Database(config.database_path)
        self.store = EvidenceStore(config.evidence_root, permitted=config.storage_permitted(), cipher=cipher)
        from .actions import ActionGate, SimulatedMailboxExecutor

        self.actions = ActionGate(self, executor or SimulatedMailboxExecutor())

    # ------------------------------------------------------------------ utils

    def _now(self) -> datetime:
        return self.clock.now()

    def _now_iso(self) -> str:
        return iso(self._now())

    @staticmethod
    def _require_channel(principal: Principal, allowed: Iterable[Channel]) -> None:
        if not isinstance(principal, Principal):
            raise GatewayError(ErrorCode.UNAUTHENTICATED, "no verified principal")
        if principal.channel not in allowed:
            raise GatewayError(ErrorCode.FORBIDDEN, f"channel {principal.channel.value} not permitted")

    def _event(self, conn, scan_id: str, tenant_id: str, event_type: str, **detail: Any) -> None:
        """Append-only scan history. Detail holds IDs and codes only."""
        conn.execute(
            "INSERT INTO scan_events (scan_id, tenant_id, event_type, detail_json, at) VALUES (?, ?, ?, ?, ?)",
            (scan_id, tenant_id, event_type, _dumps(detail), self._now_iso()),
        )
        log.info("scan_event scan_id=%s type=%s", scan_id, event_type)

    def _owned(self, table: str, key: str, value: str, principal: Principal):
        """Tenant- and owner-scoped lookup. Others' objects look nonexistent."""
        if not isinstance(value, str) or not ID_PATTERN.match(value):
            raise GatewayError(ErrorCode.NOT_FOUND, "malformed id")
        owner_col = "user_id" if table == "review_exceptions" else "owner_id"
        row = self.db.query_one(
            f"SELECT * FROM {table} WHERE {key} = ? AND tenant_id = ? AND {owner_col} = ?",
            (value, principal.tenant_id, principal.user_id),
        )
        if row is None:
            raise GatewayError(ErrorCode.NOT_FOUND, f"{table} not found")
        return row

    def _require_runtime(self) -> None:
        if self.runtime is None:
            raise GatewayError(ErrorCode.SERVICE_UNAVAILABLE, "runtime not configured")
        if not self.config.roster_complete():
            raise GatewayError(ErrorCode.SERVICE_UNAVAILABLE, "worker roster incomplete")
        if not self.store.available:
            raise GatewayError(ErrorCode.SERVICE_UNAVAILABLE, "evidence store unavailable")

    def _cancel_runtime(self, scan_id: str) -> None:
        if self.runtime is None:
            return
        try:
            self.runtime.cancel(scan_id)
        except Exception as exc:  # gateway-side revocation already happened
            log.warning("runtime_cancel_failed scan_id=%s error=%s", scan_id, type(exc).__name__)

    # -------------------------------------------------------------- resources

    def upload_resource(self, principal: Principal, body: Mapping) -> dict:
        self._require_channel(principal, WRITE_CHANNELS)
        req = schemas.validate(schemas.resource_upload_request, body)
        self._require_not_stopped()
        if req["media_type"] not in schemas.SUPPORTED_MEDIA_TYPES:
            raise GatewayError(ErrorCode.INVALID_REQUEST, "unsupported media type")
        limit = self.config.limits.max_source_bytes
        if len(req["content_base64"]) > (limit + 2) // 3 * 4:
            raise GatewayError(ErrorCode.LIMIT_EXCEEDED, "source too large", retryable=False)
        try:
            data = base64.b64decode(req["content_base64"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise GatewayError(ErrorCode.INVALID_REQUEST, "invalid base64") from exc
        if len(data) > limit:
            raise GatewayError(ErrorCode.LIMIT_EXCEEDED, "source too large", retryable=False)
        if not self.store.available:
            raise GatewayError(ErrorCode.SERVICE_UNAVAILABLE, "evidence store unavailable")

        resource_id = self.ids.new("res")
        label_id = self.ids.new("lbl")
        original_hash = sha256_hex(data)
        ref = self.store.put(principal.tenant_id, "original", data)
        now = self._now()
        evidence_expiry = iso(after(now, self.config.retention.evidence_seconds))
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO labels VALUES (?, ?, ?, ?, ?, ?)",
                (label_id, principal.tenant_id, principal.user_id, Disclosure.PRIVATE_TO_OWNER.value, resource_id, iso(now)),
            )
            conn.execute(
                "INSERT INTO resources VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    resource_id, principal.tenant_id, principal.user_id, req["media_type"], len(data),
                    original_hash, ref, label_id, iso(now), evidence_expiry,
                ),
            )
        log.info("resource_stored resource_id=%s size=%d", resource_id, len(data))
        return {
            "resource_id": resource_id,
            "original_hash": original_hash,
            "storage_state": StorageState.STORED.value,
            "media_type": req["media_type"],
            "size_bytes": len(data),
            "expires_at": evidence_expiry,
        }

    def delete_resource(self, principal: Principal, resource_id: str) -> dict:
        """Delete stored bytes and derived artifacts; revoke dependent access."""
        self._require_channel(principal, frozenset({Channel.USER_INTERFACE, Channel.API}))
        row = self._owned("resources", "resource_id", resource_id, principal)
        if row["deleted_at"]:
            return {"resource_id": resource_id, "deleted": True}
        self._purge_resource(row, ReasonCode.RESOURCE_DELETED)
        return {"resource_id": resource_id, "deleted": True}

    def _purge_resource(self, row, reason: ReasonCode) -> None:
        tenant = row["tenant_id"]
        resource_id = row["resource_id"]
        now_iso = self._now_iso()
        if row["storage_ref"]:
            self.store.delete(row["storage_ref"], tenant)
        affected = [
            s for s in self.db.query_all("SELECT * FROM scans WHERE tenant_id = ?", (tenant,))
            if resource_id in _loads(s["resource_ids_json"], [])
        ]
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE resources SET deleted_at = ?, storage_ref = NULL WHERE resource_id = ?", (now_iso, resource_id)
            )
            self.actions.purge_resource_actions(conn, tenant, row["label_id"])
            for scan in affected:
                self._purge_scan_content(conn, scan)
                if scan["state"] in ACTIVE_JOB_STATES:
                    self._terminate(conn, scan, JobState.CANCELED, [reason.value])
        for scan in affected:
            if scan["state"] in ACTIVE_JOB_STATES:
                self._cancel_runtime(scan["scan_id"])

    def _purge_scan_content(self, conn, scan) -> None:
        tenant = scan["tenant_id"]
        scan_id = scan["scan_id"]
        now_iso = self._now_iso()
        for ext in conn.execute("SELECT views_json FROM extractions WHERE scan_id = ?", (scan_id,)).fetchall():
            for view in _loads(ext["views_json"], []):
                for key in ("storage_ref", "source_map_ref"):
                    if view.get(key):
                        self.store.delete(view[key], tenant)
        conn.execute("UPDATE extractions SET views_json = '[]' WHERE scan_id = ?", (scan_id,))
        for res in conn.execute("SELECT task_output_ref FROM worker_results WHERE scan_id = ?", (scan_id,)).fetchall():
            if res["task_output_ref"]:
                self.store.delete(res["task_output_ref"], tenant)
        conn.execute("UPDATE worker_results SET task_output_ref = NULL WHERE scan_id = ?", (scan_id,))
        for ev in conn.execute(
            "SELECT evidence_id, storage_ref FROM evidence WHERE scan_id = ? AND deleted_at IS NULL", (scan_id,)
        ).fetchall():
            if ev["storage_ref"]:
                self.store.delete(ev["storage_ref"], tenant)
        conn.execute(
            "UPDATE evidence SET deleted_at = ?, storage_ref = NULL WHERE scan_id = ? AND deleted_at IS NULL",
            (now_iso, scan_id),
        )
        out = conn.execute("SELECT storage_ref FROM outputs WHERE scan_id = ?", (scan_id,)).fetchone()
        if out and out["storage_ref"]:
            self.store.delete(out["storage_ref"], tenant)
        conn.execute("UPDATE outputs SET deleted_at = ?, storage_ref = NULL WHERE scan_id = ?", (now_iso, scan_id))
        conn.execute(
            "UPDATE review_exceptions SET revoked_at = ? WHERE scan_id = ? AND revoked_at IS NULL", (now_iso, scan_id)
        )
        conn.execute(
            "UPDATE job_tokens SET revoked_at = ? WHERE scan_id = ? AND revoked_at IS NULL", (now_iso, scan_id)
        )

    def _load_resources(self, principal: Principal, resource_ids: list[str]) -> list:
        rows = []
        for resource_id in resource_ids:
            row = self._owned("resources", "resource_id", resource_id, principal)
            if row["deleted_at"] or parse_iso(row["evidence_expires_at"]) <= self._now():
                raise GatewayError(ErrorCode.NOT_FOUND, "resource expired")
            rows.append(row)
        if len(rows) > self.config.limits.max_task_sources:
            raise GatewayError(ErrorCode.LIMIT_EXCEEDED, "too many sources", retryable=False)
        if sum(r["size_bytes"] for r in rows) > self.config.limits.max_task_bytes:
            raise GatewayError(ErrorCode.LIMIT_EXCEEDED, "task too large", retryable=False)
        return rows

    # ---------------------------------------------------------- task sessions

    def create_task_session(self, principal: Principal, body: Mapping) -> dict:
        self._require_channel(principal, WRITE_CHANNELS)
        req = schemas.validate(schemas.task_session_request, body)
        policy = get_policy(req["policy_id"])
        # Classification or an assistant may suggest; only the user grants
        # a capability that goes beyond read-only.
        if principal.channel == Channel.ASSISTANT and not policy.read_only:
            raise GatewayError(ErrorCode.FORBIDDEN, "assistant cannot select a write-capable policy")
        self._load_resources(principal, req["resource_ids"])
        task_session_id = self.ids.new("ts")
        now = self._now()
        expires = iso(after(now, self.config.retention.task_session_seconds))
        self.db.execute(
            "INSERT INTO task_sessions VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?, ?, ?, NULL)",
            (
                task_session_id, principal.tenant_id, principal.user_id, policy.policy_id, policy.version,
                policy.policy_hash, _dumps(req["resource_ids"]), principal.channel.value, iso(now), iso(now), expires,
            ),
        )
        return self.get_task_session(principal, task_session_id)

    def get_task_session(self, principal: Principal, task_session_id: str) -> dict:
        self._require_channel(principal, ALL_CHANNELS)
        row = self._owned("task_sessions", "task_session_id", task_session_id, principal)
        return {
            "task_session_id": row["task_session_id"],
            "policy_id": row["policy_id"],
            "policy_version": row["policy_version"],
            "policy_hash": row["policy_hash"],
            "task_scope_version": row["scope_version"],
            "context_version": row["context_version"],
            "resource_ids": _loads(row["resource_ids_json"]),
            # Server-owned disclosure constraints bound to this session.
            "disclosure": [
                {"resource_id": r["resource_id"], "label_id": r["label_id"], "disclosure": r["disclosure"]}
                for r in self.db.query_all(
                    "SELECT res.resource_id, res.label_id, l.disclosure FROM resources res "
                    "JOIN labels l ON l.label_id = res.label_id WHERE res.tenant_id = ? AND res.owner_id = ? "
                    "ORDER BY res.resource_id",
                    (row["tenant_id"], row["owner_id"]),
                )
                if r["resource_id"] in _loads(row["resource_ids_json"])
            ],
            "expires_at": row["expires_at"],
            "active": self._session_active(row),
        }

    def _session_active(self, row) -> bool:
        return not row["canceled_at"] and parse_iso(row["expires_at"]) > self._now()

    def _active_session(self, principal: Principal, task_session_id: str):
        row = self._owned("task_sessions", "task_session_id", task_session_id, principal)
        if not self._session_active(row):
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "task session inactive")
        return row

    def update_task_session(self, principal: Principal, task_session_id: str, body: Mapping) -> dict:
        """Change the resource set. Creates a new scope version and
        invalidates pending approvals and cached decisions."""
        self._require_channel(principal, WRITE_CHANNELS)
        req = schemas.validate(schemas.task_session_update_request, body)
        row = self._active_session(principal, task_session_id)
        if principal.channel == Channel.ASSISTANT and not get_policy(row["policy_id"]).read_only:
            raise GatewayError(ErrorCode.FORBIDDEN, "assistant cannot change a write-capable session")
        self._load_resources(principal, req["resource_ids"])
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE task_sessions SET resource_ids_json = ?, scope_version = scope_version + 1, updated_at = ? "
                "WHERE task_session_id = ?",
                (_dumps(req["resource_ids"]), self._now_iso(), task_session_id),
            )
            self.actions.invalidate_session_actions(conn, task_session_id, ActionState.CANCELED)
        return self.get_task_session(principal, task_session_id)

    def advance_task_context(self, principal: Principal, task_session_id: str) -> dict:
        """Record that relevant conversation context changed (used by D's chat)."""
        self._require_channel(principal, WRITE_CHANNELS)
        self._active_session(principal, task_session_id)
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE task_sessions SET context_version = context_version + 1, updated_at = ? "
                "WHERE task_session_id = ?",
                (self._now_iso(), task_session_id),
            )
            self.actions.invalidate_session_actions(conn, task_session_id, ActionState.CANCELED)
        return self.get_task_session(principal, task_session_id)

    def cancel_task_session(self, principal: Principal, task_session_id: str) -> dict:
        self._require_channel(principal, WRITE_CHANNELS)
        row = self._owned("task_sessions", "task_session_id", task_session_id, principal)
        active = self.db.query_all(
            "SELECT * FROM scans WHERE task_session_id = ? AND tenant_id = ? AND state IN (?, ?, ?)",
            (task_session_id, row["tenant_id"], *[s.value for s in ACTIVE_JOB_STATES]),
        )
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE task_sessions SET canceled_at = COALESCE(canceled_at, ?) WHERE task_session_id = ?",
                (self._now_iso(), task_session_id),
            )
            self.actions.invalidate_session_actions(conn, task_session_id, ActionState.CANCELED)
            for scan in active:
                self._terminate(conn, scan, JobState.CANCELED, [ReasonCode.CANCELED_BY_USER.value])
        for scan in active:
            self._cancel_runtime(scan["scan_id"])
        return self.get_task_session(principal, task_session_id)

    def _bindings(self, session_row, resource_rows) -> dict:
        resource_set_hash = canonical_digest(
            sorted([r["resource_id"], r["original_hash"]] for r in resource_rows)
        )
        bindings = {
            "task_session_id": session_row["task_session_id"],
            "task_scope_version": session_row["scope_version"],
            "context_version": session_row["context_version"],
            "policy_hash": session_row["policy_hash"],
            "resource_set_hash": resource_set_hash,
            "model_configuration_hash": self.config.model_configuration_hash,
            "roster_hash": self.config.roster_hash,
        }
        bindings["context_hash"] = canonical_digest(bindings)
        return bindings

    def _current_bindings(self, session_row) -> dict:
        """Recompute bindings from current state, or raise CONTEXT_CHANGED."""
        if not self._session_active(session_row):
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "task session inactive")
        policy = get_policy(session_row["policy_id"])
        if policy is None or policy.policy_hash != session_row["policy_hash"]:
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "policy changed")
        rows = []
        for resource_id in _loads(session_row["resource_ids_json"]):
            row = self.db.query_one(
                "SELECT * FROM resources WHERE resource_id = ? AND tenant_id = ? AND owner_id = ?",
                (resource_id, session_row["tenant_id"], session_row["owner_id"]),
            )
            if row is None or row["deleted_at"] or parse_iso(row["evidence_expires_at"]) <= self._now():
                raise GatewayError(ErrorCode.CONTEXT_CHANGED, "resource unavailable")
            rows.append(row)
        return self._bindings(session_row, rows)

    # ------------------------------------------------------------------ scans

    def inspect_resource(self, principal: Principal, resource_id: str, task_session_id: str) -> dict:
        """MCP-shaped entrypoint: start or resume the scan for the session's
        current context. The resource must belong to the session."""
        self._require_channel(principal, ALL_CHANNELS)
        session = self._active_session(principal, task_session_id)
        if resource_id not in _loads(session["resource_ids_json"]):
            raise GatewayError(ErrorCode.NOT_FOUND, "resource not in task session")
        key = "auto-" + canonical_digest(
            [task_session_id, session["scope_version"], session["context_version"]]
        )[:48]
        return self.start_scan(
            principal, {"contract_version": CONTRACT_VERSION, "task_session_id": task_session_id}, key
        )

    def start_scan(self, principal: Principal, body: Mapping, idempotency_key: str | None) -> dict:
        self._require_channel(principal, ALL_CHANNELS)
        req = schemas.validate(schemas.scan_request, body)
        if not idempotency_key or not ID_PATTERN.match(idempotency_key):
            raise GatewayError(ErrorCode.INVALID_REQUEST, "idempotency key required")
        session = self._active_session(principal, req["task_session_id"])
        scope = f"{principal.tenant_id}:{principal.user_id}:scan"
        request_digest = canonical_digest(req)
        prior = self.db.query_one(
            "SELECT * FROM idempotency WHERE scope = ? AND idem_key = ?", (scope, idempotency_key)
        )
        if prior is not None:
            if prior["request_digest"] != request_digest:
                raise GatewayError(ErrorCode.INVALID_REQUEST, "idempotency key reused")
            return self.get_scan_status(principal, _loads(prior["response_json"])["scan_id"])

        self._require_runtime()
        self._require_not_stopped()
        bindings = self._current_bindings(session)
        resource_ids = _loads(session["resource_ids_json"])
        now = self._now()
        scan_id = self.ids.new("scan")
        policy = get_policy(session["policy_id"])
        with self.db.transaction() as conn:
            active = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE tenant_id = ? AND owner_id = ? AND state IN (?, ?, ?)",
                (principal.tenant_id, principal.user_id, *[s.value for s in ACTIVE_JOB_STATES]),
            ).fetchone()[0]
            if active >= self.config.limits.max_concurrent_scans_per_user:
                raise GatewayError(ErrorCode.LIMIT_EXCEEDED, "too many concurrent scans", retryable=True)
            conn.execute(
                "INSERT INTO scans (scan_id, tenant_id, owner_id, task_session_id, task_scope_version, "
                "context_version, policy_id, policy_version, policy_hash, resource_set_hash, resource_ids_json, "
                "model_configuration_hash, roster_hash, context_hash, state, required_checks_json, budget_json, "
                "created_at, updated_at, deadline_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id, principal.tenant_id, principal.user_id, session["task_session_id"],
                    session["scope_version"], session["context_version"], policy.policy_id, policy.version,
                    policy.policy_hash, bindings["resource_set_hash"], _dumps(resource_ids),
                    bindings["model_configuration_hash"], bindings["roster_hash"], bindings["context_hash"],
                    JobState.QUEUED.value, _dumps(["EXTRACTION"] + [r.value for r in INSPECTION_ROLES]),
                    _dumps(self._budget()), iso(now), iso(now),
                    iso(after(now, self.config.limits.scan_deadline_seconds)),
                ),
            )
            conn.execute(
                "INSERT INTO idempotency VALUES (?, ?, ?, ?, ?)",
                (scope, idempotency_key, request_digest, _dumps({"scan_id": scan_id}), iso(now)),
            )
            self._event(conn, scan_id, principal.tenant_id, "QUEUED")
        self._run_extraction(scan_id)
        return self.get_scan_status(principal, scan_id)

    def _budget(self) -> dict:
        limits = self.config.limits
        return {
            "scan_deadline_seconds": limits.scan_deadline_seconds,
            "worker_lease_seconds": limits.worker_lease_seconds,
            "worker_retries": limits.worker_retries,
            "model_token_budget": limits.model_token_budget,
            "max_findings": limits.max_findings,
            "max_artifacts": limits.max_artifacts,
            "max_artifact_chars": limits.max_artifact_chars,
        }

    @staticmethod
    def _required_roles(scan) -> list[str]:
        return [c for c in _loads(scan["required_checks_json"]) if c != "EXTRACTION"]

    def _scan(self, scan_id: str):
        return self.db.query_one("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))

    def _set_state(self, conn, scan_id: str, state: JobState, expected: Iterable[JobState]) -> bool:
        expected = [s.value for s in expected]
        cursor = conn.execute(
            f"UPDATE scans SET state = ?, updated_at = ? WHERE scan_id = ? AND state IN ({','.join('?' * len(expected))})",
            (state.value, self._now_iso(), scan_id, *expected),
        )
        return cursor.rowcount == 1

    def _new_token(self, conn, assignment_id: str, scan, worker_id: str) -> str:
        token = self.ids.secret()
        assignment = conn.execute("SELECT lease_expires_at FROM assignments WHERE assignment_id = ?", (assignment_id,)).fetchone()
        expires = min(
            after(self._now(), self.config.retention.job_token_seconds), parse_iso(scan["deadline_at"]),
            parse_iso(assignment["lease_expires_at"]),
        )
        conn.execute(
            "INSERT INTO job_tokens VALUES (?, ?, ?, ?, ?, ?, NULL)",
            (GatewayConfig.hash_token(token), assignment_id, scan["scan_id"], scan["tenant_id"], worker_id, iso(expires)),
        )
        return token

    def _run_extraction(self, scan_id: str) -> None:
        scan = self._scan(scan_id)
        with self.db.transaction() as conn:
            if not self._set_state(conn, scan_id, JobState.EXTRACTING, [JobState.QUEUED]):
                return
            self._event(conn, scan_id, scan["tenant_id"], "EXTRACTING")
        extractor = self.config.roster_entry(WorkerRole.EXTRACTOR.value)
        limits = self.config.limits
        for resource_id in _loads(scan["resource_ids_json"]):
            if self._scan(scan_id)["state"] != JobState.EXTRACTING.value:
                return  # canceled meanwhile
            resource = self.db.query_one("SELECT * FROM resources WHERE resource_id = ?", (resource_id,))
            assignment_id = self.ids.new("xa")
            assignment = {
                "contract_version": CONTRACT_VERSION,
                "assignment_id": assignment_id,
                "scan_id": scan_id,
                "attempt": 1,
                "resource_id": resource_id,
                "original_hash": resource["original_hash"],
                "media_type": resource["media_type"],
                "limits": {"max_source_bytes": limits.max_source_bytes, "max_extracted_chars": limits.max_extracted_chars},
                "deadline": scan["deadline_at"],
            }
            with self.db.transaction() as conn:
                conn.execute(
                    "INSERT INTO assignments VALUES (?, ?, ?, 'EXTRACTION', ?, ?, ?, ?, 1, 'ASSIGNED', ?, ?, ?)",
                    (
                        assignment_id, scan_id, scan["tenant_id"], extractor.role, extractor.worker_id,
                        extractor.build_version, extractor.prompt_version, scan["deadline_at"],
                        _dumps(assignment), self._now_iso(),
                    ),
                )
            try:
                raw = self.runtime.extract(dict(assignment))
            except Exception as exc:
                log.warning("extract_failed scan_id=%s error=%s", scan_id, type(exc).__name__)
                self._fail(scan_id, ReasonCode.RUNTIME_UNAVAILABLE)
                return
            finally:
                with self.db.transaction() as conn:
                    conn.execute(
                        "UPDATE job_tokens SET revoked_at = ? WHERE assignment_id = ? AND revoked_at IS NULL",
                        (self._now_iso(), assignment_id),
                    )
                    conn.execute(
                        "UPDATE assignments SET state = 'COMPLETED' WHERE assignment_id = ? AND state = 'ASSIGNED'",
                        (assignment_id,),
                    )
            status, version, views, unsupported = self._accept_extraction(scan, resource, assignment, raw)
            committed = False
            try:
                with self.db.transaction() as conn:
                    current = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
                    if current["state"] != JobState.EXTRACTING.value:
                        return
                    if self._now() >= parse_iso(current["deadline_at"]):
                        self._terminate(conn, current, JobState.FAILED, [ReasonCode.TIMEOUT.value])
                        return
                    session = conn.execute("SELECT * FROM task_sessions WHERE task_session_id = ?",
                                           (current["task_session_id"],)).fetchone()
                    try:
                        bound_context = self._current_bindings(session)["context_hash"]
                    except GatewayError:
                        bound_context = None
                    if bound_context != current["context_hash"]:
                        self._terminate(conn, current, JobState.FAILED, [ReasonCode.INTERRUPTED.value])
                        return
                    conn.execute(
                        "INSERT INTO extractions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (scan_id, resource_id, assignment_id, status, version, _dumps(views), _dumps(unsupported), self._now_iso()),
                    )
                    self._event(conn, scan_id, scan["tenant_id"], "EXTRACTED", resource_id=resource_id, status=status)
                committed = True
            finally:
                if not committed:
                    for view in views:
                        self.store.delete(view["storage_ref"], scan["tenant_id"])
                        self.store.delete(view["source_map_ref"], scan["tenant_id"])

        outcome = self._evaluate(scan_id)
        if outcome.decision is not None:
            self._finalize(scan_id, outcome)
        else:
            self._dispatch(scan_id, self._required_roles(scan))

    def _accept_extraction(self, scan, resource, assignment, raw) -> tuple[str, str | None, list, list]:
        error = (ExtractionStatus.ERROR.value, None, [], [])
        try:
            result = schemas.validate(schemas.extraction_result, raw)
        except ContractError as exc:
            log.warning("extraction_invalid scan_id=%s path=%s", scan["scan_id"], exc.path)
            return error
        if (
            result["assignment_id"] != assignment["assignment_id"]
            or result["resource_id"] != resource["resource_id"]
            or result["original_hash"] != resource["original_hash"]
            or result["extractor_version"] != self.db.query_one(
                "SELECT build_version FROM assignments WHERE assignment_id = ?",
                (assignment["assignment_id"],),
            )["build_version"]
        ):
            return error
        views, seen = [], set()
        for view in result["views"]:
            text = view["text"]
            if view["view_id"] in seen or sha256_hex(text) != view["view_hash"]:
                return error
            seen.add(view["view_id"])
            for vs, ve, os_, oe in view["source_map"]:
                if not (0 <= vs <= ve <= len(text) and 0 <= os_ <= oe <= resource["size_bytes"]):
                    return error
            covered_to = 0
            for vs, ve, _, _ in sorted(view["source_map"]):
                if vs > covered_to:
                    return error
                covered_to = max(covered_to, ve)
            if covered_to != len(text):
                return error
        # Validate every view before allocating any private objects.
        staged = []
        try:
            for view in result["views"]:
                ref = self.store.put(scan["tenant_id"], "view", view["text"].encode("utf-8"))
                staged.append(ref)
                map_ref = self.store.put(scan["tenant_id"], "sourcemap", _dumps(view["source_map"]).encode("utf-8"))
                staged.append(map_ref)
                views.append({"view_id": view["view_id"], "kind": view["kind"],
                              "view_hash": view["view_hash"], "length": len(view["text"]),
                              "storage_ref": ref, "source_map_ref": map_ref})
        except BaseException:
            for ref in staged:
                self.store.delete(ref, scan["tenant_id"])
            raise
        status = result["status"]
        if status == ExtractionStatus.COMPLETE.value and not views:
            status = ExtractionStatus.INCOMPLETE.value
        unsupported = [
            {"resource_id": resource["resource_id"], "part_id": f"part_{i + 1}",
             "media_type": part["media_type"] if part["media_type"] in _PUBLIC_MEDIA_TYPES else "application/octet-stream",
             "task_relevant": part["task_relevant"],
             "reason": part["reason"] if part["reason"] in _PUBLIC_UNSUPPORTED_REASONS else "UNSUPPORTED_CONTENT"}
            for i, part in enumerate(result["unsupported_parts"])
        ]
        return status, result["extractor_version"], views, unsupported

    def _dispatch(self, scan_id: str, roles: list[str]) -> None:
        scan = self._scan(scan_id)
        if self.runtime is None:
            self._fail(scan_id, ReasonCode.RUNTIME_UNAVAILABLE)
            return
        budget = _loads(scan["budget_json"])
        now = self._now()
        deadline = parse_iso(scan["deadline_at"])
        resources = []
        for ext in self.db.query_all(
            "SELECT * FROM extractions WHERE scan_id = ? ORDER BY resource_id", (scan_id,)
        ):
            original = self.db.query_one("SELECT original_hash FROM resources WHERE resource_id = ?", (ext["resource_id"],))
            resources.append(
                {
                    "resource_id": ext["resource_id"],
                    "original_hash": original["original_hash"],
                    "views": [
                        {"view_id": v["view_id"], "view_hash": v["view_hash"], "length": v["length"]}
                        for v in _loads(ext["views_json"], [])
                    ],
                }
            )
        assignments = []
        with self.db.transaction() as conn:
            if not self._set_state(conn, scan_id, JobState.INSPECTING, [JobState.EXTRACTING, JobState.INSPECTING]):
                return
            for role in roles:
                entry = self.config.roster_entry(role)
                attempt = conn.execute(
                    "SELECT COUNT(*) FROM assignments WHERE scan_id = ? AND role = ? AND kind = 'INSPECTION'",
                    (scan_id, role),
                ).fetchone()[0] + 1
                assignment_id = self.ids.new("ia")
                payload = {
                    "contract_version": CONTRACT_VERSION,
                    "assignment_id": assignment_id,
                    "scan_id": scan_id,
                    "attempt": attempt,
                    "worker": entry.as_dict(),
                    "task_session_id": scan["task_session_id"],
                    "task_scope_version": scan["task_scope_version"],
                    "policy": {
                        "policy_id": scan["policy_id"],
                        "policy_version": scan["policy_version"],
                        "policy_hash": scan["policy_hash"],
                    },
                    "resource_set_hash": scan["resource_set_hash"],
                    "context_hash": scan["context_hash"],
                    "model_configuration_hash": scan["model_configuration_hash"],
                    "resources": resources,
                    "limits": {
                        "max_findings": budget["max_findings"],
                        "max_artifacts": budget["max_artifacts"],
                        "max_artifact_chars": budget["max_artifact_chars"],
                        "model_token_budget": budget["model_token_budget"],
                    },
                    "deadline": scan["deadline_at"],
                }
                lease = min(after(now, budget["worker_lease_seconds"]), deadline)
                conn.execute(
                    "INSERT INTO assignments VALUES (?, ?, ?, 'INSPECTION', ?, ?, ?, ?, ?, 'ASSIGNED', ?, ?, ?)",
                    (
                        assignment_id, scan_id, scan["tenant_id"], role, entry.worker_id, entry.build_version,
                        entry.prompt_version, attempt, iso(lease), _dumps(payload), iso(now),
                    ),
                )
                assignments.append(payload)
                self._event(conn, scan_id, scan["tenant_id"], "DISPATCHED", assignment_id=assignment_id, role=role, attempt=attempt)
        try:
            receipts = self.runtime.dispatch([dict(a) for a in assignments])
        except Exception as exc:
            log.warning("dispatch_failed scan_id=%s error=%s", scan_id, type(exc).__name__)
            self._fail(scan_id, ReasonCode.RUNTIME_UNAVAILABLE)
            return
        delivered = set()
        for receipt in receipts or []:
            if isinstance(receipt, Mapping) and receipt.get("delivered") is True:
                delivered.add(receipt.get("assignment_id"))
        undelivered = False
        with self.db.transaction() as conn:
            for payload in assignments:
                aid = payload["assignment_id"]
                if aid in delivered:
                    conn.execute(
                        "UPDATE assignments SET state = 'DELIVERED' WHERE assignment_id = ? AND state = 'ASSIGNED'",
                        (aid,),
                    )
                else:
                    cursor = conn.execute(
                        "UPDATE assignments SET state = 'UNDELIVERED' WHERE assignment_id = ? AND state = 'ASSIGNED'",
                        (aid,),
                    )
                    undelivered = undelivered or cursor.rowcount == 1
        if undelivered:
            self._recover_scan(scan_id)

    def _fail(self, scan_id: str, reason: ReasonCode) -> None:
        scan = self._scan(scan_id)
        with self.db.transaction() as conn:
            changed = self._terminate(conn, scan, JobState.FAILED, [reason.value])
        if changed:
            self._cancel_runtime(scan_id)

    def _terminate(self, conn, scan, state: JobState, reasons: list[str]) -> bool:
        """Move an active (or, for CANCELED, decided) scan to a terminal state
        that releases nothing, revoking every job capability."""
        allowed = list(ACTIVE_JOB_STATES) + ([JobState.DECIDED] if state == JobState.CANCELED else [])
        if not self._set_state(conn, scan["scan_id"], state, allowed):
            return False
        now_iso = self._now_iso()
        existing = _loads(scan["reason_codes_json"], [])
        conn.execute(
            "UPDATE scans SET reason_codes_json = ? WHERE scan_id = ?",
            (_dumps(list(dict.fromkeys(existing + reasons))), scan["scan_id"]),
        )
        conn.execute(
            "UPDATE assignments SET state = 'CANCELED' WHERE scan_id = ? AND state IN ('ASSIGNED', 'DELIVERED', 'UNDELIVERED')",
            (scan["scan_id"],),
        )
        conn.execute(
            "UPDATE job_tokens SET revoked_at = ? WHERE scan_id = ? AND revoked_at IS NULL", (now_iso, scan["scan_id"])
        )
        conn.execute(
            "UPDATE review_exceptions SET revoked_at = ? WHERE scan_id = ? AND revoked_at IS NULL",
            (now_iso, scan["scan_id"]),
        )
        self._event(conn, scan["scan_id"], scan["tenant_id"], state.value, reasons=reasons)
        return True

    # --------------------------------------------------------- worker results

    def accept_worker_result(self, verified_identity: Mapping, worker_result: Mapping) -> dict:
        """Called by B after it verified application sender identity and
        message replay rules. A re-checks assignment, tenant, versions,
        bindings and completeness. Raises GatewayError on rejection."""
        try:
            return self._accept_worker_result(verified_identity, worker_result)
        except GatewayError as exc:
            assignment_id = worker_result.get("assignment_id") if isinstance(worker_result, Mapping) else None
            row = None
            if isinstance(assignment_id, str):
                row = self.db.query_one("SELECT scan_id, tenant_id FROM assignments WHERE assignment_id = ?", (assignment_id,))
            if row is not None:
                with self.db.transaction() as conn:
                    self._event(conn, row["scan_id"], row["tenant_id"], "RESULT_REJECTED", assignment_id=assignment_id, code=exc.code.value)
            raise

    def _accept_worker_result(self, verified_identity: Mapping, worker_result: Mapping) -> dict:
        identity = schemas.validate(schemas.worker_identity, dict(verified_identity), "$identity")
        result = schemas.validate(schemas.worker_result, worker_result)
        assignment = self.db.query_one(
            "SELECT * FROM assignments WHERE assignment_id = ? AND kind = 'INSPECTION'", (result["assignment_id"],)
        )
        if assignment is None:
            raise GatewayError(ErrorCode.FORBIDDEN, "not assigned")
        expected_worker = {
            "worker_id": assignment["worker_id"],
            "role": assignment["role"],
            "build_version": assignment["build_version"],
            "prompt_version": assignment["prompt_version"],
        }
        if identity != expected_worker or result["worker"] != expected_worker:
            raise GatewayError(ErrorCode.FORBIDDEN, "worker identity does not match assignment")
        if result["scan_id"] != assignment["scan_id"] or result["attempt"] != assignment["attempt"]:
            raise GatewayError(ErrorCode.FORBIDDEN, "scan or attempt mismatch")

        digest = canonical_digest(result)
        seen = self.db.query_one("SELECT * FROM seen_nonces WHERE nonce = ?", (result["nonce"],))
        if seen is not None:
            if seen["assignment_id"] == result["assignment_id"] and seen["result_digest"] == digest:
                return {"status": "DUPLICATE", "assignment_id": result["assignment_id"]}
            raise GatewayError(ErrorCode.FORBIDDEN, "nonce replay")
        if assignment["state"] == "COMPLETED":
            raise GatewayError(ErrorCode.FORBIDDEN, "assignment already completed")
        if assignment["state"] not in LIVE_ASSIGNMENT_STATES:
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "assignment no longer live")
        scan = self._scan(assignment["scan_id"])
        if scan["state"] != JobState.INSPECTING.value:
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "scan not inspecting")
        now = self._now()
        if now >= parse_iso(assignment["lease_expires_at"]) or now >= parse_iso(scan["deadline_at"]):
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "lease expired")

        expected = _loads(assignment["assignment_json"])
        for key in (
            "task_session_id", "task_scope_version", "policy", "resource_set_hash", "context_hash", "model_configuration_hash",
        ):
            if result[key] != expected[key]:
                raise GatewayError(ErrorCode.CONTEXT_CHANGED, f"binding mismatch: {key}")

        assigned_views = {
            (r["resource_id"], v["view_id"]): v for r in expected["resources"] for v in r["views"]
        }
        hashes_by_resource: dict[str, dict[str, int]] = {}
        for (rid, _), view in assigned_views.items():
            hashes_by_resource.setdefault(rid, {})[view["view_hash"]] = view["length"]

        checked = set()
        for item in result["checked_views"]:
            key = (item["resource_id"], item["view_id"])
            if key not in assigned_views or assigned_views[key]["view_hash"] != item["view_hash"]:
                raise GatewayError(ErrorCode.INVALID_REQUEST, "checked view not assigned")
            checked.add(key)
        if result["inspection_status"] == InspectionStatus.COMPLETE.value and checked != set(assigned_views):
            raise GatewayError(ErrorCode.INVALID_REQUEST, "COMPLETE without checking every assigned view")

        role = assignment["role"]
        is_behavior = role == WorkerRole.BEHAVIOR_TESTER.value
        if not is_behavior and ("task_output" in result or "telemetry_event_ids" in result):
            raise GatewayError(ErrorCode.INVALID_REQUEST, "only the behavior tester reports output or telemetry")

        limits = expected["limits"]
        artifacts = result.get("artifacts", [])
        if len(result["findings"]) > limits["max_findings"] or len(artifacts) > limits["max_artifacts"]:
            raise GatewayError(ErrorCode.INVALID_REQUEST, "result exceeds limits")
        artifact_ids = set()
        for artifact in artifacts:
            if artifact["artifact_id"] in artifact_ids or len(artifact["text"]) > limits["max_artifact_chars"]:
                raise GatewayError(ErrorCode.INVALID_REQUEST, "invalid artifact")
            artifact_ids.add(artifact["artifact_id"])

        events = {
            e["event_id"]: e
            for e in self.db.query_all("SELECT * FROM collector_events WHERE scan_id = ?", (scan["scan_id"],))
        }
        for event_id in result.get("telemetry_event_ids", []):
            if event_id not in events:
                raise GatewayError(ErrorCode.INVALID_REQUEST, "unknown telemetry event")

        for item in result["findings"]:
            lengths = hashes_by_resource.get(item["resource_id"], {})
            if item["view_hash"] not in lengths:
                raise GatewayError(ErrorCode.INVALID_REQUEST, "finding references unassigned view")
            if "span" in item and not 0 <= item["span"]["start"] < item["span"]["end"] <= lengths[item["view_hash"]]:
                raise GatewayError(ErrorCode.INVALID_REQUEST, "finding span out of range")
            for evidence_id in item["evidence_ids"]:
                if evidence_id not in artifact_ids and evidence_id not in events:
                    raise GatewayError(ErrorCode.INVALID_REQUEST, "unknown evidence reference")
            if item["category"] == FindingCategory.OBSERVED_FORBIDDEN_ACTION.value:
                if not any(
                    events.get(e) is not None and events[e]["effective_policy_check"] == PolicyCheck.FORBIDDEN.value
                    for e in item["evidence_ids"]
                ):
                    raise GatewayError(ErrorCode.INVALID_REQUEST, "forbidden action claim lacks collector evidence")

        answer_mismatch = False
        output = result.get("task_output")
        if output is not None:
            policy = get_policy(scan["policy_id"])
            if output["kind"] != policy.output_kind:
                raise GatewayError(ErrorCode.INVALID_REQUEST, "task output kind does not match policy")
            if output["kind"] == OUTPUT_INVOICE:
                schemas.validate_invoice_values(output)
            answer_mismatch = self._verify_output_refs(scan, output, hashes_by_resource)

        # Stage immutable objects, then revalidate authority at commit time.
        stored_artifacts, staged = [], []
        output_ref = None
        try:
            for artifact in artifacts:
                ref = self.store.put(scan["tenant_id"], "artifact", artifact["text"].encode("utf-8"))
                staged.append(ref)
                stored_artifacts.append((artifact, ref))
            if output is not None:
                output_ref = self.store.put(scan["tenant_id"], "taskoutput", _dumps(output).encode("utf-8"))
                staged.append(output_ref)
            with self.db.transaction() as conn:
                current = conn.execute(
                    "SELECT a.state AS a_state, a.lease_expires_at, s.state AS s_state, s.deadline_at FROM assignments a JOIN scans s ON s.scan_id = a.scan_id "
                    "WHERE a.assignment_id = ?",
                    (assignment["assignment_id"],),
                ).fetchone()
                if current["a_state"] not in LIVE_ASSIGNMENT_STATES or current["s_state"] != JobState.INSPECTING.value:
                    raise GatewayError(ErrorCode.CONTEXT_CHANGED, "assignment no longer live")
                now = self._now()
                if now >= parse_iso(current["lease_expires_at"]) or now >= parse_iso(current["deadline_at"]):
                    raise GatewayError(ErrorCode.CONTEXT_CHANGED, "lease expired")
                session = conn.execute("SELECT * FROM task_sessions WHERE task_session_id = ?", (scan["task_session_id"],)).fetchone()
                if self._current_bindings(session)["context_hash"] != scan["context_hash"]:
                    raise GatewayError(ErrorCode.CONTEXT_CHANGED, "bindings changed")
                now_iso = iso(now)
                evidence_expiry = iso(min(after(now, self.config.retention.evidence_seconds), self._source_expiry(scan)))
                evidence_map = {}
                for artifact, ref in stored_artifacts:
                    evidence_id = self.ids.new("ev")
                    evidence_map[artifact["artifact_id"]] = evidence_id
                    conn.execute(
                        "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, 'WORKER_ARTIFACT', ?, NULL, ?, ?, NULL)",
                        (evidence_id, scan["scan_id"], scan["tenant_id"], scan["owner_id"], artifact["kind"], ref, now_iso, evidence_expiry),
                    )
                for event_id, event in events.items():
                    evidence_map.setdefault(event_id, event["evidence_id"])
                findings = [
                    {
                        "category": f["category"],
                        "resource_id": f["resource_id"],
                        "view_hash": f["view_hash"],
                        **({"span": f["span"]} if "span" in f else {}),
                        "evidence_ids": [evidence_map[e] for e in f["evidence_ids"]],
                    }
                    for f in result["findings"]
                ]
                conn.execute(
                    "INSERT INTO worker_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        assignment["assignment_id"], scan["scan_id"], role, result["nonce"], digest,
                        result["inspection_status"], _dumps(findings), _dumps(result.get("telemetry_event_ids", [])),
                        output_ref, _dumps(result.get("coverage_limits", [])), int(answer_mismatch), now_iso,
                    ),
                )
                conn.execute("INSERT INTO seen_nonces VALUES (?, ?, ?, ?)", (result["nonce"], assignment["assignment_id"], digest, now_iso))
                conn.execute("UPDATE assignments SET state = 'COMPLETED' WHERE assignment_id = ?", (assignment["assignment_id"],))
                conn.execute(
                    "UPDATE job_tokens SET revoked_at = ? WHERE assignment_id = ? AND revoked_at IS NULL",
                    (now_iso, assignment["assignment_id"]),
                )
                self._event(
                    conn, scan["scan_id"], scan["tenant_id"], "RESULT_ACCEPTED",
                    assignment_id=assignment["assignment_id"], role=role, status=result["inspection_status"],
                )
        except BaseException:
            for ref in staged:
                self.store.delete(ref, scan["tenant_id"])
            raise
        self._try_decide(scan["scan_id"])
        return {"status": "ACCEPTED", "assignment_id": assignment["assignment_id"]}

    def _view_text(self, scan, resource_id: str, view_hash: str) -> str | None:
        ext = self.db.query_one(
            "SELECT views_json FROM extractions WHERE scan_id = ? AND resource_id = ?", (scan["scan_id"], resource_id)
        )
        for view in _loads(ext["views_json"], []) if ext else []:
            if view["view_hash"] == view_hash and view.get("storage_ref"):
                text = self.store.get(view["storage_ref"], scan["tenant_id"]).decode("utf-8")
                if sha256_hex(text) != view_hash:
                    raise GatewayError(ErrorCode.SERVICE_UNAVAILABLE, "stored view integrity failure", retryable=False)
                return text
        return None

    def _verify_output_refs(self, scan, output: dict, hashes_by_resource: dict) -> bool:
        """Validate source references; return True if a value disagrees with
        its cited source text (deterministic answer-integrity check)."""

        def check_ref(ref: dict) -> str:
            lengths = hashes_by_resource.get(ref["resource_id"], {})
            if ref["view_hash"] not in lengths or not 0 <= ref["start"] < ref["end"] <= lengths[ref["view_hash"]]:
                raise GatewayError(ErrorCode.INVALID_REQUEST, "output source reference out of range")
            text = self._view_text(scan, ref["resource_id"], ref["view_hash"])
            if text is None:
                raise GatewayError(ErrorCode.INVALID_REQUEST, "output source view unavailable")
            return text[ref["start"]:ref["end"]]

        if output["kind"] != OUTPUT_INVOICE:
            for statement in output["statements"]:
                for ref in statement["source_refs"]:
                    check_ref(ref)
            return False
        mismatch = False
        for name, field in output["fields"].items():
            if "absent" in field:
                continue
            spans = [check_ref(ref) for ref in field["source_refs"]]
            if name == "amount":
                # A citation cannot carve a smaller amount from inside a source number.
                matches = any(
                    ref["start"] <= token.start() and token.end() <= ref["end"]
                    and Decimal((token.group("sign_before") or token.group("sign_after") or "").translate(str.maketrans("−﹣－＋", "---+")) + token.group("number").replace(",", "")) == Decimal(field["value"])
                    for ref in field["source_refs"]
                    for token in _AMOUNT_TOKEN.finditer(self._view_text(scan, ref["resource_id"], ref["view_hash"]))
                )
            else:
                matches = any(_value_matches(name, field["value"], span) for span in spans)
            if not matches:
                mismatch = True
        return mismatch

    # ------------------------------------------------------ collector events

    def record_collector_event(self, verified_collector_identity: Mapping, event: Mapping) -> dict:
        """Authoritative simulated-tool telemetry from B's collector channel.
        Uses a separate identity that workers never receive."""
        identity = schemas.validate(schemas.collector_identity, dict(verified_collector_identity), "$identity")
        if identity["collector_id"] not in self.config.collector_ids:
            raise GatewayError(ErrorCode.FORBIDDEN, "unknown collector identity")
        ev = schemas.validate(schemas.collector_event, event)
        scan = self._scan(ev["scan_id"])
        if scan is None:
            raise GatewayError(ErrorCode.NOT_FOUND, "scan not found")
        run = self.db.query_one(
            "SELECT * FROM assignments WHERE assignment_id = ? AND scan_id = ? AND role = ? AND kind = 'INSPECTION'",
            (ev["run_id"], ev["scan_id"], WorkerRole.BEHAVIOR_TESTER.value),
        )
        if run is None:
            raise GatewayError(ErrorCode.FORBIDDEN, "run not bound to a behavior assignment of this scan")
        digest = canonical_digest(ev)
        prior = self.db.query_one("SELECT * FROM collector_events WHERE event_id = ?", (ev["event_id"],))
        if prior is not None:
            if prior["event_digest"] == digest:
                return {"status": "DUPLICATE", "event_id": ev["event_id"]}
            raise GatewayError(ErrorCode.FORBIDDEN, "conflicting event id")
        policy = get_policy(scan["policy_id"])
        # Most restrictive of the collector's check and the gateway policy.
        effective = (
            PolicyCheck.FORBIDDEN.value
            if ev["policy_check"] == PolicyCheck.FORBIDDEN.value or not policy.operation_permitted(ev["operation"])
            else PolicyCheck.PERMITTED.value
        )
        now = self._now()
        evidence_id = self.ids.new("ev")
        try:
            with self.db.transaction() as conn:
                conn.execute(
                    "INSERT INTO evidence VALUES (?, ?, ?, ?, 'COLLECTOR_EVENT', 'COLLECTOR', NULL, ?, ?, ?, NULL)",
                    (evidence_id, scan["scan_id"], scan["tenant_id"], scan["owner_id"], ev["event_id"], iso(now),
                     iso(after(now, self.config.retention.evidence_seconds))),
                )
                conn.execute(
                    "INSERT INTO collector_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        ev["event_id"], scan["scan_id"], scan["tenant_id"], ev["run_id"], ev["sequence"], ev["operation"],
                        ev["argument_digest"], ev["attempted_outcome"], ev["policy_check"], effective, ev["timestamp"],
                        identity["collector_id"], digest, evidence_id, iso(now),
                    ),
                )
                self._event(conn, scan["scan_id"], scan["tenant_id"], "COLLECTOR_EVENT", event_id=ev["event_id"], policy_check=effective)
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise GatewayError(ErrorCode.FORBIDDEN, "duplicate run sequence") from exc
            raise
        if effective == PolicyCheck.FORBIDDEN.value:
            self._apply_forbidden_evidence(scan["scan_id"])
        return {"status": "RECORDED", "event_id": ev["event_id"], "evidence_id": evidence_id}

    def _apply_forbidden_evidence(self, scan_id: str) -> None:
        scan = self._scan(scan_id)
        if scan["state"] in (JobState.EXTRACTING.value, JobState.INSPECTING.value):
            self._try_decide(scan_id)
        elif scan["state"] == JobState.DECIDED.value and scan["decision"] != Decision.QUARANTINE.value:
            # Late authoritative evidence downgrades an earlier decision.
            with self.db.transaction() as conn:
                conn.execute(
                    "UPDATE scans SET decision = ?, reason_codes_json = ?, updated_at = ?, decision_record_json = ? "
                    "WHERE scan_id = ?",
                    (
                        Decision.QUARANTINE.value, _dumps([ReasonCode.VERIFIED_FORBIDDEN_ACTION.value]), self._now_iso(),
                        _dumps(self._decision_record(conn, scan, Decision.QUARANTINE.value)), scan_id,
                    ),
                )
                conn.execute(
                    "UPDATE review_exceptions SET revoked_at = ? WHERE scan_id = ? AND revoked_at IS NULL",
                    (self._now_iso(), scan_id),
                )
                self._event(conn, scan_id, scan["tenant_id"], "DECISION_DOWNGRADED", decision=Decision.QUARANTINE.value)

    # -------------------------------------------------------------- decisions

    def _evaluate(self, scan_id: str) -> DecisionOutcome:
        scan = self._scan(scan_id)
        extractions = self.db.query_all("SELECT * FROM extractions WHERE scan_id = ?", (scan_id,))
        statuses = [e["status"] for e in extractions]
        if len(extractions) < len(_loads(scan["resource_ids_json"])):
            statuses.append(ExtractionStatus.INCOMPLETE.value)
        unsupported_relevant = any(
            p.get("task_relevant") for e in extractions for p in _loads(e["unsupported_json"], [])
        )
        total_chars = sum(v["length"] for e in extractions for v in _loads(e["views_json"], []))

        required = self._required_roles(scan)
        retries = _loads(scan["budget_json"])["worker_retries"]
        results = {}
        for row in self.db.query_all("SELECT * FROM worker_results WHERE scan_id = ?", (scan_id,)):
            categories = frozenset(f["category"] for f in _loads(row["findings_json"], []))
            run_events = {
                e["event_id"]
                for e in self.db.query_all("SELECT event_id FROM collector_events WHERE run_id = ?", (row["assignment_id"],))
            }
            results[row["role"]] = RoleResult(
                status=InspectionStatus(row["inspection_status"]),
                categories=categories,
                has_task_output=row["task_output_ref"] is not None,
                answer_mismatch=bool(row["answer_mismatch"]),
                contradicts_telemetry=bool(run_events - set(_loads(row["telemetry_json"], []))),
            )
        now = self._now()
        exhausted = set()
        for role in required:
            if role in results:
                continue
            rows = self.db.query_all(
                "SELECT state, lease_expires_at FROM assignments WHERE scan_id = ? AND role = ? AND kind = 'INSPECTION'",
                (scan_id, role),
            )
            live = any(r["state"] in LIVE_ASSIGNMENT_STATES and parse_iso(r["lease_expires_at"]) >= now for r in rows)
            if rows and not live and len(rows) >= 1 + retries:
                exhausted.add(role)
        forbidden = self.db.query_one(
            "SELECT 1 FROM collector_events WHERE scan_id = ? AND effective_policy_check = ?",
            (scan_id, PolicyCheck.FORBIDDEN.value),
        )
        return decide(
            DecisionInputs(
                extraction_statuses=statuses,
                unsupported_relevant=unsupported_relevant,
                extraction_limit_exceeded=total_chars > self.config.limits.max_extracted_chars,
                required_roles=tuple(required),
                results=results,
                exhausted_roles=frozenset(exhausted),
                deadline_passed=now >= parse_iso(scan["deadline_at"]),
                verified_forbidden_action=forbidden is not None,
            )
        )

    def _try_decide(self, scan_id: str) -> None:
        scan = self._scan(scan_id)
        if scan["state"] != JobState.INSPECTING.value:
            return
        outcome = self._evaluate(scan_id)
        if outcome.decision is not None:
            self._finalize(scan_id, outcome)

    def _finalize(self, scan_id: str, outcome: DecisionOutcome) -> None:
        scan = self._scan(scan_id)
        output_record = None
        if outcome.decision != Decision.QUARANTINE:
            output_record = self._build_output(scan)
        now = self._now()
        with self.db.transaction() as conn:
            if not self._set_state(conn, scan_id, JobState.DECIDED, [JobState.EXTRACTING, JobState.INSPECTING]):
                if output_record:
                    self.store.delete(output_record[1], scan["tenant_id"])
                return
            outstanding = conn.execute(
                "UPDATE assignments SET state = 'CANCELED' WHERE scan_id = ? AND state IN ('ASSIGNED', 'DELIVERED', 'UNDELIVERED')",
                (scan_id,),
            ).rowcount
            conn.execute(
                "UPDATE scans SET decision = ?, reason_codes_json = ?, decided_at = ?, decision_expires_at = ?, "
                "decision_record_json = ? WHERE scan_id = ?",
                (
                    outcome.decision.value, _dumps(list(outcome.reason_codes)), iso(now),
                    iso(min(after(now, self.config.retention.decision_seconds), self._source_expiry(scan))),
                    _dumps(self._decision_record(conn, scan, outcome.decision.value)), scan_id,
                ),
            )
            conn.execute("UPDATE job_tokens SET revoked_at = ? WHERE scan_id = ? AND revoked_at IS NULL", (iso(now), scan_id))
            if output_record:
                digest, ref, label_ids = output_record
                conn.execute(
                    "INSERT INTO outputs VALUES (?, ?, ?, ?, ?, ?, NULL)",
                    (scan_id, scan["tenant_id"], digest, ref, _dumps(label_ids), iso(now)),
                )
            self._event(conn, scan_id, scan["tenant_id"], "DECIDED", decision=outcome.decision.value, reasons=list(outcome.reason_codes))
        if outstanding:
            self._cancel_runtime(scan_id)

    def _completed_checks(self, conn, scan) -> list[str]:
        scan_id = scan["scan_id"]
        extractions = conn.execute("SELECT status FROM extractions WHERE scan_id = ?", (scan_id,)).fetchall()
        completed = []
        if extractions and len(extractions) == len(_loads(scan["resource_ids_json"])) and all(
            e["status"] == ExtractionStatus.COMPLETE.value for e in extractions
        ):
            completed.append("EXTRACTION")
        completed += [
            r["role"]
            for r in conn.execute(
                "SELECT role, inspection_status FROM worker_results WHERE scan_id = ? ORDER BY role", (scan_id,)
            ).fetchall()
            if r["inspection_status"] == InspectionStatus.COMPLETE.value
        ]
        return completed

    def _decision_record(self, conn, scan, decision: str) -> dict:
        """Durable decision record (master section 10): policy version,
        completed checks, decision and the evidence IDs it rests on."""
        evidence_ids = sorted(
            {e for r in conn.execute("SELECT findings_json FROM worker_results WHERE scan_id = ?", (scan["scan_id"],))
             for f in _loads(r["findings_json"], []) for e in f["evidence_ids"]}
            | {r["evidence_id"] for r in conn.execute(
                "SELECT evidence_id FROM collector_events WHERE scan_id = ? AND effective_policy_check = ?",
                (scan["scan_id"], PolicyCheck.FORBIDDEN.value))}
        )
        return {
            "policy_id": scan["policy_id"],
            "policy_version": scan["policy_version"],
            "decision": decision,
            "completed_checks": self._completed_checks(conn, scan),
            "evidence_ids": evidence_ids,
        }

    def _build_output(self, scan) -> tuple[str, str, list[str]] | None:
        row = self.db.query_one(
            "SELECT task_output_ref FROM worker_results WHERE scan_id = ? AND role = ? AND task_output_ref IS NOT NULL",
            (scan["scan_id"], WorkerRole.BEHAVIOR_TESTER.value),
        )
        if row is None:
            return None
        raw = json.loads(self.store.get(row["task_output_ref"], scan["tenant_id"]))
        labels = {
            r["resource_id"]: r["label_id"]
            for r in self.db.query_all("SELECT resource_id, label_id FROM resources WHERE tenant_id = ?", (scan["tenant_id"],))
            if r["resource_id"] in _loads(scan["resource_ids_json"])
        }

        def label_for(refs: list) -> list[str]:
            return sorted({labels[ref["resource_id"]] for ref in refs})

        if raw["kind"] == OUTPUT_INVOICE:
            body = {
                "kind": raw["kind"],
                "fields": {
                    name: field if "absent" in field else dict(field, label_ids=label_for(field["source_refs"]))
                    for name, field in raw["fields"].items()
                },
            }
        else:
            body = {
                "kind": raw["kind"],
                "statements": [dict(s, label_ids=label_for(s["source_refs"])) for s in raw["statements"]],
            }
        # Combining private sources keeps every label (most restrictive).
        all_labels = sorted(set(labels.values()))
        output = {
            "contract_version": CONTRACT_VERSION,
            "scan_id": scan["scan_id"],
            "policy_id": scan["policy_id"],
            "context_hash": scan["context_hash"],
            "trust": "UNTRUSTED_INSPECTED_UNDER_POLICY",
            "label_ids": all_labels,
            "output": body,
        }
        digest = canonical_digest(output)
        ref = self.store.put(scan["tenant_id"], "output", _dumps(output).encode("utf-8"))
        return digest, ref, all_labels

    # --------------------------------------------------------------- recovery

    def _recover_scan(self, scan_id: str) -> None:
        scan = self._scan(scan_id)
        if scan is None:
            return
        if scan["state"] in (JobState.QUEUED.value, JobState.EXTRACTING.value):
            if self._now() >= parse_iso(scan["deadline_at"]):
                self._fail(scan_id, ReasonCode.TIMEOUT)
            return
        if scan["state"] != JobState.INSPECTING.value:
            return
        now = self._now()
        deadline = parse_iso(scan["deadline_at"])
        with self.db.transaction() as conn:
            stale = conn.execute(
                "SELECT assignment_id FROM assignments WHERE scan_id = ? AND kind = 'INSPECTION' AND "
                "(state = 'UNDELIVERED' OR (state IN ('ASSIGNED', 'DELIVERED') AND lease_expires_at < ?))",
                (scan_id, iso(now)),
            ).fetchall()
            for row in stale:
                conn.execute("UPDATE assignments SET state = 'EXPIRED' WHERE assignment_id = ?", (row["assignment_id"],))
                conn.execute(
                    "UPDATE job_tokens SET revoked_at = ? WHERE assignment_id = ? AND revoked_at IS NULL",
                    (iso(now), row["assignment_id"]),
                )
                self._event(conn, scan_id, scan["tenant_id"], "LEASE_EXPIRED", assignment_id=row["assignment_id"])
        retry = []
        retries = _loads(scan["budget_json"])["worker_retries"]
        if now < deadline:
            done = {r["role"] for r in self.db.query_all("SELECT role FROM worker_results WHERE scan_id = ?", (scan_id,))}
            for role in self._required_roles(scan):
                if role in done:
                    continue
                rows = self.db.query_all(
                    "SELECT state FROM assignments WHERE scan_id = ? AND role = ? AND kind = 'INSPECTION'",
                    (scan_id, role),
                )
                if any(r["state"] in LIVE_ASSIGNMENT_STATES for r in rows):
                    continue
                if len(rows) < 1 + retries:
                    retry.append(role)
        if retry:
            self._dispatch(scan_id, retry)
        self._try_decide(scan_id)

    def recover(self, *, startup: bool = False) -> None:
        """Reclaim expired leases and enforce deadlines. On startup, scans
        interrupted mid-extraction fail closed rather than resume silently."""
        for row in self.db.query_all(
            "SELECT scan_id, state FROM scans WHERE state IN (?, ?, ?)", tuple(s.value for s in ACTIVE_JOB_STATES)
        ):
            if row["state"] in (JobState.QUEUED.value, JobState.EXTRACTING.value):
                if startup:
                    self._fail(row["scan_id"], ReasonCode.INTERRUPTED)
                else:
                    self._recover_scan(row["scan_id"])
            else:
                self._recover_scan(row["scan_id"])

    # ------------------------------------------------------- status / results

    def get_scan_status(self, principal: Principal, scan_id: str) -> dict:
        self._require_channel(principal, ALL_CHANNELS)
        self._owned("scans", "scan_id", scan_id, principal)
        self._recover_scan(scan_id)
        scan = self._scan(scan_id)
        extractions = self.db.query_all("SELECT * FROM extractions WHERE scan_id = ? ORDER BY resource_id", (scan_id,))
        results = self.db.query_all(
            "SELECT * FROM worker_results WHERE scan_id = ? ORDER BY role", (scan_id,)
        )
        with self.db.transaction() as conn:
            completed = self._completed_checks(conn, scan)
        reasons = _loads(scan["reason_codes_json"], [])
        output = self.db.query_one("SELECT * FROM outputs WHERE scan_id = ? AND deleted_at IS NULL", (scan_id,))
        eligible = (
            scan["state"] == JobState.DECIDED.value
            and review_exception_eligible(scan["decision"], reasons)
            and output is not None
        )
        if eligible:
            try:
                self._require_not_stopped()
                self._check_scan_bindings(scan)
            except GatewayError:
                eligible = False
        status = {
            "scan_id": scan_id,
            "task_session_id": scan["task_session_id"],
            "task_scope_version": scan["task_scope_version"],
            "policy_id": scan["policy_id"],
            "state": scan["state"],
            "decision": scan["decision"],
            "reason_codes": reasons,
            "required_checks": _loads(scan["required_checks_json"]),
            "completed_checks": completed,
            "coverage": {
                "extraction": [
                    {
                        "resource_id": e["resource_id"],
                        "status": e["status"],
                        "unsupported_parts": [
                            {k: p[k] for k in ("part_id", "media_type", "task_relevant", "reason")}
                            for p in _loads(e["unsupported_json"], [])
                        ],
                    }
                    for e in extractions
                ],
                "inspections": {r["role"]: r["inspection_status"] for r in results},
            },
            "findings": [
                {"role": r["role"], "category": f["category"], "resource_id": f["resource_id"], "evidence_ids": f["evidence_ids"]}
                for r in results
                for f in _loads(r["findings_json"], [])
            ],
            "collector_evidence": [
                {"evidence_id": e["evidence_id"], "operation": e["operation"], "policy_check": e["effective_policy_check"]}
                for e in self.db.query_all(
                    "SELECT evidence_id, operation, effective_policy_check FROM collector_events "
                    "WHERE scan_id = ? AND effective_policy_check = ? ORDER BY sequence",
                    (scan_id, PolicyCheck.FORBIDDEN.value),
                )
            ],
            "created_at": scan["created_at"],
            "updated_at": scan["updated_at"],
            "deadline_at": scan["deadline_at"],
            "decision_expires_at": scan["decision_expires_at"],
            "review": {"eligible": eligible, **({"result_digest": output["output_digest"]} if eligible else {})},
        }
        exception = eligible and output and self._active_exception(scan, principal.user_id, output['output_digest'])
        status['review_exception'] = {'active': bool(exception), **({'expires_at': exception['expires_at']} if exception else {})}
        status['inference_mode'] = self._inference_mode(scan)
        return status

    def _inference_mode(self, scan) -> str:
        """LIVE or REPLAY for the model configuration bound into this scan.

        Replay is a separate configuration (its binding carries inference=replay),
        so a scan created under replay never shares the live hash. UNKNOWN means
        the scan was bound to a configuration this gateway no longer runs.
        """
        if scan["model_configuration_hash"] != self.config.model_configuration_hash:
            return "UNKNOWN"
        return "REPLAY" if self.config.model_configuration.get("inference") == "replay" else "LIVE"

    def _source_expiry(self, scan):
        expiries = []
        for rid in _loads(scan["resource_ids_json"]):
            row = self.db.query_one(
                "SELECT * FROM resources WHERE resource_id = ? AND tenant_id = ? AND owner_id = ?",
                (rid, scan["tenant_id"], scan["owner_id"]),
            )
            if row is None or row["deleted_at"] or parse_iso(row["evidence_expires_at"]) <= self._now():
                raise GatewayError(ErrorCode.CONTEXT_CHANGED, "source expired")
            expiries.append(parse_iso(row["evidence_expires_at"]))
        return min(expiries)

    def _check_scan_bindings(self, scan) -> None:
        if self.db.query_one(
            "SELECT 1 FROM collector_events WHERE scan_id = ? AND effective_policy_check = 'FORBIDDEN' LIMIT 1",
            (scan["scan_id"],),
        ):
            raise GatewayError(ErrorCode.FORBIDDEN, "forbidden collector evidence")
        session = self.db.query_one("SELECT * FROM task_sessions WHERE task_session_id = ?", (scan["task_session_id"],))
        current = self._current_bindings(session)
        if (
            current["context_hash"] != scan["context_hash"]
            or current["resource_set_hash"] != scan["resource_set_hash"]
            or session["policy_hash"] != scan["policy_hash"]
        ):
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "bindings changed")
        if not scan["decision_expires_at"] or parse_iso(scan["decision_expires_at"]) <= self._now():
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "decision expired")

    def _active_exception(self, scan, user_id: str, output_digest: str):
        return self.db.query_one(
            "SELECT * FROM review_exceptions WHERE scan_id = ? AND tenant_id = ? AND user_id = ? AND revoked_at IS NULL "
            "AND expires_at > ? AND result_digest = ? AND context_hash = ?",
            (scan["scan_id"], scan["tenant_id"], user_id, self._now_iso(), output_digest, scan["context_hash"]),
        )

    def get_inspected_result(self, principal: Principal, scan_id: str) -> dict:
        self._require_channel(principal, ALL_CHANNELS)
        self._owned("scans", "scan_id", scan_id, principal)
        self._require_not_stopped()
        self._recover_scan(scan_id)
        with self.db.transaction():
            self._require_not_stopped()
            scan = self._scan(scan_id)
            state = scan["state"]
            if state in (JobState.QUEUED.value, JobState.EXTRACTING.value, JobState.INSPECTING.value):
                raise GatewayError(ErrorCode.NOT_READY, "inspection incomplete")
            if state != JobState.DECIDED.value:
                raise GatewayError(ErrorCode.FORBIDDEN, "scan failed or canceled", retryable=False)
            if scan["decision"] == Decision.QUARANTINE.value:
                raise GatewayError(ErrorCode.FORBIDDEN, "quarantined")
            self._check_scan_bindings(scan)
            output = self.db.query_one("SELECT * FROM outputs WHERE scan_id = ? AND deleted_at IS NULL", (scan_id,))
            if scan["decision"] == Decision.ALLOW_UNDER_POLICY.value:
                basis, exception = "ALLOW_UNDER_POLICY", None
            else:
                exception = output and self._active_exception(scan, principal.user_id, output["output_digest"])
                if not exception:
                    raise GatewayError(ErrorCode.APPROVAL_REQUIRED, "review pending", retryable=False)
                basis = "REVIEW_EXCEPTION"
            if output is None or not output["storage_ref"]:
                raise GatewayError(ErrorCode.CONTEXT_CHANGED, "output unavailable")
            payload = self.store.get(output["storage_ref"], scan["tenant_id"])
            content = json.loads(payload)
            if canonical_digest(content) != output["output_digest"]:
                raise GatewayError(ErrorCode.SERVICE_UNAVAILABLE, "output integrity check failed", retryable=False)
            labels = [
                {"label_id": r["label_id"], "disclosure": r["disclosure"]}
                for r in self.db.query_all(
                    "SELECT label_id, disclosure FROM labels WHERE tenant_id = ? ORDER BY label_id", (scan["tenant_id"],)
                )
                if r["label_id"] in content["label_ids"]
            ]
            expires = scan["decision_expires_at"] if exception is None else min(scan["decision_expires_at"], exception["expires_at"])
            return {
                "scan_id": scan_id,
                "decision": scan["decision"],
                "release_basis": basis,
                "read_only": True,
                "result_digest": output["output_digest"],
                "expires_at": expires,
                "labels": labels,
                "inference_mode": self._inference_mode(scan),
                "result": content,
            }

    def cancel_scan(self, principal: Principal, scan_id: str) -> dict:
        self._require_channel(principal, WRITE_CHANNELS)
        scan = self._owned("scans", "scan_id", scan_id, principal)
        with self.db.transaction() as conn:
            changed = self._terminate(conn, scan, JobState.CANCELED, [ReasonCode.CANCELED_BY_USER.value])
        if changed:
            self._cancel_runtime(scan_id)
        return self.get_scan_status(principal, scan_id)

    def review_scan(self, principal: Principal, scan_id: str, body: Mapping) -> dict:
        """User-only REJECT or eligible ALLOW_READ_ONLY exception."""
        self._require_channel(principal, USER_ONLY)
        req = schemas.validate(schemas.review_request, body)
        scan = self._owned("scans", "scan_id", scan_id, principal)
        if req["action"] == ReviewAction.REJECT.value:
            with self.db.transaction() as conn:
                changed = self._terminate(conn, scan, JobState.CANCELED, [ReasonCode.REJECTED_BY_USER.value])
            if changed:
                self._cancel_runtime(scan_id)
            return {"scan_id": scan_id, "review": ReviewAction.REJECT.value, "state": self._scan(scan_id)["state"]}

        reasons = _loads(scan["reason_codes_json"], [])
        if scan["state"] != JobState.DECIDED.value or not review_exception_eligible(scan["decision"], reasons):
            raise GatewayError(ErrorCode.FORBIDDEN, "not eligible for a review exception")
        if "result_digest" not in req:
            raise GatewayError(ErrorCode.INVALID_REQUEST, "result_digest required")
        self._check_scan_bindings(scan)
        output = self.db.query_one("SELECT * FROM outputs WHERE scan_id = ? AND deleted_at IS NULL", (scan_id,))
        if output is None or output["output_digest"] != req["result_digest"]:
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "result digest mismatch")
        now = self._now()
        requested = req.get("expires_in_seconds", self.config.retention.review_exception_max_seconds)
        expires = min(
            after(now, min(requested, self.config.retention.review_exception_max_seconds)),
            parse_iso(scan["decision_expires_at"]),
        )
        exception_id = self.ids.new("rx")
        with self.db.transaction() as conn:
            self._require_not_stopped()
            scan = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if scan["state"] != JobState.DECIDED.value or not review_exception_eligible(
                scan["decision"], _loads(scan["reason_codes_json"], [])
            ):
                raise GatewayError(ErrorCode.FORBIDDEN, "not eligible for a review exception")
            self._check_scan_bindings(scan)
            output = conn.execute("SELECT * FROM outputs WHERE scan_id = ? AND deleted_at IS NULL", (scan_id,)).fetchone()
            if output is None or output["output_digest"] != req["result_digest"]:
                raise GatewayError(ErrorCode.CONTEXT_CHANGED, "result digest mismatch")
            now = self._now()
            expires = min(after(now, min(requested, self.config.retention.review_exception_max_seconds)),
                          parse_iso(scan["decision_expires_at"]))
            conn.execute(
                "INSERT INTO review_exceptions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    exception_id, scan_id, scan["tenant_id"], principal.user_id, output["output_digest"], scan["context_hash"],
                    scan["resource_set_hash"], scan["resource_ids_json"], req["reason"], iso(now), iso(expires),
                ),
            )
            self._event(conn, scan_id, scan["tenant_id"], "REVIEW_EXCEPTION", exception_id=exception_id)
        return {
            "scan_id": scan_id,
            "review": ReviewAction.ALLOW_READ_ONLY.value,
            "exception_id": exception_id,
            "decision": scan["decision"],
            "result_digest": output["output_digest"],
            "read_only": True,
            "expires_at": iso(expires),
        }

    # --------------------------------------------------------------- evidence

    def get_evidence(self, principal: Principal, evidence_id: str) -> dict:
        """Bounded, HTML-escaped text for the user's evidence viewer.
        Never an assistant tool and never fed back into a model."""
        self._require_channel(principal, EVIDENCE_CHANNELS)
        row = self._owned("evidence", "evidence_id", evidence_id, principal)
        if row["deleted_at"] or parse_iso(row["expires_at"]) <= self._now():
            raise GatewayError(ErrorCode.NOT_FOUND, "evidence expired")
        self._source_expiry(self._scan(row["scan_id"]))
        scan = self._scan(row["scan_id"])
        source_excerpts = []
        if row["source"] == "COLLECTOR":
            ev = self.db.query_one(
                "SELECT * FROM collector_events WHERE event_id = ? AND tenant_id = ?", (row["collector_event_id"], row["tenant_id"])
            )
            text = (
                f"operation={ev['operation']} outcome={ev['attempted_outcome']} "
                f"policy_check={ev['effective_policy_check']} sequence={ev['sequence']} at={ev['event_timestamp']}"
            )
        else:
            text = self.store.get(row["storage_ref"], row["tenant_id"]).decode("utf-8", errors="replace")
            try:
                artifact = json.loads(text)
            except (TypeError, ValueError):
                artifact = None
            if isinstance(artifact, dict) and isinstance(artifact.get("model_findings"), list):
                view_hashes = {}
                for extraction in self.db.query_all(
                    "SELECT resource_id, views_json FROM extractions WHERE scan_id = ?", (scan["scan_id"],)
                ):
                    for view in _loads(extraction["views_json"], []):
                        view_hashes[(extraction["resource_id"], view.get("view_id"))] = view.get("view_hash")
                source_cache = {}
                for finding_index, finding in enumerate(artifact["model_findings"][:64]):
                    if not isinstance(finding, dict) or not isinstance(finding.get("source_references"), list):
                        continue
                    for reference_index, ref in enumerate(finding["source_references"][:20]):
                        if not isinstance(ref, dict):
                            continue
                        resource_id, view_id = ref.get("resource_id"), ref.get("view_id")
                        span = ref.get("span")
                        if (not isinstance(resource_id, str) or not isinstance(view_id, str)
                                or view_hashes.get((resource_id, view_id)) != ref.get("view_hash")
                                or not isinstance(span, list) or len(span) != 2
                                or any(type(offset) is not int for offset in span)):
                            continue
                        source_key = (resource_id, ref["view_hash"])
                        if source_key not in source_cache:
                            source_cache[source_key] = self._view_text(scan, resource_id, ref["view_hash"])
                        source_text = source_cache[source_key]
                        if source_text is None or span[0] < 0 or span[1] < span[0] or span[1] > len(source_text):
                            continue
                        excerpt_start = max(0, span[0] - 100)
                        excerpt_end = min(len(source_text), excerpt_start + 520)
                        source_excerpts.append({
                            "finding_index": finding_index,
                            "reference_index": reference_index,
                            "text": source_text[excerpt_start:excerpt_end],
                            "truncated": excerpt_start > 0 or excerpt_end < len(source_text) or span[1] > excerpt_end,
                        })
                        if len(source_excerpts) >= 64:
                            break
                    if len(source_excerpts) >= 64:
                        break
        limit = self.config.limits.evidence_view_chars
        return {
            "evidence_id": evidence_id,
            "scan_id": row["scan_id"],
            "kind": row["kind"],
            "source": row["source"],
            "content_type": "text/plain",
            "text_escaped": html.escape(text[:limit], quote=True),
            "source_excerpts": source_excerpts,
            "truncated": len(text) > limit,
        }

    # ---------------------------------------------------------------- actions

    def propose_simulated_action(self, principal: Principal, body: Mapping) -> dict:
        return self.actions.propose(principal, body)

    def get_action(self, principal: Principal, action_id: str) -> dict:
        return self.actions.get(principal, action_id)

    def confirm_simulated_action(self, principal: Principal, action_id: str, body: Mapping) -> dict:
        return self.actions.confirm(principal, action_id, body)

    def execute_simulated_action(
        self, principal: Principal, action_id: str, body: Mapping, idempotency_key: str | None
    ) -> dict:
        return self.actions.execute(principal, action_id, body, idempotency_key)

    # ------------------------------------------------- worker capability API

    def issue_job_capability(self, assignment_id: str) -> str:
        """Called in process by B's launcher to provision a worker's
        short-lived resource capability over a private channel. Re-issuing
        revokes earlier capabilities for the assignment. Not an HTTP route."""
        self._require_not_stopped()
        assignment = self.db.query_one("SELECT * FROM assignments WHERE assignment_id = ?", (assignment_id,))
        if assignment is None:
            raise GatewayError(ErrorCode.NOT_FOUND, "assignment not found")
        scan = self._scan(assignment["scan_id"])
        live = assignment["state"] in LIVE_ASSIGNMENT_STATES and parse_iso(assignment["lease_expires_at"]) >= self._now()
        if not live or scan["state"] not in (JobState.EXTRACTING.value, JobState.INSPECTING.value):
            raise GatewayError(ErrorCode.FORBIDDEN, "assignment not live")
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE job_tokens SET revoked_at = ? WHERE assignment_id = ? AND revoked_at IS NULL",
                (self._now_iso(), assignment_id),
            )
            return self._new_token(conn, assignment_id, scan, assignment["worker_id"])

    def _token_row(self, capability: str, verified_identity: Mapping):
        self._require_not_stopped()
        identity = schemas.validate(schemas.worker_identity, dict(verified_identity), "$identity")
        if not isinstance(capability, str) or not capability:
            raise GatewayError(ErrorCode.UNAUTHENTICATED, "missing capability")
        row = self.db.query_one("SELECT * FROM job_tokens WHERE token_hash = ?", (GatewayConfig.hash_token(capability),))
        if row is None or row["revoked_at"] or parse_iso(row["expires_at"]) <= self._now():
            raise GatewayError(ErrorCode.UNAUTHENTICATED, "invalid capability")
        assignment = self.db.query_one("SELECT * FROM assignments WHERE assignment_id = ?", (row["assignment_id"],))
        if assignment is None or assignment["state"] not in LIVE_ASSIGNMENT_STATES or parse_iso(assignment["lease_expires_at"]) <= self._now():
            raise GatewayError(ErrorCode.FORBIDDEN, "assignment no longer live")
        if any(assignment[key] != identity[key] for key in ("worker_id", "role", "build_version", "prompt_version")):
            raise GatewayError(ErrorCode.FORBIDDEN, "capability bound to another worker")
        scan = self._scan(row["scan_id"])
        if scan["state"] not in (JobState.EXTRACTING.value, JobState.INSPECTING.value):
            raise GatewayError(ErrorCode.FORBIDDEN, "scan not active")
        session = self.db.query_one("SELECT * FROM task_sessions WHERE task_session_id = ?", (scan["task_session_id"],))
        if self._current_bindings(session)["context_hash"] != scan["context_hash"]:
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "bindings changed")
        return row, assignment, scan

    def validate_job_token(self, capability: str, verified_identity: Mapping) -> dict:
        _, assignment, _ = self._token_row(capability, verified_identity)
        return {"assignment_id": assignment["assignment_id"], "scan_id": assignment["scan_id"], "kind": assignment["kind"]}

    def read_assigned_original(self, capability: str, verified_identity: Mapping, resource_id: str) -> bytes:
        _, assignment, scan = self._token_row(capability, verified_identity)
        payload = _loads(assignment["assignment_json"])
        if assignment["kind"] != "EXTRACTION" or payload["resource_id"] != resource_id:
            raise GatewayError(ErrorCode.FORBIDDEN, "resource not assigned")
        resource = self.db.query_one(
            "SELECT * FROM resources WHERE resource_id = ? AND tenant_id = ?", (resource_id, scan["tenant_id"])
        )
        if resource is None or not resource["storage_ref"]:
            raise GatewayError(ErrorCode.NOT_FOUND, "resource unavailable")
        data = self.store.get(resource["storage_ref"], scan["tenant_id"])
        if sha256_hex(data) != resource["original_hash"]:
            raise GatewayError(ErrorCode.SERVICE_UNAVAILABLE, "stored object integrity failure", retryable=False)
        return data

    def read_assigned_view(self, capability: str, verified_identity: Mapping, resource_id: str, view_id: str) -> str:
        _, assignment, scan = self._token_row(capability, verified_identity)
        payload = _loads(assignment["assignment_json"])
        if assignment["kind"] != "INSPECTION":
            raise GatewayError(ErrorCode.FORBIDDEN, "not an inspection capability")
        assigned = {(r["resource_id"], v["view_id"]): v["view_hash"] for r in payload["resources"] for v in r["views"]}
        if (resource_id, view_id) not in assigned:
            raise GatewayError(ErrorCode.FORBIDDEN, "view not assigned")
        text = self._view_text(scan, resource_id, assigned[(resource_id, view_id)])
        if text is None:
            raise GatewayError(ErrorCode.NOT_FOUND, "view unavailable")
        return text

    # ------------------------------------------------------ emergency controls

    def emergency_stopped(self) -> bool:
        row = self.db.query_one("SELECT value FROM controls WHERE name = 'emergency_stop'")
        return row is not None and row["value"] == "1"

    def _require_not_stopped(self) -> None:
        if self.emergency_stopped():
            raise GatewayError(ErrorCode.SERVICE_UNAVAILABLE, "emergency stop active", retryable=False)

    def emergency_stop(self) -> dict:
        """Operator control (not an HTTP route): stop retrieval and new work,
        cancel queued and running jobs, revoke job capabilities and pending
        actions. Already-completed effects are not undone."""
        now_iso = self._now_iso()
        active = self.db.query_all(
            "SELECT * FROM scans WHERE state IN (?, ?, ?)", tuple(s.value for s in ACTIVE_JOB_STATES)
        )
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO controls VALUES ('emergency_stop', '1', ?) "
                "ON CONFLICT(name) DO UPDATE SET value = '1', updated_at = excluded.updated_at",
                (now_iso,),
            )
            for scan in active:
                self._terminate(conn, scan, JobState.CANCELED, [ReasonCode.EMERGENCY_STOP.value])
            conn.execute("UPDATE job_tokens SET revoked_at = ? WHERE revoked_at IS NULL", (now_iso,))
            pending = conn.execute(
                "SELECT DISTINCT task_session_id FROM actions WHERE state IN (?, ?)",
                (ActionState.PROPOSED.value, ActionState.CONFIRMED.value),
            ).fetchall()
            for row in pending:
                self.actions.invalidate_session_actions(conn, row["task_session_id"], ActionState.CANCELED)
        for scan in active:
            self._cancel_runtime(scan["scan_id"])
        log.warning("emergency_stop scans_canceled=%d", len(active))
        return {"emergency_stop": True, "scans_canceled": len(active)}

    def emergency_resume(self) -> dict:
        self.db.execute("UPDATE controls SET value = '0', updated_at = ? WHERE name = 'emergency_stop'", (self._now_iso(),))
        return {"emergency_stop": False}

    # -------------------------------------------------------------- retention

    def run_retention(self) -> dict:
        """Expire evidence, metadata, tokens, sessions and pending approvals."""
        now = self._now()
        now_iso = iso(now)
        counts = {"resources": 0, "scans_purged": 0, "metadata_deleted": 0}
        for row in self.db.query_all(
            "SELECT * FROM resources WHERE deleted_at IS NULL AND evidence_expires_at <= ?", (now_iso,)
        ):
            self._purge_resource(row, ReasonCode.RESOURCE_DELETED)
            counts["resources"] += 1
        evidence_cutoff = iso(after(now, -self.config.retention.evidence_seconds))
        for scan in self.db.query_all("SELECT * FROM scans WHERE created_at <= ?", (evidence_cutoff,)):
            with self.db.transaction() as conn:
                self._purge_scan_content(conn, scan)
            counts["scans_purged"] += 1
        meta_cutoff = iso(after(now, -self.config.retention.metadata_seconds))
        with self.db.transaction() as conn:
            old = [r["scan_id"] for r in conn.execute("SELECT scan_id FROM scans WHERE created_at <= ?", (meta_cutoff,))]
            for scan_id in old:
                for table in (
                    "extractions", "assignments", "job_tokens", "worker_results", "evidence", "collector_events",
                    "scan_events", "outputs", "review_exceptions",
                ):
                    conn.execute(f"DELETE FROM {table} WHERE scan_id = ?", (scan_id,))
                conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            counts["metadata_deleted"] = len(old)
            conn.execute("DELETE FROM resources WHERE deleted_at IS NOT NULL AND created_at <= ?", (meta_cutoff,))
            conn.execute("DELETE FROM task_sessions WHERE created_at <= ?", (meta_cutoff,))
            conn.execute("DELETE FROM labels WHERE created_at <= ? AND NOT EXISTS ("
                         "SELECT 1 FROM resources r WHERE r.resource_id = labels.source_resource_id)", (meta_cutoff,))
            conn.execute("DELETE FROM job_tokens WHERE expires_at <= ? OR revoked_at IS NOT NULL", (now_iso,))
            conn.execute("DELETE FROM browser_sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL", (now_iso,))
            conn.execute("DELETE FROM seen_nonces WHERE seen_at <= ?", (meta_cutoff,))
            conn.execute("DELETE FROM idempotency WHERE created_at <= ?", (meta_cutoff,))
            self.actions.purge_retained_content(conn, evidence_cutoff, meta_cutoff)
            self.actions.expire(conn, now_iso)
        return counts


_CURRENCY_SYMBOLS = {"$": "USD", "€": "EUR", "£": "GBP", "¥": "JPY"}
_PUBLIC_MEDIA_TYPES = {"application/pdf", "application/octet-stream", "message/rfc822", "text/plain", "text/html", "image/png", "image/jpeg"}
_PUBLIC_UNSUPPORTED_REASONS = {"UNSUPPORTED_FORMAT", "UNSUPPORTED_CONTENT", "ENCRYPTED_CONTENT", "LIMIT_EXCEEDED", "EXTRACTION_ERROR"}
_AMOUNT_TOKEN = re.compile(
    r"(?<![\w.,])(?:(?P<sign_before>[-+−﹣－＋])\s*(?:[$€£¥]\s*)?|[$€£¥]\s*(?P<sign_after>[-+−﹣－＋]?)\s*)?"
    r"(?P<number>(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?)(?![\w.]|,\d)"
)
_DATE_FORMATS = ("%Y-%m-%d", "%d %B %Y", "%B %d, %Y", "%d %b %Y", "%b %d, %Y")


def _value_matches(field: str, value: str, span_text: str) -> bool:
    """Deterministic comparison of an extracted value with its cited span."""
    text = span_text.strip()
    if field == "invoice_id":
        return value in text
    if field == "currency":
        return value in text.upper() or any(sym in text and code == value for sym, code in _CURRENCY_SYMBOLS.items())
    if field == "amount":
        digits = re.sub(r"[^0-9.\-]", "", text.replace(",", ""))
        try:
            return Decimal(digits) == Decimal(value)
        except (InvalidOperation, ValueError):
            return False
    if field == "due_date":
        if value in text:
            return True
        for fmt in _DATE_FORMATS:
            try:
                return datetime.strptime(text, fmt).strftime("%Y-%m-%d") == value
            except ValueError:
                continue
        return False
    return False
