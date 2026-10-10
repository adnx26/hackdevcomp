"""Simulated-action gate: propose -> exact preview -> user confirmation -> execute.

Reading a source, allowing a scan and confirming an action are separate
authorizations. Only the user-owned interface session confirms; a
model-written approval string has no effect. The v1 executor changes dummy
state only and there is no real-provider fallback.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Mapping

from ..contracts import schemas
from ..contracts.canonical import canonical_digest, sha256_hex
from ..contracts.enums import (
    CONTRACT_VERSION,
    ActionState,
    Channel,
    Decision,
    ErrorCode,
    ExecutionOutcome,
    JobState,
    PolicyCheck,
    RecipientTrust,
)
from ..contracts.errors import GatewayError
from ..contracts.policies import SIMULATED_SEND_OPERATION, get_policy
from ..contracts.validation import ID_PATTERN
from .auth import Principal
from .clock import after, iso, parse_iso

if TYPE_CHECKING:  # pragma: no cover
    from .service import GatewayService

WRITE_CHANNELS = frozenset({Channel.USER_INTERFACE, Channel.API, Channel.ASSISTANT})
PENDING_STATES = (ActionState.PROPOSED.value, ActionState.CONFIRMED.value)


class SimulatedMailboxExecutor:
    """Records a dummy send inside the gateway's write transaction."""

    def execute(self, conn, action: Mapping) -> tuple[str, str | None]:
        arguments = action["arguments"]
        conn.execute(
            "INSERT INTO dummy_mailbox VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                action["effect_id"], action["action_id"], action["tenant_id"], action["owner_id"], arguments["to"],
                sha256_hex(arguments["subject"]), sha256_hex(arguments["body"]), json.dumps(action["attachments"]), action["now"],
            ),
        )
        return ExecutionOutcome.SUCCEEDED.value, action["effect_id"]


class ActionGate:
    def __init__(self, service: "GatewayService", executor):
        self.s = service
        self.executor = executor

    # ------------------------------------------------------------ helpers

    def _arguments(self, row: Mapping) -> dict:
        expiry = after(parse_iso(row["created_at"]), self.s.config.retention.evidence_seconds)
        for label_id in json.loads(row["label_ids_json"]):
            source = self.s.db.query_one(
                "SELECT r.* FROM resources r JOIN labels l ON l.source_resource_id = r.resource_id "
                "WHERE l.label_id = ? AND r.tenant_id = ? AND r.owner_id = ?",
                (label_id, row["tenant_id"], row["owner_id"]),
            )
            if source is None or source["deleted_at"]:
                raise GatewayError(ErrorCode.CONTEXT_CHANGED, "action source unavailable")
            expiry = min(expiry, parse_iso(source["evidence_expires_at"]))
        if self.s._now() >= expiry:
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "action content expired")
        ref = json.loads(row["arguments_json"]).get("storage_ref")
        if not ref:
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "action content expired")
        return json.loads(self.s.store.get(ref, row["tenant_id"]))

    def _digest_material(self, row: Mapping) -> dict:
        arguments = self._arguments(row)
        return {
            "contract_version": CONTRACT_VERSION,
            "action_id": row["action_id"],
            "task_session_id": row["task_session_id"],
            "task_scope_version": row["task_scope_version"],
            "context_hash": row["context_hash"],
            "policy_id": row["policy_id"],
            "policy_hash": row["policy_hash"],
            "operation": row["operation"],
            "arguments": {
                "to": arguments["to"],
                "subject": arguments["subject"],
                "body_sha256": sha256_hex(arguments["body"]),
                "attachments": json.loads(row["attachments_json"]),
            },
            "label_ids": json.loads(row["label_ids_json"]),
            "recipient_trust": row["recipient_trust"],
            "expires_at": row["expires_at"],
        }

    def _view(self, row) -> dict:
        arguments = self._arguments(row)
        view = {
            "action_id": row["action_id"],
            "state": row["state"],
            "task_session_id": row["task_session_id"],
            "task_scope_version": row["task_scope_version"],
            "context_hash": row["context_hash"],
            "policy_id": row["policy_id"],
            "operation": row["operation"],
            "preview": {
                "to": arguments["to"],
                "subject": arguments["subject"],
                "body": arguments["body"],
                "body_sha256": sha256_hex(arguments["body"]),
                "attachments": json.loads(row["attachments_json"]),
            },
            "recipient_trust": row["recipient_trust"],
            "requires_recipient_selection": row["recipient_trust"] == RecipientTrust.UNTRUSTED.value,
            "label_ids": json.loads(row["label_ids_json"]),
            "digest": row["digest"],
            "expires_at": row["expires_at"],
        }
        if row["outcome_json"]:
            view["outcome"] = json.loads(row["outcome_json"])
        return view

    def _allowed_scan_for(self, session, context_hash: str, resource_id: str):
        for scan in self.s.db.query_all(
            "SELECT * FROM scans WHERE task_session_id = ? AND tenant_id = ? AND state = ? AND decision = ? "
            "AND context_hash = ? AND decision_expires_at > ? AND NOT EXISTS ("
            "SELECT 1 FROM collector_events ce WHERE ce.scan_id = scans.scan_id "
            "AND ce.effective_policy_check = ?)",
            (
                session["task_session_id"], session["tenant_id"], JobState.DECIDED.value,
                Decision.ALLOW_UNDER_POLICY.value, context_hash, self.s._now_iso(), PolicyCheck.FORBIDDEN.value,
            ),
        ):
            if resource_id in json.loads(scan["resource_ids_json"]):
                return scan
        return None

    def _derive(self, principal: Principal, session, bindings: dict, arguments: dict, body_labeled: bool) -> tuple:
        """Server-side derivation of attachments, labels and recipient trust."""
        session_resources = json.loads(session["resource_ids_json"])
        attachments, label_ids = [], set()
        labels = {
            r["resource_id"]: r
            for r in self.s.db.query_all(
                "SELECT resource_id, label_id, original_hash, deleted_at FROM resources WHERE tenant_id = ? AND owner_id = ?",
                (principal.tenant_id, principal.user_id),
            )
        }
        for resource_id in arguments["attachment_resource_ids"]:
            if resource_id not in session_resources or resource_id not in labels or labels[resource_id]["deleted_at"]:
                raise GatewayError(ErrorCode.NOT_FOUND, "attachment not in task session")
            if self._allowed_scan_for(session, bindings["context_hash"], resource_id) is None:
                raise GatewayError(ErrorCode.FORBIDDEN, "attachment lacks an active allowed inspection")
            attachments.append({"resource_id": resource_id, "original_hash": labels[resource_id]["original_hash"]})
            label_ids.add(labels[resource_id]["label_id"])
        if body_labeled:
            # Text produced outside the user's own interface may derive from
            # session sources. Each source needs an active inspection as well
            # as its label, even when the action has no attachments.
            for resource_id in session_resources:
                if resource_id not in labels or labels[resource_id]["deleted_at"]:
                    raise GatewayError(ErrorCode.NOT_FOUND, "body source not in task session")
                if self._allowed_scan_for(session, bindings["context_hash"], resource_id) is None:
                    raise GatewayError(ErrorCode.FORBIDDEN, "body source lacks an active allowed inspection")
                label_ids.add(labels[resource_id]["label_id"])
        trust = (
            RecipientTrust.TRUSTED_CONTACT.value
            if self.s.config.is_trusted_contact(principal.tenant_id, principal.user_id, arguments["to"])
            else RecipientTrust.UNTRUSTED.value
        )
        if label_ids and trust != RecipientTrust.TRUSTED_CONTACT.value:
            raise GatewayError(ErrorCode.FORBIDDEN, "private-labeled data cannot go to an unapproved recipient")
        return attachments, sorted(label_ids), trust

    def _set_state(self, action_id: str, state: ActionState, expected=PENDING_STATES) -> None:
        with self.s.db.transaction() as conn:
            conn.execute(
                f"UPDATE actions SET state = ?, updated_at = ? WHERE action_id = ? AND state IN ({','.join('?' * len(expected))})",
                (state.value, self.s._now_iso(), action_id, *expected),
            )
            conn.execute(
                "UPDATE approvals SET revoked_at = ? WHERE action_id = ? AND used_at IS NULL AND revoked_at IS NULL",
                (self.s._now_iso(), action_id),
            )

    def _revalidate(self, principal: Principal, row) -> None:
        """Recheck task, policy, context, attachments, labels, trust and digest."""
        try:
            session = self.s._active_session(principal, row["task_session_id"])
            policy = get_policy(session["policy_id"])
            if policy is None or not policy.permits_simulated_send or policy.policy_hash != row["policy_hash"]:
                raise GatewayError(ErrorCode.CONTEXT_CHANGED, "policy changed")
            bindings = self.s._current_bindings(session)
            if bindings["context_hash"] != row["context_hash"] or session["scope_version"] != row["task_scope_version"]:
                raise GatewayError(ErrorCode.CONTEXT_CHANGED, "context changed")
            arguments = self._arguments(row)
            attachments, label_ids, trust = self._derive(
                principal, session, bindings, arguments, row["proposed_by_channel"] != Channel.USER_INTERFACE.value
            )
            if (
                attachments != json.loads(row["attachments_json"])
                or label_ids != json.loads(row["label_ids_json"])
                or trust != row["recipient_trust"]
                or canonical_digest(self._digest_material(row)) != row["digest"]
            ):
                raise GatewayError(ErrorCode.CONTEXT_CHANGED, "action bindings changed")
        except GatewayError as exc:
            if exc.code in (ErrorCode.CONTEXT_CHANGED, ErrorCode.FORBIDDEN, ErrorCode.NOT_FOUND):
                self._set_state(row["action_id"], ActionState.CANCELED)
                raise GatewayError(ErrorCode.CONTEXT_CHANGED, exc.detail) from exc
            raise

    def _expire_if_needed(self, row) -> None:
        if row["state"] == ActionState.PROPOSED.value and parse_iso(row["expires_at"]) <= self.s._now():
            self._set_state(row["action_id"], ActionState.EXPIRED, (ActionState.PROPOSED.value,))
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "proposal expired")

    # ------------------------------------------------------------- public

    def propose(self, principal: Principal, body: Mapping) -> dict:
        self.s._require_channel(principal, WRITE_CHANNELS)
        req = schemas.validate(schemas.action_request, body)
        self.s._require_not_stopped()
        session = self.s._active_session(principal, req["task_session_id"])
        policy = get_policy(session["policy_id"])
        if not policy.permits_simulated_send:
            raise GatewayError(ErrorCode.FORBIDDEN, "task policy does not permit sending")
        bindings = self.s._current_bindings(session)
        arguments = req["action"]["arguments"]
        if len(arguments["attachment_resource_ids"]) > self.s.config.limits.max_attachments:
            raise GatewayError(ErrorCode.LIMIT_EXCEEDED, "too many attachments", retryable=False)
        attachments, label_ids, trust = self._derive(
            principal, session, bindings, arguments, principal.channel != Channel.USER_INTERFACE
        )
        now = self.s._now()
        row = {
            "action_id": self.s.ids.new("act"),
            "tenant_id": principal.tenant_id,
            "owner_id": principal.user_id,
            "task_session_id": session["task_session_id"],
            "task_scope_version": session["scope_version"],
            "context_hash": bindings["context_hash"],
            "policy_id": policy.policy_id,
            "policy_hash": policy.policy_hash,
            "operation": SIMULATED_SEND_OPERATION,
            "arguments_json": json.dumps({"storage_ref": self.s.store.put(
                principal.tenant_id, "action", json.dumps(arguments, sort_keys=True).encode("utf-8")
            )}),
            "attachments_json": json.dumps(attachments),
            "label_ids_json": json.dumps(label_ids),
            "recipient_trust": trust,
            "state": ActionState.PROPOSED.value,
            "proposed_by_channel": principal.channel.value,
            "created_at": iso(now),
            "updated_at": iso(now),
            "expires_at": iso(after(now, self.s.config.retention.action_proposal_seconds)),
            "outcome_json": None,
        }
        row["digest"] = canonical_digest(self._digest_material(row))
        columns = (
            "action_id", "tenant_id", "owner_id", "task_session_id", "task_scope_version", "context_hash", "policy_id",
            "policy_hash", "operation", "arguments_json", "attachments_json", "label_ids_json", "recipient_trust",
            "digest", "state", "proposed_by_channel", "created_at", "updated_at", "expires_at", "outcome_json",
        )
        self.s.db.execute(
            f"INSERT INTO actions ({','.join(columns)}) VALUES ({','.join('?' * len(columns))})",
            tuple(row[c] for c in columns),
        )
        return self._view(row)

    def get(self, principal: Principal, action_id: str) -> dict:
        self.s._require_channel(principal, WRITE_CHANNELS)
        return self._view(self.s._owned("actions", "action_id", action_id, principal))

    def confirm(self, principal: Principal, action_id: str, body: Mapping) -> dict:
        # Only the user-owned interface session (cookie + CSRF) can confirm.
        self.s._require_channel(principal, frozenset({Channel.USER_INTERFACE}))
        req = schemas.validate(schemas.confirm_request, body)
        self.s._require_not_stopped()
        row = self.s._owned("actions", "action_id", action_id, principal)
        self._expire_if_needed(row)
        if row["state"] == ActionState.CONFIRMED.value and req["digest"] == row["digest"]:
            return self._view(row)
        if row["state"] != ActionState.PROPOSED.value:
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "action not pending confirmation")
        self._revalidate(principal, row)
        if req["digest"] != row["digest"]:
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "digest does not match the exact proposed action")
        selected = bool(req.get("recipient_selected_by_user", False))
        if row["recipient_trust"] == RecipientTrust.UNTRUSTED.value and not selected:
            raise GatewayError(ErrorCode.APPROVAL_REQUIRED, "user must explicitly select an untrusted recipient")
        now = self.s._now()
        approval_expires = min(
            after(now, self.s.config.retention.approval_seconds), parse_iso(row["expires_at"])
        )
        with self.s.db.transaction() as conn:
            changed = conn.execute(
                "UPDATE actions SET state = ?, updated_at = ? WHERE action_id = ? AND state = ?",
                (ActionState.CONFIRMED.value, iso(now), action_id, ActionState.PROPOSED.value),
            ).rowcount
            if changed != 1:
                raise GatewayError(ErrorCode.CONTEXT_CHANGED, "action not pending confirmation")
            conn.execute(
                "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                (
                    self.s.ids.new("apr"), action_id, principal.tenant_id, principal.user_id, row["digest"],
                    int(selected), iso(now), iso(approval_expires),
                ),
            )
        return self._view(self.s._owned("actions", "action_id", action_id, principal))

    def execute(self, principal: Principal, action_id: str, body: Mapping, idempotency_key: str | None) -> dict:
        self.s._require_channel(principal, WRITE_CHANNELS)
        schemas.validate(schemas.empty_request, body)
        self.s._require_not_stopped()
        if not idempotency_key or not ID_PATTERN.match(idempotency_key):
            raise GatewayError(ErrorCode.INVALID_REQUEST, "idempotency key required")
        row = self.s._owned("actions", "action_id", action_id, principal)
        scope = f"{principal.tenant_id}:{principal.user_id}:execute"
        request_digest = canonical_digest({"action_id": action_id})
        prior = self.s.db.query_one("SELECT * FROM idempotency WHERE scope = ? AND idem_key = ?", (scope, idempotency_key))
        if prior is not None:
            if prior["request_digest"] != request_digest:
                raise GatewayError(ErrorCode.INVALID_REQUEST, "idempotency key reused")
            return self._view(row)

        state = row["state"]
        if state in (ActionState.PROPOSED.value, ActionState.EXECUTED.value):
            raise GatewayError(ErrorCode.APPROVAL_REQUIRED, "no unused approval")
        if state == ActionState.UNKNOWN_OUTCOME.value:
            raise GatewayError(ErrorCode.NOT_READY, "outcome requires reconciliation", retryable=False)
        if state != ActionState.CONFIRMED.value:
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, "action no longer executable")
        approval = self.s.db.query_one(
            "SELECT * FROM approvals WHERE action_id = ? AND user_id = ? AND tenant_id = ? AND used_at IS NULL "
            "AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1",
            (action_id, principal.user_id, principal.tenant_id),
        )
        now = self.s._now()
        if approval is None:
            raise GatewayError(ErrorCode.APPROVAL_REQUIRED, "no unused approval")
        if parse_iso(approval["expires_at"]) <= now:
            self._set_state(action_id, ActionState.EXPIRED)
            raise GatewayError(ErrorCode.APPROVAL_REQUIRED, "approval expired")
        self._revalidate(principal, row)
        if approval["digest"] != row["digest"]:
            raise GatewayError(ErrorCode.APPROVAL_REQUIRED, "approval does not match action")

        effect_id = self.s.ids.new("fx")
        with self.s.db.transaction() as conn:
            # Serialize final authorization with the dummy effect. Earlier
            # validation may have raced with quarantine, expiry or a stop.
            row = self.s._owned("actions", "action_id", action_id, principal)
            self.s._require_not_stopped()
            if row["state"] != ActionState.CONFIRMED.value:
                raise GatewayError(ErrorCode.CONTEXT_CHANGED, "action no longer executable")
            self._revalidate(principal, row)
            arguments = self._arguments(row)
            now = self.s._now()
            claimed = conn.execute(
                "UPDATE approvals SET used_at = ? WHERE approval_id = ? AND used_at IS NULL AND revoked_at IS NULL "
                "AND expires_at > ? AND digest = ?",
                (iso(now), approval["approval_id"], iso(now), row["digest"]),
            ).rowcount
            if claimed != 1:
                raise GatewayError(ErrorCode.APPROVAL_REQUIRED, "approval already used")
            outcome, effect = self.executor.execute(
                conn,
                {
                    "action_id": action_id,
                    "tenant_id": row["tenant_id"],
                    "owner_id": row["owner_id"],
                    "effect_id": effect_id,
                    "arguments": arguments,
                    "attachments": json.loads(row["attachments_json"]),
                    "digest": row["digest"],
                    "now": iso(now),
                },
            )
            new_state = {
                ExecutionOutcome.SUCCEEDED.value: ActionState.EXECUTED,
                ExecutionOutcome.NOT_DELIVERED.value: ActionState.REJECTED,
                ExecutionOutcome.UNKNOWN.value: ActionState.UNKNOWN_OUTCOME,
            }[outcome]
            outcome_record = {"outcome": outcome, "effect_id": effect, "simulated": True, "at": iso(now)}
            conn.execute(
                "UPDATE actions SET state = ?, outcome_json = ?, updated_at = ? WHERE action_id = ? AND state = ?",
                (new_state.value, json.dumps(outcome_record), iso(now), action_id, ActionState.CONFIRMED.value),
            )
            updated = conn.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,)).fetchone()
            response = self._view(updated)
            conn.execute(
                "INSERT INTO idempotency VALUES (?, ?, ?, ?, ?)",
                (scope, idempotency_key, request_digest, json.dumps({"action_id": action_id}), iso(now)),
            )
        return response

    def reconcile_unknown_outcome(self, action_id: str, provider_status: str) -> dict:
        """Operator/provider reconciliation for an ambiguous outcome. Never resends."""
        if provider_status not in ("DELIVERED", "NOT_DELIVERED"):
            raise GatewayError(ErrorCode.INVALID_REQUEST, "unknown provider status")
        target = ActionState.EXECUTED if provider_status == "DELIVERED" else ActionState.REJECTED
        with self.s.db.transaction() as conn:
            changed = conn.execute(
                "UPDATE actions SET state = ?, updated_at = ? WHERE action_id = ? AND state = ?",
                (target.value, self.s._now_iso(), action_id, ActionState.UNKNOWN_OUTCOME.value),
            ).rowcount
            if changed != 1:
                raise GatewayError(ErrorCode.CONTEXT_CHANGED, "action is not awaiting reconciliation")
            row = conn.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,)).fetchone()
        return self._view(row)

    def invalidate_session_actions(self, conn, task_session_id: str, state: ActionState) -> None:
        now_iso = self.s._now_iso()
        ids = [
            r["action_id"]
            for r in conn.execute(
                "SELECT action_id FROM actions WHERE task_session_id = ? AND state IN (?, ?)",
                (task_session_id, *PENDING_STATES),
            ).fetchall()
        ]
        for action_id in ids:
            conn.execute("UPDATE actions SET state = ?, updated_at = ? WHERE action_id = ?", (state.value, now_iso, action_id))
            conn.execute(
                "UPDATE approvals SET revoked_at = ? WHERE action_id = ? AND used_at IS NULL AND revoked_at IS NULL",
                (now_iso, action_id),
            )

    def expire(self, conn, now_iso: str) -> None:
        conn.execute(
            "UPDATE approvals SET revoked_at = ? WHERE expires_at <= ? AND used_at IS NULL AND revoked_at IS NULL",
            (now_iso, now_iso),
        )
        conn.execute(
            "UPDATE actions SET state = ?, updated_at = ? WHERE state = ? AND expires_at <= ?",
            (ActionState.EXPIRED.value, now_iso, ActionState.PROPOSED.value, now_iso),
        )
        conn.execute(
            "UPDATE actions SET state = ?, updated_at = ? WHERE state = ? AND NOT EXISTS ("
            "SELECT 1 FROM approvals a WHERE a.action_id = actions.action_id AND a.used_at IS NULL AND a.revoked_at IS NULL)",
            (ActionState.EXPIRED.value, now_iso, ActionState.CONFIRMED.value),
        )

    def _purge_content(self, conn, row) -> None:
        ref = json.loads(row["arguments_json"]).get("storage_ref")
        if ref:
            self.s.store.delete(ref, row["tenant_id"])
            conn.execute("UPDATE actions SET arguments_json = ? WHERE action_id = ?",
                         (json.dumps({"storage_ref": None}), row["action_id"]))

    def purge_resource_actions(self, conn, tenant_id: str, label_id: str) -> None:
        """Deleting a source also deletes its private derived action content."""
        for row in conn.execute("SELECT * FROM actions WHERE tenant_id = ?", (tenant_id,)).fetchall():
            if label_id in json.loads(row["label_ids_json"]):
                self._purge_content(conn, row)
                self._set_state(row["action_id"], ActionState.CANCELED)

    def purge_retained_content(self, conn, evidence_cutoff: str, metadata_cutoff: str) -> None:
        """Expire private action bytes with evidence, and action metadata after seven days."""
        for row in conn.execute("SELECT * FROM actions WHERE created_at <= ?", (evidence_cutoff,)).fetchall():
            self._purge_content(conn, row)
        old_ids = [r["action_id"] for r in conn.execute("SELECT action_id FROM actions WHERE created_at <= ?", (metadata_cutoff,))]
        for action_id in old_ids:
            conn.execute("DELETE FROM approvals WHERE action_id = ?", (action_id,))
            conn.execute("DELETE FROM dummy_mailbox WHERE action_id = ?", (action_id,))
            conn.execute("DELETE FROM actions WHERE action_id = ?", (action_id,))
