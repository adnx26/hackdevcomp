"""A real user must confirm the exact simulated action; edits, expiry,
cancellation and replay fail; execution records one effect."""

import unittest

from protection_gateway.contracts.enums import ErrorCode
from protection_gateway.contracts.errors import GatewayError

from .support import V, Harness


class UnknownOutcomeExecutor:
    """Stands in for a future provider that returns an ambiguous response."""

    def execute(self, conn, action):
        return "UNKNOWN", None


class ActionGateTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.setup_session(self.h)

    def setup_session(self, h):
        self.api = h.api()
        self.ui = h.ui()
        self.res = h.upload(self.ui, "Quarterly report text")
        self.ts = h.session(self.ui, [self.res["resource_id"]], "simulate_send")
        self.scan_id = h.scan(self.ui, self.ts["task_session_id"])["scan_id"]
        h.complete_clean(self.scan_id, h.summary_output(self.scan_id))

    def tearDown(self):
        self.h.close()

    def propose(self, principal=None, to="carol@example.com", body="Hello Carol", attachments=None, h=None):
        h = h or self.h
        return h.service.propose_simulated_action(
            principal or self.ui,
            {
                "contract_version": V,
                "task_session_id": self.ts["task_session_id"],
                "action": {
                    "operation": "simulated_send_email",
                    "arguments": {
                        "to": to,
                        "subject": "Report",
                        "body": body,
                        "attachment_resource_ids": attachments if attachments is not None else [self.res["resource_id"]],
                    },
                },
            },
        )

    def confirm(self, action, principal=None, digest=None, **extra):
        return self.h.service.confirm_simulated_action(
            principal or self.ui, action["action_id"], {"contract_version": V, "digest": digest or action["digest"], **extra}
        )

    def execute(self, action, key="exec-1", principal=None):
        return self.h.service.execute_simulated_action(principal or self.api, action["action_id"], {"contract_version": V}, key)

    def code(self, fn, *args, **kwargs):
        with self.assertRaises(GatewayError) as ctx:
            fn(*args, **kwargs)
        return ctx.exception.code

    def effects(self):
        return self.h.service.db.query_all("SELECT * FROM dummy_mailbox")

    def test_happy_path_records_one_effect(self):
        action = self.propose()
        self.assertEqual(action["state"], "PROPOSED")
        self.assertEqual(action["preview"]["to"], "carol@example.com")
        self.assertEqual(action["recipient_trust"], "TRUSTED_CONTACT")
        self.assertEqual(self.effects(), [])
        self.assertEqual(self.confirm(action)["state"], "CONFIRMED")
        executed = self.execute(action)
        self.assertEqual(executed["state"], "EXECUTED")
        self.assertTrue(executed["outcome"]["simulated"])
        self.assertEqual(len(self.effects()), 1)
        # Same idempotency key replays the stored response without a new effect.
        self.assertEqual(self.execute(action), executed)
        # A new key cannot reuse the consumed approval.
        self.assertEqual(self.code(self.execute, action, "exec-2"), ErrorCode.APPROVAL_REQUIRED)
        self.assertEqual(len(self.effects()), 1)

    def test_concurrent_execute_consumes_approval_once(self):
        action = self.propose()
        self.confirm(action)
        gate = self.h.service.actions
        original = gate._revalidate

        def racing_revalidate(principal, row):
            original(principal, row)
            # Another request claims the approval between the checks and the write.
            with self.h.service.db.transaction() as conn:
                conn.execute("UPDATE approvals SET used_at = 'raced' WHERE action_id = ?", (row["action_id"],))

        gate._revalidate = racing_revalidate
        self.assertEqual(self.code(self.execute, action), ErrorCode.APPROVAL_REQUIRED)
        self.assertEqual(self.effects(), [])

    def test_only_user_interface_can_confirm(self):
        action = self.propose()
        for principal in (self.api, self.api.as_assistant()):
            self.assertEqual(self.code(self.confirm, action, principal), ErrorCode.FORBIDDEN)
        self.assertEqual(self.code(self.execute, action), ErrorCode.APPROVAL_REQUIRED)

    def test_mcp_cannot_propose(self):
        from protection_gateway.contracts.enums import Channel

        mcp = self.h.auth.authenticate_bearer("token-alice-0123456789", Channel.MCP)
        self.assertEqual(self.code(self.propose, mcp), ErrorCode.FORBIDDEN)

    def test_changed_argument_invalidates_confirmation(self):
        action = self.propose()
        edited = self.propose(to="dave@example.com", attachments=[], body="hi")
        self.assertNotEqual(action["digest"], edited["digest"])
        # Confirming one action with another's digest fails.
        self.assertEqual(self.code(self.confirm, action, digest=edited["digest"]), ErrorCode.CONTEXT_CHANGED)

    def test_untrusted_recipient_requires_explicit_user_selection(self):
        action = self.propose(to="dave@example.com", attachments=[])
        self.assertTrue(action["requires_recipient_selection"])
        self.assertEqual(self.code(self.confirm, action), ErrorCode.APPROVAL_REQUIRED)
        self.assertEqual(self.confirm(action, recipient_selected_by_user=True)["state"], "CONFIRMED")

    def test_private_data_cannot_go_to_untrusted_recipient(self):
        # Attachment carries a private label.
        self.assertEqual(self.code(self.propose, to="attacker@example.net"), ErrorCode.FORBIDDEN)
        # Assistant-written body inherits session labels.
        self.assertEqual(self.code(self.propose, self.api.as_assistant(), to="attacker@example.net", attachments=[]), ErrorCode.FORBIDDEN)

    def test_policy_must_permit_sending(self):
        res = self.h.upload(self.ui, "x")
        ts = self.h.session(self.ui, [res["resource_id"]], "summarize_email")
        body = {"contract_version": V, "task_session_id": ts["task_session_id"],
                "action": {"operation": "simulated_send_email", "arguments": {"to": "carol@example.com", "subject": "", "body": "", "attachment_resource_ids": []}}}
        self.assertEqual(self.code(self.h.service.propose_simulated_action, self.ui, body), ErrorCode.FORBIDDEN)
        self.assertEqual(self.code(self.h.service.propose_simulated_action, self.ui, dict(body, action={**body["action"], "operation": "real_send"})), ErrorCode.INVALID_REQUEST)

    def test_assistant_cannot_create_write_capable_session(self):
        self.assertEqual(self.code(self.h.session, self.api.as_assistant(), [self.res["resource_id"]], "simulate_send"), ErrorCode.FORBIDDEN)

    def test_attachment_requires_active_allowed_inspection(self):
        other = self.h.upload(self.ui, "unscanned")
        self.assertEqual(self.code(self.propose, attachments=[other["resource_id"]]), ErrorCode.NOT_FOUND)

    def test_expiry(self):
        action = self.propose()
        self.h.clock.advance(601)
        self.assertEqual(self.code(self.confirm, action), ErrorCode.CONTEXT_CHANGED)
        action = self.propose(attachments=[])
        self.confirm(action)
        self.h.clock.advance(301)
        self.assertEqual(self.code(self.execute, action), ErrorCode.APPROVAL_REQUIRED)
        self.assertEqual(self.effects(), [])

    def test_context_change_invalidates_pending_approval(self):
        action = self.propose()
        self.confirm(action)
        self.h.service.advance_task_context(self.ui, self.ts["task_session_id"])
        self.assertEqual(self.h.service.get_action(self.ui, action["action_id"])["state"], "CANCELED")
        self.assertEqual(self.code(self.execute, action), ErrorCode.CONTEXT_CHANGED)
        self.assertEqual(self.effects(), [])

    def test_cancel_session_revokes_actions(self):
        action = self.propose()
        self.confirm(action)
        self.h.service.cancel_task_session(self.ui, self.ts["task_session_id"])
        self.assertEqual(self.code(self.execute, action), ErrorCode.CONTEXT_CHANGED)

    def test_quarantine_after_confirmation_blocks_execution(self):
        from .support import COLLECTOR

        action = self.propose()
        self.confirm(action)
        self.h.service.record_collector_event(COLLECTOR, self.h.collector_event(self.scan_id, operation="fetch_url"))
        self.assertEqual(self.code(self.execute, action), ErrorCode.CONTEXT_CHANGED)
        self.assertEqual(self.effects(), [])

    def test_other_user_cannot_touch_action(self):
        action = self.propose()
        bob = self.h.ui("bob")
        self.assertEqual(self.code(self.confirm, action, bob), ErrorCode.NOT_FOUND)
        self.assertEqual(self.code(self.execute, action, "k", self.h.api("mallory")), ErrorCode.NOT_FOUND)

    def test_unknown_outcome_requires_reconciliation(self):
        h = Harness(executor=UnknownOutcomeExecutor())
        try:
            self.h.close()
            self.h = h
            self.setup_session(h)
            action = self.propose()
            self.confirm(action)
            self.assertEqual(self.execute(action)["state"], "UNKNOWN_OUTCOME")
            self.assertEqual(self.code(self.execute, action, "exec-2"), ErrorCode.NOT_READY)
            reconciled = h.service.actions.reconcile_unknown_outcome(action["action_id"], "DELIVERED")
            self.assertEqual(reconciled["state"], "EXECUTED")
            with self.assertRaises(GatewayError):
                h.service.actions.reconcile_unknown_outcome(action["action_id"], "DELIVERED")
        finally:
            pass


if __name__ == "__main__":
    unittest.main()
