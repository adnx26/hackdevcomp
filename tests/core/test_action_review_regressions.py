"""Action authority regression proofs from the final A design review."""

import unittest

from protection_gateway.contracts.errors import GatewayError

from .support import COLLECTOR, Harness


class ActionReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.ui = self.h.ui()
        self.api = self.h.api()

    def tearDown(self):
        self.h.close()

    def propose_body(self, session, *, attachments=(), principal=None):
        return self.h.service.propose_simulated_action(principal or self.api.as_assistant(), {
            "contract_version": "v1",
            "task_session_id": session["task_session_id"],
            "action": {"operation": "simulated_send_email", "arguments": {
                "to": "carol@example.com", "subject": "Report",
                "body": "Private source-derived text",
                "attachment_resource_ids": list(attachments),
            }},
        })

    def confirm(self, action):
        return self.h.service.confirm_simulated_action(self.ui, action["action_id"], {
            "contract_version": "v1", "digest": action["digest"],
        })

    def execute(self, action):
        return self.h.service.execute_simulated_action(self.api, action["action_id"], {
            "contract_version": "v1",
        }, "action-review-execute")

    def assert_no_effects(self):
        self.assertEqual(self.h.service.db.query_all("SELECT * FROM dummy_mailbox"), [])

    def test_uninspected_body_source_cannot_be_proposed_without_attachments(self):
        resource = self.h.upload(self.ui, "Uninspected private source")
        session = self.h.session(self.ui, [resource["resource_id"]], "simulate_send")
        with self.assertRaises(GatewayError):
            self.propose_body(session)
        self.assert_no_effects()

    def test_incomplete_body_source_cannot_be_proposed_without_attachments(self):
        resource = self.h.upload(self.ui, "Pending private source")
        session = self.h.session(self.ui, [resource["resource_id"]], "simulate_send")
        self.h.scan(self.ui, session["task_session_id"])
        with self.assertRaises(GatewayError):
            self.propose_body(session)
        self.assert_no_effects()

    def test_body_quarantine_before_confirmation_cannot_grant_approval(self):
        _, session, scan = self.h.allowed_scan(self.ui, policy="simulate_send")
        action = self.propose_body(session)
        self.h.service.record_collector_event(COLLECTOR, self.h.collector_event(scan["scan_id"], operation="fetch_url"))
        with self.assertRaises(GatewayError):
            self.confirm(action)
        self.assertEqual(self.h.service.db.query_all("SELECT * FROM approvals"), [])
        self.assert_no_effects()

    def test_body_quarantine_after_confirmation_prevents_execution(self):
        _, session, scan = self.h.allowed_scan(self.ui, policy="simulate_send")
        action = self.propose_body(session)
        self.confirm(action)
        self.h.service.record_collector_event(COLLECTOR, self.h.collector_event(scan["scan_id"], operation="fetch_url"))
        with self.assertRaises(GatewayError):
            self.execute(action)
        self.assert_no_effects()

    def test_committed_forbidden_event_prevents_execution_before_downgrade(self):
        resource, session, scan = self.h.allowed_scan(self.ui, policy="simulate_send")
        action = self.propose_body(session, attachments=[resource["resource_id"]], principal=self.ui)
        self.confirm(action)
        original = self.h.service._apply_forbidden_evidence
        attempted = []

        def execute_before_downgrade(scan_id):
            # Exercise the interval after collector persistence while the
            # cached decision can still say ALLOW_UNDER_POLICY.
            events = self.h.service.db.query_all(
                "SELECT * FROM collector_events WHERE scan_id = ? AND effective_policy_check = 'FORBIDDEN'",
                (scan_id,),
            )
            self.assertEqual(len(events), 1)
            with self.assertRaises(GatewayError):
                self.execute(action)
            attempted.append(True)
            self.assert_no_effects()
            original(scan_id)

        self.h.service._apply_forbidden_evidence = execute_before_downgrade
        self.h.service.record_collector_event(COLLECTOR, self.h.collector_event(scan["scan_id"], operation="fetch_url"))
        self.assertEqual(attempted, [True])
        self.assertEqual(self.h.service.get_scan_status(self.api, scan["scan_id"])["decision"], "QUARANTINE")
        self.assert_no_effects()


if __name__ == "__main__":
    unittest.main()
