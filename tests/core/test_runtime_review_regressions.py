"""Independent runtime-review regressions for PR A's design merge gate."""

import os
import unittest

from protection_gateway.contracts.canonical import sha256_hex
from protection_gateway.contracts.enums import ErrorCode
from protection_gateway.contracts.errors import GatewayError
from tests.core.support import Harness, IDENTITIES, INVOICE_TEXT


class RuntimeReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.p = self.h.api()

    def tearDown(self):
        self.h.close()

    def stored_files(self):
        return {
            os.path.relpath(os.path.join(root, name), self.h.config.evidence_root)
            for root, _, names in os.walk(self.h.config.evidence_root)
            for name in names
        }

    def test_lease_expiring_during_storage_rejects_result_without_orphans(self):
        resource = self.h.upload(self.p)
        session = self.h.session(self.p, [resource["resource_id"]])
        scan_id = self.h.scan(self.p, session["task_session_id"])["scan_id"]
        self.h.submit(self.h.worker_result(scan_id, "INSTRUCTION_INSPECTOR"))
        self.h.submit(self.h.worker_result(scan_id, "DATA_TOOL_INSPECTOR"))
        result = self.h.worker_result(
            scan_id, "BEHAVIOR_TESTER", task_output=self.h.invoice_output(scan_id),
            artifacts=[{"artifact_id": "delayed-artifact", "kind": "EXPLANATION", "text": "private explanation"}],
        )
        before = self.stored_files()
        original_put = self.h.service.store.put

        def delayed_put(tenant_id, kind, data):
            if kind == "artifact":
                self.h.clock.advance(self.h.config.limits.worker_lease_seconds + 1)
            return original_put(tenant_id, kind, data)

        self.h.service.store.put = delayed_put
        with self.assertRaises(GatewayError) as rejected:
            self.h.submit(result)
        self.assertEqual(rejected.exception.code, ErrorCode.CONTEXT_CHANGED)
        self.assertIsNone(self.h.service.db.query_one(
            "SELECT * FROM worker_results WHERE assignment_id = ?", (result["assignment_id"],)
        ))
        self.assertEqual(self.stored_files(), before, "Rejected writes must leave no private orphan objects")
        with self.assertRaises(GatewayError):
            self.h.service.get_inspected_result(self.p, scan_id)

    def test_unregistered_extractor_version_cannot_satisfy_extraction(self):
        resource = self.h.upload(self.p)
        self.h.runtime.extract_overrides[resource["resource_id"]] = {
            "extractor_version": "unregistered-extractor-9"
        }
        before = self.stored_files()
        session = self.h.session(self.p, [resource["resource_id"]])
        status = self.h.scan(self.p, session["task_session_id"])
        self.assertEqual(status["decision"], "REVIEW")
        self.assertNotIn("EXTRACTION", status["completed_checks"])
        self.assertEqual(self.h.runtime.assignments, {}, "Unknown extractor builds must never dispatch inspectors")
        self.assertEqual(self.stored_files(), before)
        with self.assertRaises(GatewayError):
            self.h.service.get_inspected_result(self.p, status["scan_id"])

    def test_extraction_expiring_during_storage_fails_and_removes_staging(self):
        resource = self.h.upload(self.p)
        session = self.h.session(self.p, [resource["resource_id"]])
        before = self.stored_files()
        original_put = self.h.service.store.put

        def delayed_put(tenant_id, kind, data):
            if kind == "view":
                self.h.clock.advance(self.h.config.limits.scan_deadline_seconds)
            return original_put(tenant_id, kind, data)

        self.h.service.store.put = delayed_put
        status = self.h.scan(self.p, session["task_session_id"])
        self.assertEqual(status["state"], "FAILED")
        self.assertIn("TIMEOUT", status["reason_codes"])
        self.assertIsNone(status["decision"])
        self.assertEqual(self.h.runtime.assignments, {})
        self.assertEqual(self.stored_files(), before)
        self.assertEqual(self.h.service.db.query_all("SELECT * FROM extractions"), [])
        self.assertEqual(self.h.service.db.query_all(
            "SELECT * FROM job_tokens WHERE revoked_at IS NULL"
        ), [])
        with self.assertRaises(GatewayError):
            self.h.service.get_inspected_result(self.p, status["scan_id"])

    def test_periodic_recovery_terminates_extractor_waiting_past_deadline(self):
        resource = self.h.upload(self.p)
        session = self.h.session(self.p, [resource["resource_id"]])
        before = self.stored_files()
        original_extract = self.h.runtime.extract
        while_waiting = {}

        def waiting_extract(assignment):
            result = original_extract(assignment)
            # The callback has not returned; periodic recovery must still
            # terminate the live extraction and revoke its resource token.
            self.h.clock.advance(self.h.config.limits.scan_deadline_seconds)
            self.h.service.recover()
            row = self.h.service.db.query_one(
                "SELECT state FROM scans WHERE scan_id = ?", (assignment["scan_id"],)
            )
            while_waiting["state"] = row["state"]
            while_waiting["live_tokens"] = self.h.service.db.query_all(
                "SELECT * FROM job_tokens WHERE revoked_at IS NULL"
            )
            while_waiting["runtime_canceled"] = assignment["scan_id"] in self.h.runtime.canceled
            return result

        self.h.runtime.extract = waiting_extract
        status = self.h.scan(self.p, session["task_session_id"])
        self.assertEqual(while_waiting["state"], "FAILED")
        self.assertEqual(while_waiting["live_tokens"], [])
        self.assertTrue(while_waiting["runtime_canceled"])
        self.assertEqual(status["state"], "FAILED")
        self.assertIn("TIMEOUT", status["reason_codes"])
        self.assertEqual(self.h.runtime.assignments, {})
        self.assertEqual(self.stored_files(), before)
        self.assertEqual(self.h.service.db.query_all("SELECT * FROM extractions"), [])

    def test_invalid_later_extraction_view_leaves_no_orphaned_content(self):
        resource = self.h.upload(self.p)
        self.h.runtime.extract_overrides[resource["resource_id"]] = {
            "views": [
                {"view_id": "visible", "kind": "plain_text", "text": INVOICE_TEXT,
                 "view_hash": sha256_hex(INVOICE_TEXT),
                 "source_map": [[0, len(INVOICE_TEXT), 0, len(INVOICE_TEXT.encode("utf-8"))]]},
                {"view_id": "invalid", "kind": "plain_text", "text": "x",
                 "view_hash": sha256_hex("x"), "source_map": []},
            ]
        }
        before = self.stored_files()
        session = self.h.session(self.p, [resource["resource_id"]])
        status = self.h.scan(self.p, session["task_session_id"])
        self.assertEqual(status["decision"], "REVIEW")
        self.assertEqual(self.h.runtime.assignments, {})
        self.assertEqual(self.stored_files(), before, "Invalid extraction must not orphan earlier valid views")
        self.h.clock.advance(8 * 24 * 3600 + 1)
        self.h.service.run_retention()
        self.assertEqual(self.stored_files(), set())

    def test_metadata_expires_seven_days_after_creation(self):
        resource = self.h.upload(self.p)
        session = self.h.session(self.p, [resource["resource_id"]])
        self.h.scan(self.p, session["task_session_id"])
        self.h.clock.advance(self.h.config.retention.evidence_seconds + 1)
        self.h.service.run_retention()
        self.h.clock.advance(
            self.h.config.retention.metadata_seconds - self.h.config.retention.evidence_seconds
        )
        self.h.service.run_retention()
        for table in ("resources", "task_sessions", "labels", "scans"):
            with self.subTest(table=table):
                self.assertEqual(self.h.service.db.query_all("SELECT * FROM " + table), [],
                                 "Metadata expiry must use creation time, not deletion or session expiry")

    def test_expired_source_blocks_new_task_and_scan_without_cleanup(self):
        resource = self.h.upload(self.p)
        self.h.clock.advance(self.h.config.retention.evidence_seconds - 1)
        session = self.h.session(self.p, [resource["resource_id"]])
        self.h.clock.advance(1)
        with self.assertRaises(GatewayError):
            self.h.session(self.p, [resource["resource_id"]])
        with self.assertRaises(GatewayError):
            self.h.scan(self.p, session["task_session_id"])
        self.assertEqual(self.h.runtime.assignments, {})

    def test_expired_source_blocks_still_live_inspection_capability(self):
        resource = self.h.upload(self.p)
        self.h.clock.advance(self.h.config.retention.evidence_seconds - 1)
        session = self.h.session(self.p, [resource["resource_id"]])
        scan_id = self.h.scan(self.p, session["task_session_id"])["scan_id"]
        assignment = self.h.runtime.latest(scan_id, "INSTRUCTION_INSPECTOR")
        capability = self.h.runtime.capabilities[assignment["assignment_id"]]
        view_id = assignment["resources"][0]["views"][0]["view_id"]
        self.h.clock.advance(1)
        with self.assertRaises(GatewayError):
            self.h.service.read_assigned_view(
                capability, assignment["worker"], resource["resource_id"], view_id
            )
        with self.assertRaises(GatewayError):
            self.h.service.validate_job_token(capability, assignment["worker"])

    def test_expired_source_blocks_still_live_extractor_capability(self):
        resource = self.h.upload(self.p)
        self.h.clock.advance(self.h.config.retention.evidence_seconds - 1)
        session = self.h.session(self.p, [resource["resource_id"]])
        attempted = []

        def delayed_original_read(assignment):
            capability = self.h.service.issue_job_capability(assignment["assignment_id"])
            self.h.clock.advance(1)
            attempted.append(True)
            with self.assertRaises(GatewayError):
                self.h.service.read_assigned_original(
                    capability, IDENTITIES["EXTRACTOR"], resource["resource_id"]
                )
            # A runtime failure following the denied read cannot dispatch.
            raise ConnectionError("source unavailable to extractor")

        self.h.runtime.extract = delayed_original_read
        status = self.h.scan(self.p, session["task_session_id"])
        self.assertEqual(attempted, [True])
        self.assertEqual(status["state"], "FAILED")
        self.assertEqual(self.h.runtime.assignments, {})

    def test_source_expiry_bounds_evidence_result_and_action_preview(self):
        resource = self.h.upload(self.p)
        self.h.clock.advance(self.h.config.retention.evidence_seconds - 1)
        session = self.h.session(self.p, [resource["resource_id"]], "simulate_send")
        scan_id = self.h.scan(self.p, session["task_session_id"])["scan_id"]
        self.h.submit(self.h.worker_result(
            scan_id, "INSTRUCTION_INSPECTOR",
            artifacts=[{"artifact_id": "private-log", "kind": "EXPLANATION", "text": "private explanation"}],
        ))
        self.h.submit(self.h.worker_result(scan_id, "DATA_TOOL_INSPECTOR"))
        self.h.submit(self.h.worker_result(
            scan_id, "BEHAVIOR_TESTER", task_output=self.h.summary_output(scan_id)
        ))
        action = self.h.service.propose_simulated_action(self.p, {
            "contract_version": "v1", "task_session_id": session["task_session_id"],
            "action": {"operation": "simulated_send_email", "arguments": {
                "to": "carol@example.com", "subject": "Report", "body": "Derived private text",
                "attachment_resource_ids": [resource["resource_id"]],
            }},
        })
        evidence = self.h.service.db.query_one("SELECT * FROM evidence WHERE source = 'WORKER_ARTIFACT'")
        decision = self.h.service.db.query_one("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        source = self.h.service.db.query_one("SELECT * FROM resources WHERE resource_id = ?", (resource["resource_id"],))
        self.assertEqual(evidence["expires_at"], source["evidence_expires_at"])
        self.assertEqual(decision["decision_expires_at"], source["evidence_expires_at"])
        self.h.clock.advance(1)
        for lookup in (
            lambda: self.h.service.get_evidence(self.p, evidence["evidence_id"]),
            lambda: self.h.service.get_inspected_result(self.p, scan_id),
            lambda: self.h.service.get_action(self.p, action["action_id"]),
        ):
            with self.assertRaises(GatewayError):
                lookup()

    def test_unlabeled_user_action_arguments_expire_after_own_24_hours(self):
        ui = self.h.ui()
        resource = self.h.upload(ui)
        session = self.h.session(ui, [resource["resource_id"]], "simulate_send")
        action = self.h.service.propose_simulated_action(ui, {
            "contract_version": "v1", "task_session_id": session["task_session_id"],
            "action": {"operation": "simulated_send_email", "arguments": {
                "to": "carol@example.com", "subject": "User report", "body": "User authored private text",
                "attachment_resource_ids": [],
            }},
        })
        self.assertEqual(action["label_ids"], [], "This checks action age independently of source labels")
        self.h.clock.advance(self.h.config.retention.evidence_seconds)
        with self.assertRaises(GatewayError):
            self.h.service.get_action(ui, action["action_id"])


if __name__ == "__main__":
    unittest.main()
