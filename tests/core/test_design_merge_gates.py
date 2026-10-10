"""Regression proofs for design requirements missed by the initial PR A tests."""
import json
import os
import unittest

from protection_gateway.contracts.errors import GatewayError
from protection_gateway.contracts.canonical import sha256_hex
from tests.core.support import Harness


class DesignMergeGates(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.p = self.h.api()

    def tearDown(self):
        self.h.close()

    def send_action(self):
        ui = self.h.ui()
        res, ts, scan = self.h.allowed_scan(ui, policy="simulate_send")
        action = self.h.service.propose_simulated_action(ui, {
            "contract_version": "v1", "task_session_id": ts["task_session_id"],
            "action": {"operation": "simulated_send_email", "arguments": {
                "to": "carol@example.com", "subject": "Report",
                "body": "PRIVATE-DERIVED-CONTENT", "attachment_resource_ids": [res["resource_id"]]
            }}
        })
        self.h.service.confirm_simulated_action(ui, action["action_id"], {
            "contract_version": "v1", "digest": action["digest"]
        })
        return ui, ts, action

    def test_emergency_stop_withholds_previously_allowed_result(self):
        _, _, scan = self.h.allowed_scan()
        self.h.service.emergency_stop()
        with self.assertRaises(GatewayError):
            self.h.service.get_inspected_result(self.p, scan["scan_id"])

    def test_expired_lease_cannot_read_assigned_view_before_recovery(self):
        res = self.h.upload(self.p, "Hello there")
        ts = self.h.session(self.p, [res["resource_id"]], "summarize_email")
        scan = self.h.scan(self.p, ts["task_session_id"])
        a = self.h.runtime.latest(scan["scan_id"], "INSTRUCTION_INSPECTOR")
        cap = self.h.runtime.capabilities[a["assignment_id"]]
        view = a["resources"][0]["views"][0]
        self.h.clock.advance(self.h.config.limits.worker_lease_seconds + 1)
        with self.assertRaises(GatewayError):
            self.h.service.read_assigned_view(cap, a["worker"], res["resource_id"], view["view_id"])

    def test_cancellation_between_validation_and_execution_prevents_effect(self):
        ui, ts, action = self.send_action()
        gate = self.h.service.actions
        original = gate._revalidate

        def cancel_after_validation(principal, row):
            original(principal, row)
            self.h.service.cancel_task_session(ui, ts["task_session_id"])

        gate._revalidate = cancel_after_validation
        try:
            self.h.service.execute_simulated_action(self.p, action["action_id"], {"contract_version": "v1"}, "race-cancel")
        except GatewayError:
            pass
        self.assertEqual(len(self.h.service.db.query_all("SELECT * FROM dummy_mailbox")), 0,
                         "Cancellation must leave zero effects")

    def test_context_change_between_validation_and_execution_prevents_effect(self):
        ui, ts, action = self.send_action()
        gate = self.h.service.actions
        original = gate._revalidate

        def change_after_validation(principal, row):
            original(principal, row)
            self.h.service.advance_task_context(ui, ts["task_session_id"])

        gate._revalidate = change_after_validation
        try:
            self.h.service.execute_simulated_action(self.p, action["action_id"], {"contract_version": "v1"}, "race-context")
        except GatewayError:
            pass
        self.assertEqual(len(self.h.service.db.query_all("SELECT * FROM dummy_mailbox")), 0,
                         "Changed context must leave zero effects")

    def test_metadata_retention_expires_action_content(self):
        _, _, action = self.send_action()
        self.h.clock.advance(self.h.config.retention.metadata_seconds + 1)
        self.h.service.run_retention()
        rows = self.h.service.db.query_all("SELECT arguments_json FROM actions")
        self.assertNotIn("PRIVATE-DERIVED-CONTENT", json.dumps([dict(r) for r in rows]),
                         "Private action content must not remain indefinitely after retention")

    def test_action_text_and_idempotency_response_stay_out_of_metadata(self):
        _, _, action = self.send_action()
        self.h.service.execute_simulated_action(self.p, action["action_id"], {"contract_version": "v1"}, "private-action")
        for table in ("actions", "idempotency", "dummy_mailbox"):
            rows = self.h.service.db.query_all("SELECT * FROM " + table)
            self.assertNotIn("PRIVATE-DERIVED-CONTENT", json.dumps([dict(r) for r in rows]))
        for name in os.listdir(self.h.tmp):
            if name.startswith("gateway.sqlite3"):
                with open(os.path.join(self.h.tmp, name), "rb") as handle:
                    self.assertNotIn(b"PRIVATE-DERIVED-CONTENT", handle.read())

    def test_action_bytes_expire_with_evidence_and_metadata_later(self):
        _, _, action = self.send_action()
        row = self.h.service.db.query_one("SELECT * FROM actions WHERE action_id = ?", (action["action_id"],))
        ref = json.loads(row["arguments_json"])["storage_ref"]
        self.h.clock.advance(self.h.config.retention.evidence_seconds + 1)
        self.h.service.run_retention()
        with self.assertRaises(GatewayError):
            self.h.service.store.get(ref, row["tenant_id"])
        with self.assertRaises(GatewayError):
            self.h.service.get_action(self.p, action["action_id"])
        self.assertIsNotNone(self.h.service.db.query_one("SELECT * FROM actions WHERE action_id = ?", (action["action_id"],)))
        self.h.clock.advance(self.h.config.retention.metadata_seconds)
        self.h.service.run_retention()
        for table in ("actions", "approvals", "dummy_mailbox"):
            self.assertEqual(self.h.service.db.query_all("SELECT * FROM " + table), [])

    def test_worker_capability_rejects_changed_build_or_prompt(self):
        res = self.h.upload(self.p, "Hello there")
        ts = self.h.session(self.p, [res["resource_id"]], "summarize_email")
        scan = self.h.scan(self.p, ts["task_session_id"])
        a = self.h.runtime.latest(scan["scan_id"], "INSTRUCTION_INSPECTOR")
        cap = self.h.runtime.capabilities[a["assignment_id"]]
        for field in ("build_version", "prompt_version"):
            with self.assertRaises(GatewayError):
                self.h.service.validate_job_token(cap, dict(a["worker"], **{field: "different-version"}))

    def test_changed_stored_view_is_not_released_to_worker(self):
        res = self.h.upload(self.p, "Hello there")
        ts = self.h.session(self.p, [res["resource_id"]], "summarize_email")
        scan = self.h.scan(self.p, ts["task_session_id"])
        a = self.h.runtime.latest(scan["scan_id"], "INSTRUCTION_INSPECTOR")
        cap = self.h.runtime.capabilities[a["assignment_id"]]
        ext = self.h.service.db.query_one("SELECT views_json FROM extractions WHERE scan_id = ?", (scan["scan_id"],))
        stored = json.loads(ext["views_json"])[0]
        with open(os.path.join(self.h.config.evidence_root, stored["storage_ref"]), "wb") as handle:
            handle.write(b"Altered bytes")
        with self.assertRaises(GatewayError):
            self.h.service.read_assigned_view(cap, a["worker"], res["resource_id"], stored["view_id"])

    def test_numeric_subspan_cannot_invent_smaller_invoice_amount(self):
        res = self.h.upload(self.p)
        ts = self.h.session(self.p, [res["resource_id"]])
        sid = self.h.scan(self.p, ts["task_session_id"])["scan_id"]
        output = self.h.invoice_output(sid)
        output["fields"]["amount"]["value"] = "250.00"
        output["fields"]["amount"]["source_refs"][0]["start"] += 3
        self.h.complete_clean(sid, output)
        status = self.h.service.get_scan_status(self.p, sid)
        self.assertEqual(status["decision"], "REVIEW")
        self.assertIn("ANSWER_MISMATCH", status["reason_codes"])
        with self.assertRaises(GatewayError):
            self.h.service.get_inspected_result(self.p, sid)

    def test_incomplete_source_map_cannot_satisfy_extraction(self):
        for source_map in ([], [[0, 5, 0, 5]], [[1, 11, 1, 11]]):
            res = self.h.upload(self.p, "Hello there")
            ts = self.h.session(self.p, [res["resource_id"]], "summarize_email")
            self.h.runtime.extract_overrides[res["resource_id"]] = {
                "views": [{"view_id": "visible", "kind": "plain_text", "text": "Hello there",
                           "view_hash": sha256_hex("Hello there"), "source_map": source_map}]
            }
            sid = self.h.scan(self.p, ts["task_session_id"], "map-" + res["resource_id"])["scan_id"]
            status = self.h.service.get_scan_status(self.p, sid)
            self.assertEqual(status["decision"], "REVIEW")
            self.assertIn("EXTRACTION_ERROR", status["reason_codes"])
            self.assertNotIn("EXTRACTION", status["completed_checks"])

    def test_resource_deletion_removes_derived_action_content(self):
        ui, ts, action = self.send_action()
        row = self.h.service.db.query_one("SELECT * FROM actions WHERE action_id = ?", (action["action_id"],))
        ref = json.loads(row["arguments_json"])["storage_ref"]
        self.h.service.delete_resource(ui, ts["resource_ids"][0])
        with self.assertRaises(GatewayError):
            self.h.service.store.get(ref, row["tenant_id"])
        with self.assertRaises(GatewayError):
            self.h.service.get_action(ui, action["action_id"])
        with self.assertRaises(GatewayError):
            self.h.service.execute_simulated_action(self.p, action["action_id"], {"contract_version": "v1"}, "deleted-source")
        self.assertEqual(self.h.service.db.query_all("SELECT * FROM dummy_mailbox"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
