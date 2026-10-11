"""Checks added during the final spec audit (teammate A doc + master §10, §11, §15)."""

import json
import unittest

from protection_gateway.contracts.enums import ErrorCode
from protection_gateway.contracts.errors import GatewayError

from .support import COLLECTOR, IDENTITIES, V, Harness


class SpecAlignmentTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.p = self.h.api()

    def tearDown(self):
        self.h.close()

    def started(self, policy="summarize_email", key="k1"):
        res = self.h.upload(self.p, "Hello there")
        ts = self.h.session(self.p, [res["resource_id"]], policy)
        return res, ts, self.h.scan(self.p, ts["task_session_id"], key)["scan_id"]

    # §15: runtime.extract(assignment) / runtime.dispatch(assignments); B provisions capabilities
    def test_capabilities_are_provisioned_by_b_not_broadcast(self):
        _, _, scan_id = self.started()
        a = self.h.runtime.latest(scan_id, "INSTRUCTION_INSPECTOR")
        self.assertNotIn(self.h.runtime.capabilities[a["assignment_id"]], json.dumps(a))
        old = self.h.runtime.capabilities[a["assignment_id"]]
        new = self.h.service.issue_job_capability(a["assignment_id"])
        identity = IDENTITIES["INSTRUCTION_INSPECTOR"]
        self.h.service.validate_job_token(new, identity)
        with self.assertRaises(GatewayError):
            self.h.service.validate_job_token(old, identity)  # re-issue revokes
        self.h.submit(self.h.worker_result(scan_id, "INSTRUCTION_INSPECTOR"))
        with self.assertRaises(GatewayError) as ctx:
            self.h.service.issue_job_capability(a["assignment_id"])  # completed assignment
        self.assertEqual(ctx.exception.code, ErrorCode.FORBIDDEN)

    # A §3: store source maps
    def test_source_maps_are_persisted(self):
        _, _, scan_id = self.started()
        ext = self.h.service.db.query_one("SELECT views_json FROM extractions WHERE scan_id = ?", (scan_id,))
        view = json.loads(ext["views_json"])[0]
        stored = json.loads(self.h.service.store.get(view["source_map_ref"], "tenant-a"))
        self.assertEqual(stored, [[0, 11, 0, 11]])

    # §10 scan job: required workers and budget are durable per scan
    def test_required_checks_and_budget_are_bound_to_the_scan(self):
        from dataclasses import replace

        _, _, scan_id = self.started()
        scan = self.h.service.db.query_one("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        self.assertEqual(json.loads(scan["required_checks_json"]),
                         ["EXTRACTION", "INSTRUCTION_INSPECTOR", "DATA_TOOL_INSPECTOR", "BEHAVIOR_TESTER"])
        self.assertEqual(json.loads(scan["budget_json"])["worker_retries"], 1)
        # A later configuration change does not alter an in-flight scan's retry budget.
        self.h.service.config = replace(self.h.config, limits=replace(self.h.config.limits, worker_retries=5))
        self.h.clock.advance(26)
        self.h.service.recover()
        self.h.clock.advance(26)
        status = self.h.service.get_scan_status(self.p, scan_id)
        self.assertIn("WORKER_MISSING", status["reason_codes"])

    # §10 decision record
    def test_decision_record_is_durable(self):
        _, _, scan_id = self.started()
        recorded = self.h.service.record_collector_event(COLLECTOR, self.h.collector_event(scan_id))
        scan = self.h.service.db.query_one("SELECT decision_record_json FROM scans WHERE scan_id = ?", (scan_id,))
        record = json.loads(scan["decision_record_json"])
        self.assertEqual(record["decision"], "QUARANTINE")
        self.assertEqual(record["policy_version"], "1")
        self.assertEqual(record["completed_checks"], ["EXTRACTION"])
        self.assertEqual(record["evidence_ids"], [recorded["evidence_id"]])

    # master §6: contradictory evidence -> REVIEW
    def test_telemetry_omitting_collector_events_is_contradictory(self):
        _, _, scan_id = self.started()
        self.h.service.record_collector_event(COLLECTOR, self.h.collector_event(scan_id, operation="read_selected", policy_check="PERMITTED"))
        self.h.complete_clean(scan_id, self.h.summary_output(scan_id))  # behavior result reports no telemetry
        status = self.h.service.get_scan_status(self.p, scan_id)
        self.assertEqual((status["decision"], status["reason_codes"]), ("REVIEW", ["CONTRADICTORY_EVIDENCE"]))
        self.assertFalse(status["review"]["eligible"])

    # §15: completion report coverage limits are kept as private worker data
    def test_coverage_limits_stored_privately(self):
        _, _, scan_id = self.started()
        self.h.submit(self.h.worker_result(scan_id, "BEHAVIOR_TESTER", task_output=self.h.summary_output(scan_id),
                                           coverage_limits=["NO_ATTACHMENTS_TESTED"]))
        row = self.h.service.db.query_one("SELECT coverage_limits_json FROM worker_results WHERE scan_id = ?", (scan_id,))
        self.assertEqual(json.loads(row["coverage_limits_json"]), ["NO_ATTACHMENTS_TESTED"])
        self.assertNotIn("NO_ATTACHMENTS_TESTED", json.dumps(self.h.service.get_scan_status(self.p, scan_id)))

    # A §2.3: task sessions bind disclosure constraints
    def test_task_session_reports_disclosure_constraints(self):
        res, ts, _ = self.started()
        self.assertEqual(ts["disclosure"], [{"resource_id": res["resource_id"], "label_id": ts["disclosure"][0]["label_id"],
                                             "disclosure": "PRIVATE_TO_OWNER"}])

    # master §11: emergency controls
    def test_emergency_stop(self):
        ui = self.h.ui()
        res = self.h.upload(ui, "report")
        send_ts = self.h.session(ui, [res["resource_id"]], "simulate_send")
        send_scan = self.h.scan(ui, send_ts["task_session_id"], "send")["scan_id"]
        self.h.complete_clean(send_scan, self.h.summary_output(send_scan))
        action = self.h.service.propose_simulated_action(ui, {"contract_version": V, "task_session_id": send_ts["task_session_id"], "action": {
            "operation": "simulated_send_email", "arguments": {"to": "carol@example.com", "subject": "", "body": "", "attachment_resource_ids": []}}})
        _, _, scan_id = self.started(key="k2")
        a = self.h.runtime.latest(scan_id, "INSTRUCTION_INSPECTOR")
        cap = self.h.runtime.capabilities[a["assignment_id"]]

        stopped = self.h.service.emergency_stop()
        self.assertEqual(stopped["scans_canceled"], 1)
        status = self.h.service.get_scan_status(self.p, scan_id)
        self.assertEqual((status["state"], status["reason_codes"]), ("CANCELED", ["EMERGENCY_STOP"]))
        self.assertEqual(self.h.service.get_action(ui, action["action_id"])["state"], "CANCELED")
        for call in (
            lambda: self.h.service.validate_job_token(cap, a["worker"]),
            lambda: self.h.upload(self.p, "new"),
            lambda: self.h.scan(self.p, send_ts["task_session_id"], "k3"),
        ):
            with self.assertRaises(GatewayError) as ctx:
                call()
            self.assertEqual(ctx.exception.code, ErrorCode.SERVICE_UNAVAILABLE)
        self.h.service.emergency_resume()
        self.h.upload(self.p, "works again")


if __name__ == "__main__":
    unittest.main()


class DispatchOrderTests(unittest.TestCase):
    def test_documents_follow_the_task_resource_order_not_random_ids(self):
        h = Harness()
        try:
            p = h.api()
            first, second = h.upload(p, "first file"), h.upload(p, "second file")  # IDs sort first < second
            ts = h.session(p, [second["resource_id"], first["resource_id"]], "summarize_email")
            scan_id = h.scan(p, ts["task_session_id"])["scan_id"]
            assignment = h.runtime.latest(scan_id, "INSTRUCTION_INSPECTOR")
            self.assertEqual([r["resource_id"] for r in assignment["resources"]], [second["resource_id"], first["resource_id"]])
        finally:
            h.close()
