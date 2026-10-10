"""Upload limits, extraction coverage, runtime failures, timeouts, retries,
restarts and cancellation never produce approval."""

import base64
import unittest

from protection_gateway.contracts.enums import ErrorCode
from protection_gateway.contracts.errors import GatewayError
from protection_gateway.core.config import Limits
from protection_gateway.core.service import GatewayService

from .support import V, Harness


class ScanWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.p = self.h.api()

    def tearDown(self):
        self.h.close()

    def code(self, fn, *args, **kwargs):
        with self.assertRaises(GatewayError) as ctx:
            fn(*args, **kwargs)
        return ctx.exception.code

    def started(self, text="Hello", policy="summarize_email", key="k1"):
        res = self.h.upload(self.p, text)
        ts = self.h.session(self.p, [res["resource_id"]], policy)
        return self.h.scan(self.p, ts["task_session_id"], key)

    # uploads ---------------------------------------------------------------
    def test_upload_returns_stored_hash_only(self):
        res = self.h.upload(self.p, "hi")
        self.assertEqual(res["storage_state"], "STORED")
        self.assertEqual(set(res), {"resource_id", "original_hash", "storage_state", "media_type", "size_bytes", "expires_at"})

    def test_upload_limits_and_formats(self):
        h = Harness(limits=Limits(max_source_bytes=10))
        try:
            p = h.api()
            self.assertEqual(self.code(h.upload, p, "x" * 11), ErrorCode.LIMIT_EXCEEDED)
            self.assertEqual(self.code(h.upload, p, "x", "application/pdf"), ErrorCode.INVALID_REQUEST)
            bad = {"contract_version": V, "media_type": "text/plain", "content_base64": "!!!"}
            self.assertEqual(self.code(h.service.upload_resource, p, bad), ErrorCode.INVALID_REQUEST)
        finally:
            h.close()

    def test_task_source_limits(self):
        h = Harness(limits=Limits(max_task_sources=1))
        try:
            p = h.api()
            a, b = h.upload(p, "a"), h.upload(p, "b")
            self.assertEqual(self.code(h.session, p, [a["resource_id"], b["resource_id"]]), ErrorCode.LIMIT_EXCEEDED)
        finally:
            h.close()

    # runtime availability ----------------------------------------------------
    def test_no_runtime_returns_service_unavailable(self):
        h = Harness(runtime=False)
        try:
            p = h.api()
            res = h.upload(p)
            ts = h.session(p, [res["resource_id"]])
            self.assertEqual(self.code(h.scan, p, ts["task_session_id"]), ErrorCode.SERVICE_UNAVAILABLE)
        finally:
            h.close()

    def test_extract_outage_fails_closed(self):
        self.h.runtime.fail_extract = True
        status = self.started()
        self.assertEqual((status["state"], status["decision"]), ("FAILED", None))
        self.assertEqual(status["reason_codes"], ["RUNTIME_UNAVAILABLE"])
        self.assertEqual(self.code(self.h.service.get_inspected_result, self.p, status["scan_id"]), ErrorCode.FORBIDDEN)

    def test_dispatch_outage_fails_closed(self):
        self.h.runtime.fail_dispatch = True
        status = self.started()
        self.assertEqual(status["state"], "FAILED")

    # extraction coverage ---------------------------------------------------
    def test_unsupported_relevant_attachment_holds(self):
        res = self.h.upload(self.p, "see attached invoice")
        self.h.runtime.extract_overrides[res["resource_id"]] = {
            "unsupported_parts": [{"part_id": "att1", "media_type": "application/pdf", "task_relevant": True, "reason": "UNSUPPORTED_FORMAT"}]
        }
        ts = self.h.session(self.p, [res["resource_id"]])
        status = self.h.scan(self.p, ts["task_session_id"])
        self.assertEqual((status["state"], status["decision"]), ("DECIDED", "REVIEW"))
        self.assertEqual(status["reason_codes"], ["UNSUPPORTED_CONTENT"])
        self.assertFalse(status["review"]["eligible"])
        self.assertEqual(self.h.runtime.assignments, {})  # never dispatched

    def test_incomplete_or_forged_extraction_holds(self):
        for override, code in (
            ({"status": "INCOMPLETE"}, "EXTRACTION_INCOMPLETE"),
            ({"original_hash": "0" * 64}, "EXTRACTION_ERROR"),
            ({"views": [{"view_id": "v", "kind": "k", "text": "abc", "view_hash": "f" * 64, "source_map": []}]}, "EXTRACTION_ERROR"),
            ({"unexpected": True}, "EXTRACTION_ERROR"),
        ):
            h = Harness()
            try:
                p = h.api()
                res = h.upload(p, "body")
                h.runtime.extract_overrides[res["resource_id"]] = override
                ts = h.session(p, [res["resource_id"]], "summarize_email")
                status = h.scan(p, ts["task_session_id"])
                self.assertEqual(status["decision"], "REVIEW", override)
                self.assertIn(code, status["reason_codes"])
            finally:
                h.close()

    def test_extracted_char_limit_holds(self):
        h = Harness(limits=Limits(max_extracted_chars=5))
        try:
            p = h.api()
            res = h.upload(p, "more than five")
            ts = h.session(p, [res["resource_id"]], "summarize_email")
            self.assertIn("LIMIT_EXCEEDED", h.scan(p, ts["task_session_id"])["reason_codes"])
        finally:
            h.close()

    # idempotency and concurrency ---------------------------------------------
    def test_scan_idempotency(self):
        res = self.h.upload(self.p)
        ts = self.h.session(self.p, [res["resource_id"]])
        first = self.h.scan(self.p, ts["task_session_id"], "same")
        again = self.h.scan(self.p, ts["task_session_id"], "same")
        self.assertEqual(first["scan_id"], again["scan_id"])
        self.assertEqual(self.code(self.h.scan, self.p, ts["task_session_id"], None), ErrorCode.INVALID_REQUEST)
        ts2 = self.h.session(self.p, [res["resource_id"]])
        self.assertEqual(self.code(self.h.scan, self.p, ts2["task_session_id"], "same"), ErrorCode.INVALID_REQUEST)

    def test_concurrency_limit(self):
        self.started(key="a")
        self.started(key="b")
        with self.assertRaises(GatewayError) as ctx:
            self.started(key="c")
        self.assertEqual(ctx.exception.code, ErrorCode.LIMIT_EXCEEDED)
        self.assertTrue(ctx.exception.retryable)

    # timeouts, retries and restarts -------------------------------------------
    def test_missing_workers_time_out_to_review(self):
        status = self.started()
        self.h.submit(self.h.worker_result(status["scan_id"], "INSTRUCTION_INSPECTOR"))
        self.assertEqual(self.h.service.get_scan_status(self.p, status["scan_id"])["state"], "INSPECTING")
        self.assertEqual(self.code(self.h.service.get_inspected_result, self.p, status["scan_id"]), ErrorCode.NOT_READY)
        self.h.clock.advance(61)
        status = self.h.service.get_scan_status(self.p, status["scan_id"])
        self.assertEqual((status["state"], status["decision"]), ("DECIDED", "REVIEW"))
        self.assertIn("TIMEOUT", status["reason_codes"])
        self.assertFalse(status["review"]["eligible"])

    def test_lease_expiry_retries_once_then_worker_missing(self):
        status = self.started()
        scan_id = status["scan_id"]
        first = self.h.runtime.latest(scan_id, "DATA_TOOL_INSPECTOR")
        self.h.clock.advance(26)
        self.h.service.recover()
        retry = self.h.runtime.latest(scan_id, "DATA_TOOL_INSPECTOR")
        self.assertEqual((first["attempt"], retry["attempt"]), (1, 2))
        # Old attempt can no longer complete the check.
        with self.assertRaises(GatewayError):
            self.h.submit(dict(self.h.worker_result(scan_id, "DATA_TOOL_INSPECTOR"), assignment_id=first["assignment_id"], attempt=1))
        self.h.clock.advance(26)
        status = self.h.service.get_scan_status(self.p, scan_id)
        self.assertEqual(status["decision"], "REVIEW")
        self.assertIn("WORKER_MISSING", status["reason_codes"])

    def test_undelivered_assignment_is_retried_not_counted(self):
        self.h.runtime.undeliver_roles = {"BEHAVIOR_TESTER"}
        status = self.started()
        attempts = [a for a in self.h.runtime.assignments.values() if a["worker"]["role"] == "BEHAVIOR_TESTER"]
        self.assertEqual(len(attempts), 2)
        self.h.submit(self.h.worker_result(status["scan_id"], "INSTRUCTION_INSPECTOR"))
        self.h.submit(self.h.worker_result(status["scan_id"], "DATA_TOOL_INSPECTOR"))
        status = self.h.service.get_scan_status(self.p, status["scan_id"])
        self.assertEqual(status["decision"], "REVIEW")
        self.assertIn("WORKER_MISSING", status["reason_codes"])

    def test_restart_mid_extraction_fails_closed_and_leases_survive(self):
        status = self.started()
        scan_id = status["scan_id"]
        with self.h.service.db.transaction() as conn:
            conn.execute("UPDATE scans SET state = 'EXTRACTING' WHERE scan_id = ?", (scan_id,))
        restarted = GatewayService(self.h.config, runtime=self.h.runtime, clock=self.h.clock, ids=self.h.ids)
        restarted.recover(startup=True)
        self.assertEqual(restarted.get_scan_status(self.p, scan_id)["state"], "FAILED")

    def test_restart_during_inspection_resumes_from_durable_state(self):
        status = self.started()
        scan_id = status["scan_id"]
        self.h.submit(self.h.worker_result(scan_id, "INSTRUCTION_INSPECTOR"))
        restarted = GatewayService(self.h.config, runtime=self.h.runtime, clock=self.h.clock, ids=self.h.ids)
        self.h.runtime.service = restarted
        restarted.recover(startup=True)
        self.assertEqual(restarted.get_scan_status(self.p, scan_id)["completed_checks"], ["EXTRACTION", "INSTRUCTION_INSPECTOR"])
        restarted.accept_worker_result(*self._identity_and(self.h.worker_result(scan_id, "DATA_TOOL_INSPECTOR")))
        restarted.accept_worker_result(*self._identity_and(self.h.worker_result(scan_id, "BEHAVIOR_TESTER", task_output=self.h.summary_output(scan_id))))
        self.assertEqual(restarted.get_scan_status(self.p, scan_id)["decision"], "ALLOW_UNDER_POLICY")

    def _identity_and(self, result):
        from .support import IDENTITIES

        return IDENTITIES[result["worker"]["role"]], result

    # cancellation ----------------------------------------------------------
    def test_cancel_revokes_and_late_results_cannot_release(self):
        status = self.started()
        scan_id = status["scan_id"]
        a = self.h.runtime.latest(scan_id, "INSTRUCTION_INSPECTOR")
        cap = self.h.runtime.capabilities[a["assignment_id"]]
        canceled = self.h.service.cancel_scan(self.p, scan_id)
        self.assertEqual(canceled["state"], "CANCELED")
        self.assertIn(scan_id, self.h.runtime.canceled)
        with self.assertRaises(GatewayError) as ctx:
            self.h.service.validate_job_token(cap, a["worker"])
        self.assertEqual(ctx.exception.code, ErrorCode.UNAUTHENTICATED)
        for role in ("INSTRUCTION_INSPECTOR", "DATA_TOOL_INSPECTOR"):
            self.assertEqual(self.code(self.h.submit, self.h.worker_result(scan_id, role)), ErrorCode.CONTEXT_CHANGED)
        self.assertEqual(self.code(self.h.service.get_inspected_result, self.p, scan_id), ErrorCode.FORBIDDEN)

    def test_cancel_after_allow_withholds(self):
        _, _, scan = self.h.allowed_scan(self.p, key="z")
        self.h.service.cancel_scan(self.p, scan["scan_id"])
        self.assertEqual(self.code(self.h.service.get_inspected_result, self.p, scan["scan_id"]), ErrorCode.FORBIDDEN)

    def test_inspect_resource_resumes_same_scan(self):
        res = self.h.upload(self.p)
        ts = self.h.session(self.p, [res["resource_id"]])
        first = self.h.service.inspect_resource(self.p, res["resource_id"], ts["task_session_id"])
        again = self.h.service.inspect_resource(self.p, res["resource_id"], ts["task_session_id"])
        self.assertEqual(first["scan_id"], again["scan_id"])
        other = self.h.upload(self.p, "x")
        self.assertEqual(
            self.code(self.h.service.inspect_resource, self.p, other["resource_id"], ts["task_session_id"]), ErrorCode.NOT_FOUND
        )


if __name__ == "__main__":
    unittest.main()
