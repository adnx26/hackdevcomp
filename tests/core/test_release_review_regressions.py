"""Release concurrency and signed amount proofs from A's final review."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
import unittest

from protection_gateway.contracts.errors import GatewayError

from .support import COLLECTOR, Harness, INVOICE_TEXT


class ReleaseReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.api = self.h.api()

    def tearDown(self):
        self.h.close()

    def assert_revocation_serialized_with_content_read(self, mutation):
        _, _, scan = self.h.allowed_scan(self.api)
        scan_id = scan["scan_id"]
        output = self.h.service.db.query_one("SELECT storage_ref FROM outputs WHERE scan_id = ?", (scan_id,))
        at_content_read, resume_read, mutation_attempted = Event(), Event(), Event()
        original = self.h.service.store.get
        observed = {}

        def pause_content_read(ref, tenant):
            if ref == output["storage_ref"]:
                at_content_read.set()
                if not resume_read.wait(5):
                    raise AssertionError("release was not resumed")
            return original(ref, tenant)

        def revoke():
            # Probe from the competing thread at the exact content-read
            # boundary, then run the real mutation. Its commit must wait
            # until this previously authorized release finishes.
            acquired = self.h.service.db._lock.acquire(blocking=False)
            if acquired:
                self.h.service.db._lock.release()
            observed["serialized"] = not acquired
            mutation_attempted.set()
            return mutation(scan_id)

        self.h.service.store.get = pause_content_read
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                release = pool.submit(self.h.service.get_inspected_result, self.api, scan_id)
                try:
                    self.assertTrue(at_content_read.wait(5), "release did not reach the storage boundary")
                    revocation = pool.submit(revoke)
                    self.assertTrue(mutation_attempted.wait(5), "revocation did not start")
                    self.assertTrue(observed["serialized"], "revocation can commit after validation but before content read")
                    self.assertFalse(revocation.done(), "revocation committed before the authorized content read")
                finally:
                    resume_read.set()
                self.assertEqual(release.result(5)["release_basis"], "ALLOW_UNDER_POLICY")
                revocation.result(5)
        finally:
            self.h.service.store.get = original
            resume_read.set()
        # The concurrent release precedes revocation; every later release is
        # denied once the actual stop/quarantine has committed.
        with self.assertRaises(GatewayError):
            self.h.service.get_inspected_result(self.api, scan_id)

    def test_emergency_stop_cannot_commit_between_authorization_and_read(self):
        self.assert_revocation_serialized_with_content_read(lambda _: self.h.service.emergency_stop())
        self.assertTrue(self.h.service.emergency_stopped())

    def test_quarantine_cannot_commit_between_authorization_and_read(self):
        def quarantine(scan_id):
            return self.h.service.record_collector_event(COLLECTOR, self.h.collector_event(scan_id, operation="fetch_url"))
        self.assert_revocation_serialized_with_content_read(quarantine)

    def test_forbidden_collector_event_with_stale_allow_decision_withholds_release(self):
        _, _, scan = self.h.allowed_scan(self.api)
        original = self.h.service._apply_forbidden_evidence
        checked = []

        def check_before_downgrade(scan_id):
            self.assertEqual(self.h.service._scan(scan_id)["decision"], "ALLOW_UNDER_POLICY")
            self.assertIsNotNone(self.h.service.db.query_one(
                "SELECT 1 FROM collector_events WHERE scan_id = ? AND effective_policy_check = 'FORBIDDEN'",
                (scan_id,),
            ))
            with self.assertRaises(GatewayError):
                self.h.service.get_inspected_result(self.api, scan_id)
            checked.append(True)
            original(scan_id)

        self.h.service._apply_forbidden_evidence = check_before_downgrade
        self.h.service.record_collector_event(COLLECTOR, self.h.collector_event(scan["scan_id"], operation="fetch_url"))
        self.assertEqual(checked, [True])
        self.assertEqual(self.h.service.get_scan_status(self.api, scan["scan_id"])["decision"], "QUARANTINE")

    def signed_invoice(self, token, reported_value, cited_fragment):
        text = INVOICE_TEXT.replace("$1,250.00", token)
        resource = self.h.upload(self.api, text)
        session = self.h.session(self.api, [resource["resource_id"]])
        scan = self.h.scan(self.api, session["task_session_id"], "signed-" + resource["resource_id"])
        view = self.h.view(scan["scan_id"])
        values = {"invoice_id": "INV-1001", "amount": reported_value, "currency": "USD", "due_date": "2026-11-01"}
        fields = {}
        for name, value in values.items():
            fragment = cited_fragment if name == "amount" else value
            start = text.index(fragment)
            fields[name] = {"value": value, "source_refs": [{
                "resource_id": view["resource_id"], "view_hash": view["view_hash"],
                "start": start, "end": start + len(fragment),
            }]}
        self.h.complete_clean(scan["scan_id"], {"kind": "invoice", "fields": fields})
        return scan["scan_id"]

    def test_signed_currency_amount_cannot_approve_positive_value(self):
        for token in ("-$1250.00", "$-1250.00"):
            for citation in (token, "1250.00"):
                with self.subTest(token=token, citation=citation):
                    scan_id = self.signed_invoice(token, "1250.00", citation)
                    status = self.h.service.get_scan_status(self.api, scan_id)
                    self.assertEqual(status["decision"], "REVIEW")
                    self.assertIn("ANSWER_MISMATCH", status["reason_codes"])
                    with self.assertRaises(GatewayError):
                        self.h.service.get_inspected_result(self.api, scan_id)

    def test_signed_currency_amount_accepts_correct_negative_value(self):
        for token in ("-$1250.00", "$-1250.00"):
            with self.subTest(token=token):
                scan_id = self.signed_invoice(token, "-1250.00", token)
                self.assertEqual(self.h.service.get_scan_status(self.api, scan_id)["decision"], "ALLOW_UNDER_POLICY")
                result = self.h.service.get_inspected_result(self.api, scan_id)
                self.assertEqual(result["result"]["output"]["fields"]["amount"]["value"], "-1250.00")


if __name__ == "__main__":
    unittest.main()
