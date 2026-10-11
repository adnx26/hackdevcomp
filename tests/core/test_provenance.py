"""Provenance: the owner can see the exact source text behind each released value."""

import unittest

from protection_gateway.contracts.enums import Channel, ErrorCode
from protection_gateway.contracts.errors import GatewayError

from .support import TOKENS, V, Harness

UNICODE_INVOICE = "\U0001F9FE Rechnung ​\nInvoice INV-1001\nAmount due: $1,250.00 USD\nDue date: 2026-11-01\n"


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.p = self.h.api()

    def tearDown(self):
        self.h.close()

    def code(self, fn, *args):
        with self.assertRaises(GatewayError) as ctx:
            fn(*args)
        return ctx.exception.code

    def released(self, text=UNICODE_INVOICE):
        res = self.h.upload(self.p, text)
        ts = self.h.session(self.p, [res["resource_id"]], "extract_invoice")
        scan_id = self.h.scan(self.p, ts["task_session_id"])["scan_id"]
        self.h.complete_clean(scan_id, self.h.invoice_output(scan_id, text))
        result = self.h.service.get_inspected_result(self.p, scan_id)
        return scan_id, ts, result["result"]["output"]["fields"]

    def test_cited_view_text_matches_every_span_in_code_points(self):
        scan_id, _, fields = self.released()
        ref = fields["invoice_id"]["source_refs"][0]
        view = self.h.service.get_result_source(self.p, scan_id, ref["resource_id"], ref["view_hash"])
        self.assertEqual(view["offset_unit"], "UNICODE_CODE_POINT")
        self.assertEqual((view["text"], view["truncated"]), (UNICODE_INVOICE, False))
        expected = {"invoice_id": "INV-1001", "amount": "$1,250.00", "currency": "USD", "due_date": "2026-11-01"}
        for name, fragment in expected.items():
            span = fields[name]["source_refs"][0]
            self.assertEqual(view["text"][span["start"]:span["end"]], fragment, name)
        # The emoji is one code point but two UTF-16 units: the UI must index code points.
        self.assertGreater(len(UNICODE_INVOICE.encode("utf-16-le")) // 2, len(UNICODE_INVOICE))

    def test_only_views_cited_by_a_released_result(self):
        scan_id, _, fields = self.released()
        ref = fields["amount"]["source_refs"][0]
        self.assertEqual(self.code(self.h.service.get_result_source, self.p, scan_id, ref["resource_id"], "f" * 64), ErrorCode.NOT_FOUND)
        other = self.h.upload(self.p, "unrelated")
        self.assertEqual(self.code(self.h.service.get_result_source, self.p, scan_id, other["resource_id"], ref["view_hash"]), ErrorCode.NOT_FOUND)

    def test_withheld_results_expose_no_source(self):
        res = self.h.upload(self.p, UNICODE_INVOICE)
        ts = self.h.session(self.p, [res["resource_id"]], "extract_invoice")
        scan_id = self.h.scan(self.p, ts["task_session_id"])["scan_id"]
        view = self.h.view(scan_id, "INSTRUCTION_INSPECTOR")
        self.assertEqual(self.code(self.h.service.get_result_source, self.p, scan_id, view["resource_id"], view["view_hash"]), ErrorCode.NOT_READY)
        finding = {"category": "OVERRIDE_ATTEMPT", "resource_id": view["resource_id"], "view_hash": view["view_hash"], "evidence_ids": []}
        self.h.submit(self.h.worker_result(scan_id, "INSTRUCTION_INSPECTOR", findings=[finding]))
        self.h.submit(self.h.worker_result(scan_id, "DATA_TOOL_INSPECTOR"))
        self.h.submit(self.h.worker_result(scan_id, "BEHAVIOR_TESTER", task_output=self.h.invoice_output(scan_id, UNICODE_INVOICE)))
        self.assertEqual(self.code(self.h.service.get_result_source, self.p, scan_id, view["resource_id"], view["view_hash"]), ErrorCode.APPROVAL_REQUIRED)
        status = self.h.service.get_scan_status(self.p, scan_id)
        self.h.service.review_scan(self.h.ui(), scan_id, {"contract_version": V, "action": "ALLOW_READ_ONLY", "reason": "known sender",
                                                         "result_digest": status["review"]["result_digest"]})
        source = self.h.service.get_result_source(self.p, scan_id, view["resource_id"], view["view_hash"])
        self.assertEqual(source["release_basis"], "REVIEW_EXCEPTION")

    def test_context_change_and_channels_and_tenancy(self):
        scan_id, ts, fields = self.released()
        ref = fields["amount"]["source_refs"][0]
        args = (scan_id, ref["resource_id"], ref["view_hash"])
        self.assertEqual(self.code(self.h.service.get_result_source, self.p.as_assistant(), *args), ErrorCode.FORBIDDEN)
        mcp = self.h.auth.authenticate_bearer(TOKENS["alice"], Channel.MCP)
        self.assertEqual(self.code(self.h.service.get_result_source, mcp, *args), ErrorCode.FORBIDDEN)
        self.assertEqual(self.code(self.h.service.get_result_source, self.h.api("mallory"), *args), ErrorCode.NOT_FOUND)
        self.h.service.advance_task_context(self.p, ts["task_session_id"])
        self.assertEqual(self.code(self.h.service.get_result_source, self.p, *args), ErrorCode.CONTEXT_CHANGED)


if __name__ == "__main__":
    unittest.main()
