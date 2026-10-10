"""Unauthorized user/tenant lookups cannot read resources, scans, artifacts,
collector events or actions, and cannot learn whether they exist."""

import unittest

from protection_gateway.contracts.enums import Channel, ErrorCode
from protection_gateway.contracts.errors import GatewayError

from .support import COLLECTOR, IDENTITIES, V, Harness


class TenancyTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.alice = self.h.api("alice")
        self.res, self.ts, self.scan = self.h.allowed_scan(self.alice)
        self.scan_id = self.scan["scan_id"]

    def tearDown(self):
        self.h.close()

    def assertNotFound(self, fn, *args):
        with self.assertRaises(GatewayError) as ctx:
            fn(*args)
        self.assertEqual(ctx.exception.code, ErrorCode.NOT_FOUND)

    def test_other_tenant_and_other_user_see_not_found(self):
        s = self.h.service
        for other in (self.h.api("mallory"), self.h.api("bob")):
            self.assertNotFound(s.get_scan_status, other, self.scan_id)
            self.assertNotFound(s.get_inspected_result, other, self.scan_id)
            self.assertNotFound(s.cancel_scan, other, self.scan_id)
            self.assertNotFound(s.get_task_session, other, self.ts["task_session_id"])
            self.assertNotFound(s.delete_resource, other, self.res["resource_id"])
            self.assertNotFound(
                s.create_task_session, other,
                {"contract_version": V, "policy_id": "summarize_email", "resource_ids": [self.res["resource_id"]]},
            )

    def test_unknown_ids_look_identical(self):
        s = self.h.service
        mallory = self.h.api("mallory")
        self.assertNotFound(s.get_scan_status, mallory, "scan_9999")
        self.assertNotFound(s.get_scan_status, mallory, "../../etc/passwd")

    def test_evidence_and_collector_events_are_owner_only(self):
        h = self.h
        principal = h.api()
        res = h.upload(principal)
        ts = h.session(principal, [res["resource_id"]], "summarize_email")
        scan_id = h.scan(principal, ts["task_session_id"], "k2")["scan_id"]
        recorded = h.service.record_collector_event(COLLECTOR, h.collector_event(scan_id))
        evidence_id = recorded["evidence_id"]
        self.assertEqual(h.service.get_evidence(principal, evidence_id)["source"], "COLLECTOR")
        self.assertNotFound(h.service.get_evidence, h.api("mallory"), evidence_id)
        self.assertNotFound(h.service.get_evidence, h.api("bob"), evidence_id)

    def test_job_token_cannot_read_another_resource(self):
        h = self.h
        other = h.upload(h.api("mallory"), "mallory secret")
        principal = h.api()
        res = h.upload(principal)
        ts = h.session(principal, [res["resource_id"]], "summarize_email")
        scan_id = h.scan(principal, ts["task_session_id"], "k3")["scan_id"]
        a = h.runtime.latest(scan_id, "INSTRUCTION_INSPECTOR")
        cap = h.runtime.capabilities[a["assignment_id"]]
        with self.assertRaises(GatewayError) as ctx:
            h.service.read_assigned_view(cap, IDENTITIES["INSTRUCTION_INSPECTOR"], other["resource_id"], "visible")
        self.assertEqual(ctx.exception.code, ErrorCode.FORBIDDEN)
        # A capability is bound to its worker.
        with self.assertRaises(GatewayError):
            h.service.read_assigned_view(cap, IDENTITIES["DATA_TOOL_INSPECTOR"], res["resource_id"], "visible")
        self.assertIn("Invoice", h.service.read_assigned_view(cap, IDENTITIES["INSTRUCTION_INSPECTOR"], res["resource_id"], "visible"))

    def test_mcp_channel_is_read_only(self):
        h = self.h
        mcp = h.auth.authenticate_bearer("token-alice-0123456789", Channel.MCP)
        self.assertEqual(h.service.get_scan_status(mcp, self.scan_id)["decision"], "ALLOW_UNDER_POLICY")
        h.service.get_inspected_result(mcp, self.scan_id)
        for call in (
            lambda: h.upload(mcp),
            lambda: h.service.cancel_scan(mcp, self.scan_id),
            lambda: h.service.get_evidence(mcp, "ev_0001"),
            lambda: h.service.review_scan(mcp, self.scan_id, {"contract_version": V, "action": "REJECT", "reason": "x"}),
        ):
            with self.assertRaises(GatewayError) as ctx:
                call()
            self.assertEqual(ctx.exception.code, ErrorCode.FORBIDDEN)

    def test_tenant_cannot_come_from_request_fields(self):
        with self.assertRaises(GatewayError) as ctx:
            self.h.service.create_task_session(
                self.alice,
                {"contract_version": V, "policy_id": "summarize_email", "resource_ids": [self.res["resource_id"]], "tenant_id": "tenant-m"},
            )
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_REQUEST)


if __name__ == "__main__":
    unittest.main()
