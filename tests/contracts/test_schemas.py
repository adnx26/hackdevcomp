"""Canonical serialization, enums, policies and strict schemas."""

import unittest

from protection_gateway.contracts import schemas
from protection_gateway.contracts.canonical import canonical_digest, canonical_json, sha256_hex
from protection_gateway.contracts.enums import ActionState, Decision, ErrorCode, FindingCategory, JobState
from protection_gateway.contracts.errors import HTTP_STATUS, ContractError, GatewayError
from protection_gateway.contracts.policies import POLICIES


class CanonicalTests(unittest.TestCase):
    def test_stable_sorted_compact_utf8(self):
        self.assertEqual(canonical_json({"b": 1, "a": "é"}), '{"a":"é","b":1}'.encode("utf-8"))
        self.assertEqual(canonical_digest({"a": 1, "b": [1, 2]}), canonical_digest({"b": [1, 2], "a": 1}))
        self.assertEqual(sha256_hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_floats_rejected(self):
        with self.assertRaises(ValueError):
            canonical_json({"amount": 12.5})


class EnumTests(unittest.TestCase):
    def test_frozen_v1_values(self):
        self.assertEqual(JobState.values(), {"QUEUED", "EXTRACTING", "INSPECTING", "DECIDED", "FAILED", "CANCELED"})
        self.assertEqual(Decision.values(), {"ALLOW_UNDER_POLICY", "REVIEW", "QUARANTINE"})
        self.assertEqual(
            ActionState.values(),
            {"PROPOSED", "CONFIRMED", "EXECUTED", "REJECTED", "EXPIRED", "CANCELED", "UNKNOWN_OUTCOME"},
        )
        self.assertEqual(
            FindingCategory.values(),
            {"OVERRIDE_ATTEMPT", "HIDDEN_INSTRUCTIONS", "DISCLOSURE_REQUEST", "UNAUTHORIZED_TOOL_REQUEST",
             "OBSERVED_FORBIDDEN_ACTION", "ANSWER_MISMATCH"},
        )
        self.assertEqual(set(HTTP_STATUS), set(ErrorCode))

    def test_only_transient_errors_retry_by_default(self):
        self.assertTrue(GatewayError(ErrorCode.SERVICE_UNAVAILABLE).retryable)
        self.assertFalse(GatewayError(ErrorCode.FORBIDDEN).retryable)


class PolicyTests(unittest.TestCase):
    def test_policies(self):
        self.assertEqual(set(POLICIES), {"summarize_email", "extract_invoice", "simulate_send"})
        self.assertFalse(POLICIES["summarize_email"].operation_permitted("send_email"))
        self.assertFalse(POLICIES["extract_invoice"].operation_permitted("make_payment"))
        self.assertTrue(POLICIES["simulate_send"].permits_simulated_send)
        hashes = {p.policy_hash for p in POLICIES.values()}
        self.assertEqual(len(hashes), 3)


class SchemaTests(unittest.TestCase):
    def test_unexpected_and_missing_fields(self):
        ok = {"contract_version": "v1", "task_session_id": "ts_1"}
        schemas.validate(schemas.scan_request, ok)
        for bad in (dict(ok, safe=True), {"contract_version": "v1"}, dict(ok, contract_version="v2"), dict(ok, task_session_id="a/b")):
            with self.assertRaises(ContractError):
                schemas.validate(schemas.scan_request, bad)

    def test_typed_values(self):
        with self.assertRaises(ContractError):
            schemas.validate(schemas.span, {"start": True, "end": 2})
        with self.assertRaises(ContractError):
            schemas.validate(schemas.collector_event, {})
        output = {"kind": "invoice", "fields": {
            "invoice_id": {"absent": True}, "amount": {"value": "12.5x", "source_refs": [{"resource_id": "r", "view_hash": "0" * 64, "start": 0, "end": 1}]},
            "currency": {"absent": True}, "due_date": {"absent": True}}}
        schemas.validate(schemas.invoice_output, output)
        with self.assertRaises(ContractError):
            schemas.validate_invoice_values(output)

    def test_email_and_action_operation(self):
        args = {"to": "not-an-email", "subject": "", "body": "", "attachment_resource_ids": []}
        with self.assertRaises(ContractError):
            schemas.validate(schemas.simulated_send_arguments, args)


if __name__ == "__main__":
    unittest.main()
