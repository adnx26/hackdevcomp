"""Committed fixtures match the code and validate against canonical schemas."""

import json
import os
import unittest

from protection_gateway.contracts import schemas

from .fixture_builder import FIXTURE_DIR, build, render

EXPECTED = {
    "allowed": ("DECIDED", "ALLOW_UNDER_POLICY", [], True),
    "suspicious_review": ("DECIDED", "REVIEW", ["SUSPICIOUS_UNCORROBORATED"], False),
    "collector_quarantine": ("DECIDED", "QUARANTINE", ["VERIFIED_FORBIDDEN_ACTION"], False),
    "incomplete_unsupported": ("DECIDED", "REVIEW", ["UNSUPPORTED_CONTENT"], False),
    "incomplete_timeout": ("DECIDED", "REVIEW", ["TIMEOUT"], False),
    "canceled": ("CANCELED", None, ["CANCELED_BY_USER"], False),
    "stale_context": ("DECIDED", "ALLOW_UNDER_POLICY", [], False),
}


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.built = build()

    def load(self, rel):
        with open(os.path.join(FIXTURE_DIR, rel), encoding="utf-8") as handle:
            return json.load(handle)

    def test_committed_fixtures_match_code(self):
        for rel, obj in self.built.items():
            with open(os.path.join(FIXTURE_DIR, rel), encoding="utf-8") as handle:
                self.assertEqual(handle.read(), render(obj), f"{rel} drifted; regenerate with fixture_builder")

    def test_scenario_outcomes(self):
        for name, (state, decision, reasons, released) in EXPECTED.items():
            expected = self.load(f"scenarios/{name}.json")["expected"]
            self.assertEqual(
                (expected["state"], expected["decision"], expected["reason_codes"], expected["result_released"]),
                (state, decision, reasons, released), name,
            )
        self.assertEqual(self.load("scenarios/stale_context.json")["expected"]["result_error_code"], "CONTEXT_CHANGED")
        self.assertEqual(self.load("scenarios/canceled.json")["expected"]["late_result_error_code"], "CONTEXT_CHANGED")
        self.assertTrue(self.load("scenarios/suspicious_review.json")["after_review_exception"]["result_released"])
        cross = self.load("scenarios/cross_tenant.json")["expected"]
        self.assertTrue(all(v == {"code": "NOT_FOUND", "retryable": False, "http_status": 404} for v in cross.values()))
        replay = self.load("scenarios/action_replay.json")["expected"]
        self.assertEqual(replay["dummy_effects_recorded"], 1)
        self.assertEqual(replay["new_key_after_execution"]["code"], "APPROVAL_REQUIRED")
        self.assertEqual(replay["confirm_from_assistant_channel"]["code"], "FORBIDDEN")

    def test_runtime_examples_validate(self):
        pairs = {
            "runtime_extraction_assignment.json": schemas.extraction_assignment,
            "runtime_extraction_result.json": schemas.extraction_result,
            "runtime_inspection_assignment.json": schemas.inspection_assignment,
            "runtime_worker_result_behavior.json": schemas.worker_result,
            "runtime_worker_result_suspicious.json": schemas.worker_result,
            "runtime_collector_event.json": schemas.collector_event,
            "runtime_worker_identity.json": schemas.worker_identity,
            "runtime_collector_identity.json": schemas.collector_identity,
        }
        for rel, checker in pairs.items():
            schemas.validate(checker, self.load(f"examples/{rel}"))

    def test_request_examples_validate(self):
        pairs = {
            "http_post_resources.json": schemas.resource_upload_request,
            "http_post_task_sessions.json": schemas.task_session_request,
            "http_post_scans.json": schemas.scan_request,
            "http_post_scan_review.json": schemas.review_request,
            "http_post_actions.json": schemas.action_request,
            "http_post_action_confirm.json": schemas.confirm_request,
            "http_post_action_execute.json": schemas.empty_request,
        }
        for rel, checker in pairs.items():
            schemas.validate(checker, self.load(f"examples/{rel}")["request"])

    def test_public_status_never_contains_source_text(self):
        for name in EXPECTED:
            text = json.dumps(self.load(f"scenarios/{name}.json")["status_response"])
            for fragment in ("Ignore previous", "attacker@example.net", "password", "Invoice INV"):
                self.assertNotIn(fragment, text, name)


if __name__ == "__main__":
    unittest.main()
