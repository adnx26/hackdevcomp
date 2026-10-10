import unittest

from protection_gateway.contracts.enums import Decision, InspectionStatus
from protection_gateway.core.decisions import DecisionInputs, RoleResult, decide, review_exception_eligible

ROLES = ("INSTRUCTION_INSPECTOR", "DATA_TOOL_INSPECTOR", "BEHAVIOR_TESTER")
CLEAN = RoleResult(InspectionStatus.COMPLETE)


def inputs(**overrides):
    base = dict(
        extraction_statuses=["COMPLETE"],
        unsupported_relevant=False,
        extraction_limit_exceeded=False,
        required_roles=ROLES,
        results={
            "INSTRUCTION_INSPECTOR": CLEAN,
            "DATA_TOOL_INSPECTOR": CLEAN,
            "BEHAVIOR_TESTER": RoleResult(InspectionStatus.COMPLETE, has_task_output=True),
        },
    )
    base.update(overrides)
    return DecisionInputs(**base)


class DecisionTableTests(unittest.TestCase):
    def test_all_complete_allows(self):
        self.assertEqual(decide(inputs()).decision, Decision.ALLOW_UNDER_POLICY)

    def test_pending_role_waits(self):
        results = dict(inputs().results)
        del results["DATA_TOOL_INSPECTOR"]
        self.assertIsNone(decide(inputs(results=results)).decision)

    def test_missing_role_after_deadline_is_review_timeout(self):
        results = dict(inputs().results)
        del results["DATA_TOOL_INSPECTOR"]
        outcome = decide(inputs(results=results, deadline_passed=True))
        self.assertEqual(outcome.decision, Decision.REVIEW)
        self.assertIn("TIMEOUT", outcome.reason_codes)

    def test_exhausted_role_is_worker_missing(self):
        results = dict(inputs().results)
        del results["BEHAVIOR_TESTER"]
        outcome = decide(inputs(results=results, exhausted_roles=frozenset({"BEHAVIOR_TESTER"})))
        self.assertEqual(outcome.reason_codes, ("WORKER_MISSING",))

    def test_incomplete_and_error_never_allow(self):
        for status, code in (("INCOMPLETE", "INSPECTION_INCOMPLETE"), ("ERROR", "INSPECTION_ERROR")):
            results = dict(inputs().results, INSTRUCTION_INSPECTOR=RoleResult(InspectionStatus(status)))
            outcome = decide(inputs(results=results))
            self.assertEqual(outcome.decision, Decision.REVIEW)
            self.assertIn(code, outcome.reason_codes)

    def test_suspicion_is_review_not_quarantine(self):
        results = dict(inputs().results, INSTRUCTION_INSPECTOR=RoleResult(InspectionStatus.COMPLETE, frozenset({"OVERRIDE_ATTEMPT"})))
        outcome = decide(inputs(results=results))
        self.assertEqual((outcome.decision, outcome.reason_codes), (Decision.REVIEW, ("SUSPICIOUS_UNCORROBORATED",)))

    def test_verified_forbidden_action_quarantines_even_if_pending(self):
        outcome = decide(inputs(results={}, verified_forbidden_action=True))
        self.assertEqual(outcome.decision, Decision.QUARANTINE)

    def test_extraction_problems_review_before_inspection(self):
        for kwargs, code in (
            ({"extraction_statuses": ["INCOMPLETE"]}, "EXTRACTION_INCOMPLETE"),
            ({"extraction_statuses": ["ERROR"]}, "EXTRACTION_ERROR"),
            ({"unsupported_relevant": True}, "UNSUPPORTED_CONTENT"),
            ({"extraction_limit_exceeded": True}, "LIMIT_EXCEEDED"),
            ({"extraction_statuses": []}, "EXTRACTION_INCOMPLETE"),
        ):
            outcome = decide(inputs(results={}, **kwargs))
            self.assertEqual(outcome.decision, Decision.REVIEW, kwargs)
            self.assertIn(code, outcome.reason_codes)

    def test_missing_task_output_and_answer_mismatch(self):
        results = dict(inputs().results, BEHAVIOR_TESTER=RoleResult(InspectionStatus.COMPLETE))
        self.assertIn("TASK_OUTPUT_MISSING", decide(inputs(results=results)).reason_codes)
        results = dict(inputs().results, BEHAVIOR_TESTER=RoleResult(InspectionStatus.COMPLETE, has_task_output=True, answer_mismatch=True))
        self.assertIn("ANSWER_MISMATCH", decide(inputs(results=results)).reason_codes)

    def test_review_exception_eligibility(self):
        self.assertTrue(review_exception_eligible("REVIEW", ["SUSPICIOUS_UNCORROBORATED"]))
        self.assertFalse(review_exception_eligible("REVIEW", ["SUSPICIOUS_UNCORROBORATED", "TIMEOUT"]))
        self.assertFalse(review_exception_eligible("REVIEW", ["INSPECTION_INCOMPLETE"]))
        self.assertFalse(review_exception_eligible("QUARANTINE", ["SUSPICIOUS_UNCORROBORATED"]))
        self.assertFalse(review_exception_eligible("REVIEW", []))


if __name__ == "__main__":
    unittest.main()
