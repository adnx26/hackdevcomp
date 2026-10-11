"""Release gate: requires A/B/C's actual configured gateway + SLIM driver."""

import importlib
import json
import os
from pathlib import Path
import unittest


class FullStackGate(unittest.TestCase):
    def test_reviewed_workflows_over_real_slim(self):
        factory_path = os.environ.get("GATEWAY_FULL_STACK_FACTORY")
        required = os.environ.get("GATEWAY_REQUIRE_FULL_STACK") == "1"
        if not factory_path:
            if required:
                self.fail("Legacy reviewed-scenario release gate requires GATEWAY_FULL_STACK_FACTORY")
            self.skipTest("Legacy reviewed-scenario driver is not configured; actual local stack is tested by test_gateway_e2e.py")
        module, name = factory_path.split(":", 1)
        scenarios = json.loads((Path(__file__).parents[1] / "fixtures/workflow/scenarios.json").read_text())
        # A/C must review and record expectations before release; no local
        # transport double or changed expected outcome can replace their review.
        self.assertTrue({"A", "C"} <= set(scenarios["expectations_reviewed_by"]),
                        "Workflow expectations still need A/C review")
        driver = getattr(importlib.import_module(module), name)()
        try:
            self.assertEqual(driver.transport, "SLIM")
            self.assertFalse(driver.uses_test_transport)
            for scenario in scenarios["scenarios"]:
                with self.subTest(scenario=scenario["id"]):
                    observation = driver.run_scenario(scenario["id"])
                    self.assertTrue(observation["runtime_event_ids"], "Actual runtime evidence required")
                    self.assertTrue(observation["versions"], "Record combined component versions")
                    for check in scenario["checks"]:
                        self.assertIs(observation["checks"][check], True, check)
                    if "expected_decision" in scenario:
                        self.assertEqual(observation["decision"], scenario["expected_decision"])
        finally:
            driver.close()

    def test_native_account_smoke(self):
        factory_path = os.environ.get("GATEWAY_NATIVE_SMOKE_FACTORY")
        if not factory_path:
            if os.environ.get("GATEWAY_REQUIRE_FULL_STACK") == "1":
                self.fail("Release gate requires an actual supported Claude/ChatGPT account smoke driver")
            self.skipTest("Native connector account/workspace is not configured; not a release pass")
        module, name = factory_path.split(":", 1)
        driver = getattr(importlib.import_module(module), name)()
        try:
            observation = driver.run()
            self.assertTrue(observation["account_configuration_id"])
            self.assertEqual(set(observation["tool_names"]),
                             {"inspect_resource", "get_scan_status", "get_inspected_result"})
            self.assertIs(observation["authenticated_connection"], True)
            self.assertIs(observation["coverage_visible"], True)
            self.assertIs(observation["unauthorized_access_denied"], True)
        finally:
            driver.close()


if __name__ == "__main__":
    unittest.main()
