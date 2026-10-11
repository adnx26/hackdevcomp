import unittest

from harness import evaluate, MODES


MANIFEST = {"contract_version": "v1", "versions": {"adapter": "test", "worker": "double"},
            "model_configuration": {"model": "deterministic_double"}, "attack_budget": {"attempts": 3},
            "coverage": ["held_out", "adaptive"], "evaluation_kind": "deterministic", "dataset_id": "unit"}
CASES = [{"id": "invoice", "kind": "benign"}, {"id": "injection", "kind": "attack"}]


class EvaluationTests(unittest.TestCase):
    def test_matched_comparisons_and_separate_metrics(self):
        calls = []

        def runner(case, mode, repeat, budget):
            calls.append((case["id"], mode, repeat, budget))
            return {"decision": "ALLOW_UNDER_POLICY" if case["kind"] == "benign" else "REVIEW",
                    "attack_succeeded": False if case["kind"] == "attack" else None,
                    "task_completed": case["kind"] == "benign", "latency_ms": 100 + 100 * repeat,
                    "cost_usd": "0.001"}

        report = evaluate(runner, CASES, repeats=2, manifest=MANIFEST)
        self.assertEqual(len(calls), 12)
        for mode in MODES:
            metrics = report["metrics"][mode]
            self.assertEqual(metrics["attack_success_rate"], 0)
            self.assertEqual(metrics["legitimate_completion_rate"], 1)
            self.assertEqual(metrics["pending_reviews"], 2)
            self.assertEqual(metrics["cost_usd"], "0.004")
            self.assertEqual(metrics["latency_p50_ms"], 150)
            self.assertEqual(metrics["latency_p95_ms"], 200)
            self.assertEqual({(c[0], c[2]) for c in calls if c[1] == mode},
                             {("invoice", 0), ("invoice", 1), ("injection", 0), ("injection", 1)})

    def test_missing_objectives_are_inconclusive_not_secure(self):
        report = evaluate(lambda *args: {"decision": "ALLOW_UNDER_POLICY"}, CASES, repeats=1, manifest=MANIFEST)
        for metrics in report["metrics"].values():
            self.assertIsNone(metrics["attack_success_rate"])
            self.assertIsNone(metrics["legitimate_completion_rate"])
            self.assertEqual(metrics["inconclusive_objectives"], 2)
            self.assertIsNone(metrics["cost_usd"])

    def test_exception_is_failure_without_content_leak(self):
        def broken(*args):
            raise RuntimeError("private source text")
        report = evaluate(broken, CASES, repeats=1, manifest=MANIFEST)
        self.assertNotIn("private source text", str(report))
        self.assertTrue(all(m["failures"] == 2 for m in report["metrics"].values()))

    def test_quarantine_alone_does_not_establish_attack_success(self):
        report = evaluate(lambda *args: {"decision": "QUARANTINE", "attack_succeeded": True,
                                       "task_completed": False}, CASES, repeats=1, manifest=MANIFEST)
        for metrics in report["metrics"].values():
            self.assertEqual(metrics["attack_success_rate"], 1)
            self.assertEqual(metrics["false_blocks"], 1)

    def test_invalid_measurement_does_not_poison_report(self):
        for observation in ({"latency_ms": float('nan')}, {"cost_usd": "NaN"},
                            {"cost_usd": 0.1}, {"attack_succeeded": "false"}):
            report = evaluate(lambda *args: observation, CASES, repeats=1, manifest=MANIFEST)
            self.assertTrue(all(m["failures"] == 2 for m in report["metrics"].values()))

    def test_required_reproducibility_manifest(self):
        with self.assertRaises(ValueError):
            evaluate(lambda *args: {}, CASES, repeats=1, manifest={})

    def test_adaptive_runner_mutations_cannot_change_later_comparisons(self):
        import copy
        cases, manifest = copy.deepcopy(CASES), copy.deepcopy(MANIFEST)
        seen = []

        def runner(case, mode, repeat, budget):
            seen.append((case["id"], budget["attempts"]))
            case["id"] = "mutated"
            budget["attempts"] = 0
            return {}

        report = evaluate(runner, cases, repeats=2, manifest=manifest)
        self.assertEqual(seen, [("invoice", 3)] * 6 + [("injection", 3)] * 6)
        self.assertEqual(report["manifest"], MANIFEST)
        self.assertEqual(report["case_ids"], ["invoice", "injection"])
        self.assertEqual(cases, CASES)
        self.assertEqual(manifest, MANIFEST)


if __name__ == "__main__":
    unittest.main()
