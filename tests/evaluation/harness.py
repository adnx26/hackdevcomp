"""Offline comparison only. Never imported by production endpoint code."""

import copy
import math
from decimal import Decimal


MODES = ("enforcement_only", "one_inspector", "three_worker_pool")


def percentile(values, fraction):
    if not values:
        return None
    values = sorted(values)
    index = (len(values) - 1) * fraction
    lower, upper = math.floor(index), math.ceil(index)
    return values[lower] + (values[upper] - values[lower]) * (index - lower)


def evaluate(runner, cases, *, repeats, manifest):
    """runner(case, mode, repeat, attack_budget) -> instrumented observation.

    Success is measured from the objective, never inferred from a clean verdict.
    Missing measurements stay inconclusive; exceptions contribute to failures.
    A repeat index is the shared seed across all modes.
    """
    required = {"contract_version", "versions", "model_configuration", "attack_budget",
                "coverage", "evaluation_kind", "dataset_id"}
    if not required <= set(manifest) or manifest["contract_version"] != "v1":
        raise ValueError("A complete v1 evaluation manifest is required")
    if manifest["evaluation_kind"] not in {"deterministic", "live"}:
        raise ValueError("Separate deterministic and live reports")
    if not isinstance(repeats, int) or isinstance(repeats, bool) or repeats < 1:
        raise ValueError("Positive repeat count required")
    if not cases or len({c["id"] for c in cases}) != len(cases):
        raise ValueError("Nonempty unique cases required")
    if any(c.get("kind") not in {"benign", "attack"} for c in cases):
        raise ValueError("Cases need an objective category")
    # Adaptive runners can mutate their scratch inputs. Each comparison receives
    # the same original case/budget and the exported provenance stays immutable.
    manifest = copy.deepcopy(manifest)
    cases = copy.deepcopy(cases)
    records = []
    for case in cases:
        for repeat in range(repeats):
            for mode in MODES:
                record = {"case_id": case["id"], "kind": case["kind"],
                          "mode": mode, "repeat": repeat, "decision": None,
                          "attack_succeeded": None, "task_completed": None,
                          "latency_ms": None, "cost_usd": None, "failed": False}
                try:
                    observed = runner(copy.deepcopy(case), mode, repeat, copy.deepcopy(manifest["attack_budget"]))
                    if not isinstance(observed, dict):
                        raise ValueError("Observation required")
                    decision = observed.get("decision")
                    if decision not in {None, "ALLOW_UNDER_POLICY", "REVIEW", "QUARANTINE"}:
                        raise ValueError("Unknown decision")
                    record["decision"] = decision
                    for key in ("attack_succeeded", "task_completed"):
                        value = observed.get(key)
                        if value is not None and type(value) is not bool:
                            raise ValueError("Objective measurements must be booleans")
                        record[key] = value
                    latency = observed.get("latency_ms")
                    if latency is not None:
                        if isinstance(latency, bool) or not isinstance(latency, (float, int)) or not math.isfinite(latency) or latency < 0:
                            raise ValueError("Invalid latency")
                        record["latency_ms"] = latency
                    cost = observed.get("cost_usd")
                    if cost is not None:
                        if not isinstance(cost, str):
                            raise ValueError("Cost uses decimal strings")
                        decimal_cost = Decimal(cost)
                        if not decimal_cost.is_finite() or decimal_cost < 0:
                            raise ValueError("Invalid cost")
                        record["cost_usd"] = cost
                    record["failed"] = observed.get("failed") is True
                except Exception:
                    # No content or exception message is included in reports.
                    record.update(failed=True, attack_succeeded=None, task_completed=None,
                                  latency_ms=None, cost_usd=None, decision=None)
                records.append(record)
    metrics = {}
    for mode in MODES:
        rows = [r for r in records if r["mode"] == mode]
        attacks = [r for r in rows if r["kind"] == "attack"]
        benign = [r for r in rows if r["kind"] == "benign"]
        measured_attacks = [r for r in attacks if r["attack_succeeded"] is not None and not r["failed"]]
        measured_benign = [r for r in benign if r["task_completed"] is not None and not r["failed"]]
        successes = sum(r["attack_succeeded"] is True for r in measured_attacks)
        completed = sum(r["task_completed"] is True for r in measured_benign)
        latencies = [r["latency_ms"] for r in rows if r["latency_ms"] is not None]
        costs = [Decimal(r["cost_usd"]) for r in rows if r["cost_usd"] is not None]
        metrics[mode] = {
            "runs": len(rows), "attack_successes": successes,
            "measured_attack_runs": len(measured_attacks),
            "attack_success_rate": successes / len(measured_attacks) if measured_attacks else None,
            "legitimate_task_completions": completed, "measured_benign_runs": len(measured_benign),
            "legitimate_completion_rate": completed / len(measured_benign) if measured_benign else None,
            "false_blocks": sum(r["decision"] == "QUARANTINE" and not r["failed"] for r in benign),
            "pending_reviews": sum(r["decision"] == "REVIEW" and not r["failed"] for r in rows),
            "failures": sum(r["failed"] for r in rows),
            "inconclusive_objectives": sum(r["attack_succeeded" if r["kind"] == "attack" else "task_completed"] is None for r in rows),
            "latency_p50_ms": percentile(latencies, .50), "latency_p95_ms": percentile(latencies, .95),
            "latency_measured_runs": len(latencies), "cost_usd": str(sum(costs, Decimal(0))) if costs else None,
            "cost_measured_runs": len(costs),
        }
    return {"manifest": manifest, "case_ids": [c["id"] for c in cases],
            "repeats": repeats, "metrics": metrics, "records": records}
