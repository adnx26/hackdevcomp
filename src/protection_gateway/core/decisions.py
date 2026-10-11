"""The master decision table as a pure function.

No worker, majority vote, confidence score or source text overrides it.
Errors are never counted as a blocked attack or a successful inspection.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..contracts.enums import (
    REVIEW_EXCEPTION_ELIGIBLE_REASONS,
    Decision,
    ExtractionStatus,
    FindingCategory,
    InspectionStatus,
    ReasonCode,
    WorkerRole,
)

SUSPICION_CATEGORIES = frozenset(
    {
        FindingCategory.OVERRIDE_ATTEMPT,
        FindingCategory.HIDDEN_INSTRUCTIONS,
        FindingCategory.DISCLOSURE_REQUEST,
        FindingCategory.UNAUTHORIZED_TOOL_REQUEST,
        # Accepted only with a verified collector reference, and the
        # collector event itself drives QUARANTINE. Listed here so that a
        # finding without a matching quarantine still withholds content.
        FindingCategory.OBSERVED_FORBIDDEN_ACTION,
    }
)


@dataclass(frozen=True)
class RoleResult:
    status: InspectionStatus
    categories: frozenset[str] = frozenset()
    has_task_output: bool = False
    answer_mismatch: bool = False
    # Authoritative collector events for this run that the worker's
    # telemetry report omitted.
    contradicts_telemetry: bool = False


@dataclass
class DecisionInputs:
    extraction_statuses: list[str]
    unsupported_relevant: bool
    extraction_limit_exceeded: bool
    required_roles: tuple[str, ...]
    results: dict[str, RoleResult]
    # Roles that can no longer produce a result (retries exhausted).
    exhausted_roles: frozenset[str] = frozenset()
    deadline_passed: bool = False
    verified_forbidden_action: bool = False


@dataclass(frozen=True)
class DecisionOutcome:
    decision: Decision | None  # None means still pending
    reason_codes: tuple[str, ...] = field(default_factory=tuple)


def decide(inputs: DecisionInputs) -> DecisionOutcome:
    # 1. Verified deterministic violation from authoritative telemetry.
    if inputs.verified_forbidden_action:
        return DecisionOutcome(Decision.QUARANTINE, (ReasonCode.VERIFIED_FORBIDDEN_ACTION.value,))

    # 2. Extraction coverage gates everything else.
    reasons: list[str] = []
    if any(s == ExtractionStatus.ERROR for s in inputs.extraction_statuses):
        reasons.append(ReasonCode.EXTRACTION_ERROR.value)
    if any(s == ExtractionStatus.INCOMPLETE for s in inputs.extraction_statuses):
        reasons.append(ReasonCode.EXTRACTION_INCOMPLETE.value)
    if inputs.unsupported_relevant:
        reasons.append(ReasonCode.UNSUPPORTED_CONTENT.value)
    if inputs.extraction_limit_exceeded:
        reasons.append(ReasonCode.LIMIT_EXCEEDED.value)
    if not inputs.extraction_statuses:
        reasons.append(ReasonCode.EXTRACTION_INCOMPLETE.value)
    if reasons:
        return DecisionOutcome(Decision.REVIEW, tuple(dict.fromkeys(reasons)))

    # 3. Wait for every required check unless it can no longer arrive.
    pending = [
        role
        for role in inputs.required_roles
        if role not in inputs.results and role not in inputs.exhausted_roles
    ]
    if pending and not inputs.deadline_passed:
        return DecisionOutcome(None)

    for role in inputs.required_roles:
        result = inputs.results.get(role)
        if result is None:
            reasons.append(
                ReasonCode.TIMEOUT.value if inputs.deadline_passed and role not in inputs.exhausted_roles
                else ReasonCode.WORKER_MISSING.value
            )
            continue
        if result.status == InspectionStatus.INCOMPLETE:
            reasons.append(ReasonCode.INSPECTION_INCOMPLETE.value)
        elif result.status == InspectionStatus.ERROR:
            reasons.append(ReasonCode.INSPECTION_ERROR.value)
        if result.categories & SUSPICION_CATEGORIES:
            reasons.append(ReasonCode.SUSPICIOUS_UNCORROBORATED.value)
        if FindingCategory.ANSWER_MISMATCH in result.categories or result.answer_mismatch:
            reasons.append(ReasonCode.ANSWER_MISMATCH.value)
        if result.contradicts_telemetry:
            reasons.append(ReasonCode.CONTRADICTORY_EVIDENCE.value)

    behavior = inputs.results.get(WorkerRole.BEHAVIOR_TESTER.value)
    if behavior is not None and behavior.status == InspectionStatus.COMPLETE and not behavior.has_task_output:
        reasons.append(ReasonCode.TASK_OUTPUT_MISSING.value)

    if reasons:
        return DecisionOutcome(Decision.REVIEW, tuple(dict.fromkeys(reasons)))
    return DecisionOutcome(Decision.ALLOW_UNDER_POLICY, ())


def review_exception_eligible(decision: str | None, reason_codes: list[str] | tuple[str, ...]) -> bool:
    return (
        decision == Decision.REVIEW
        and bool(reason_codes)
        and set(reason_codes) <= {r.value for r in REVIEW_EXCEPTION_ELIGIBLE_REASONS}
    )


# The decision table in evaluation order, for the public decision trace. Each
# row names the reason codes that make it fire. Descriptions are fixed text;
# no model output or source text ever appears in a trace.
DECISION_RULES = (
    ("collector_forbidden_action", Decision.QUARANTINE.value, frozenset({ReasonCode.VERIFIED_FORBIDDEN_ACTION.value}),
     "The gateway's own tool collector recorded a forbidden operation during the sandboxed task run. A deterministic rule quarantines the source."),
    ("extraction_coverage", Decision.REVIEW.value,
     frozenset({ReasonCode.EXTRACTION_INCOMPLETE.value, ReasonCode.EXTRACTION_ERROR.value, ReasonCode.UNSUPPORTED_CONTENT.value, ReasonCode.LIMIT_EXCEEDED.value}),
     "Not all task-relevant content could be extracted. Uninspected content is never approved."),
    ("inspection_completeness", Decision.REVIEW.value,
     frozenset({ReasonCode.INSPECTION_INCOMPLETE.value, ReasonCode.INSPECTION_ERROR.value, ReasonCode.WORKER_MISSING.value, ReasonCode.TIMEOUT.value}),
     "A required inspector failed, timed out or did not return. A failure never counts as a clean result."),
    ("uncorroborated_suspicion", Decision.REVIEW.value, frozenset({ReasonCode.SUSPICIOUS_UNCORROBORATED.value}),
     "An inspector flagged suspicious content without deterministic corroboration. The source is held for user review."),
    ("answer_integrity", Decision.REVIEW.value,
     frozenset({ReasonCode.ANSWER_MISMATCH.value, ReasonCode.TASK_OUTPUT_MISSING.value, ReasonCode.CONTRADICTORY_EVIDENCE.value}),
     "The task result could not be verified against its cited source, or the evidence records conflict."),
    ("all_checks_passed", Decision.ALLOW_UNDER_POLICY.value, frozenset(),
     "Extraction and every required inspection completed with no violation or unresolved suspicion. The result is released under the task policy only."),
)

TERMINAL_RULE_TEXT = {
    "FAILED": "A required gateway service failed, so the scan ended without a decision. Nothing is released.",
    "CANCELED": "The scan was canceled or rejected before release. Nothing is released.",
}


def decision_trace(state: str, decision: str | None, reason_codes) -> dict | None:
    """Which rule of the decision table produced this outcome, and which did not."""
    reasons = set(reason_codes or ())
    if state in TERMINAL_RULE_TEXT:
        return {"deciding_rule": "terminated", "decision": None, "description": TERMINAL_RULE_TEXT[state],
                "reason_codes": sorted(reasons), "rules": []}
    if decision is None:
        return None
    rules, deciding = [], None
    for rule_id, outcome, codes, description in DECISION_RULES:
        matched = sorted(reasons & codes)
        fired = bool(matched) if codes else decision == Decision.ALLOW_UNDER_POLICY.value
        if fired and deciding is None and outcome == decision:
            deciding = rule_id
        rules.append({"rule": rule_id, "outcome": outcome, "fired": fired, "reason_codes": matched, "description": description})
    return {"deciding_rule": deciding, "decision": decision,
            "description": next((r["description"] for r in rules if r["rule"] == deciding), ""),
            "reason_codes": sorted(reasons), "rules": rules}


def disagreement_summary(verdicts: dict[str, str]) -> dict:
    """Disagreement among inspectors that reached a verdict: FLAGGED vs CLEAN vs FAILED.

    PENDING (still running) and STOPPED (canceled because the scan ended first)
    are not verdicts and are not counted.
    """
    finished = {role: v for role, v in verdicts.items() if v not in ("PENDING", "STOPPED")}
    counts = {key: sum(v == key for v in finished.values()) for key in ("FLAGGED", "CLEAN", "FAILED")}
    return {"disagree": len(set(finished.values())) > 1, "verdicts": dict(verdicts), **{k.lower(): n for k, n in counts.items()}}
