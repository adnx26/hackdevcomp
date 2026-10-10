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
