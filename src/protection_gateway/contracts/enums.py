"""Canonical v1 enumerations shared by every owner.

Do not rename or extend these values in a teammate PR; propose changes in
docs/system-design.md section 15 first.
"""

from __future__ import annotations

from enum import Enum

CONTRACT_VERSION = "v1"


class _StrEnum(str, Enum):
    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value

    @classmethod
    def values(cls) -> frozenset[str]:
        return frozenset(member.value for member in cls)


class JobState(_StrEnum):
    QUEUED = "QUEUED"
    EXTRACTING = "EXTRACTING"
    INSPECTING = "INSPECTING"
    DECIDED = "DECIDED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"


ACTIVE_JOB_STATES = frozenset({JobState.QUEUED, JobState.EXTRACTING, JobState.INSPECTING})
TERMINAL_JOB_STATES = frozenset({JobState.DECIDED, JobState.FAILED, JobState.CANCELED})


class Decision(_StrEnum):
    ALLOW_UNDER_POLICY = "ALLOW_UNDER_POLICY"
    REVIEW = "REVIEW"
    QUARANTINE = "QUARANTINE"


class ActionState(_StrEnum):
    PROPOSED = "PROPOSED"
    CONFIRMED = "CONFIRMED"
    EXECUTED = "EXECUTED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELED = "CANCELED"
    # Reserved for an ambiguous external-provider outcome. The simulated
    # executor never produces it.
    UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"


class ErrorCode(_StrEnum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    INVALID_REQUEST = "INVALID_REQUEST"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    NOT_READY = "NOT_READY"
    CONTEXT_CHANGED = "CONTEXT_CHANGED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


class FindingCategory(_StrEnum):
    OVERRIDE_ATTEMPT = "OVERRIDE_ATTEMPT"
    HIDDEN_INSTRUCTIONS = "HIDDEN_INSTRUCTIONS"
    DISCLOSURE_REQUEST = "DISCLOSURE_REQUEST"
    UNAUTHORIZED_TOOL_REQUEST = "UNAUTHORIZED_TOOL_REQUEST"
    OBSERVED_FORBIDDEN_ACTION = "OBSERVED_FORBIDDEN_ACTION"
    ANSWER_MISMATCH = "ANSWER_MISMATCH"


class InspectionStatus(_StrEnum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    ERROR = "ERROR"


class ExtractionStatus(_StrEnum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    ERROR = "ERROR"


class StorageState(_StrEnum):
    STORED = "STORED"


class ReviewAction(_StrEnum):
    REJECT = "REJECT"
    ALLOW_READ_ONLY = "ALLOW_READ_ONLY"


class WorkerRole(_StrEnum):
    """Fixed roster roles. EXTRACTOR is not an inspection check."""

    EXTRACTOR = "EXTRACTOR"
    INSTRUCTION_INSPECTOR = "INSTRUCTION_INSPECTOR"
    DATA_TOOL_INSPECTOR = "DATA_TOOL_INSPECTOR"
    BEHAVIOR_TESTER = "BEHAVIOR_TESTER"


INSPECTION_ROLES = (
    WorkerRole.INSTRUCTION_INSPECTOR,
    WorkerRole.DATA_TOOL_INSPECTOR,
    WorkerRole.BEHAVIOR_TESTER,
)


class CollectorOutcome(_StrEnum):
    """Whether the collector performed the dummy effect or denied it."""

    ALLOWED = "ALLOWED"
    DENIED = "DENIED"


class PolicyCheck(_StrEnum):
    PERMITTED = "PERMITTED"
    FORBIDDEN = "FORBIDDEN"


class ReasonCode(_StrEnum):
    """Bounded public reason codes. Never carry source or model text."""

    EXTRACTION_INCOMPLETE = "EXTRACTION_INCOMPLETE"
    EXTRACTION_ERROR = "EXTRACTION_ERROR"
    UNSUPPORTED_CONTENT = "UNSUPPORTED_CONTENT"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    INSPECTION_INCOMPLETE = "INSPECTION_INCOMPLETE"
    INSPECTION_ERROR = "INSPECTION_ERROR"
    WORKER_MISSING = "WORKER_MISSING"
    TIMEOUT = "TIMEOUT"
    SUSPICIOUS_UNCORROBORATED = "SUSPICIOUS_UNCORROBORATED"
    ANSWER_MISMATCH = "ANSWER_MISMATCH"
    TASK_OUTPUT_MISSING = "TASK_OUTPUT_MISSING"
    VERIFIED_FORBIDDEN_ACTION = "VERIFIED_FORBIDDEN_ACTION"
    RUNTIME_UNAVAILABLE = "RUNTIME_UNAVAILABLE"
    INTERRUPTED = "INTERRUPTED"
    CANCELED_BY_USER = "CANCELED_BY_USER"
    REJECTED_BY_USER = "REJECTED_BY_USER"
    RESOURCE_DELETED = "RESOURCE_DELETED"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    EMERGENCY_STOP = "EMERGENCY_STOP"


# A recorded read-only review exception is eligible only when every
# remaining reason is uncorroborated suspicion.
REVIEW_EXCEPTION_ELIGIBLE_REASONS = frozenset({ReasonCode.SUSPICIOUS_UNCORROBORATED})


class Channel(_StrEnum):
    """Server-derived request channel. Never accepted from request JSON."""

    USER_INTERFACE = "USER_INTERFACE"  # cookie session + CSRF, user-owned
    API = "API"  # bearer token for the controlled API workflow
    MCP = "MCP"  # read-only connector
    ASSISTANT = "ASSISTANT"  # in-process controlled chat adapter acting for a user


class Disclosure(_StrEnum):
    PRIVATE_TO_OWNER = "PRIVATE_TO_OWNER"


class RecipientTrust(_StrEnum):
    TRUSTED_CONTACT = "TRUSTED_CONTACT"
    UNTRUSTED = "UNTRUSTED"


class ExecutionOutcome(_StrEnum):
    SUCCEEDED = "SUCCEEDED"
    NOT_DELIVERED = "NOT_DELIVERED"
    UNKNOWN = "UNKNOWN"
