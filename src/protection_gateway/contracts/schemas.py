"""Canonical v1 message schemas.

Public request bodies, runtime messages (extraction, inspection, collector)
and task outputs. Validators return a normalized copy and raise
ContractError (INVALID_REQUEST) on any unexpected or malformed field.
"""

from __future__ import annotations

import re
from typing import Any

from . import validation as v
from .enums import (
    CONTRACT_VERSION,
    CollectorOutcome,
    ExtractionStatus,
    FindingCategory,
    InspectionStatus,
    PolicyCheck,
    ReviewAction,
    WorkerRole,
)
from .policies import INVOICE_FIELDS, OUTPUT_INVOICE, OUTPUT_SUMMARY, POLICIES, SIMULATED_SEND_OPERATION

SUPPORTED_MEDIA_TYPES = frozenset({"text/plain", "text/html", "message/rfc822"})

EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")
DECIMAL_PATTERN = re.compile(r"^-?\d{1,15}(\.\d{1,6})?$")
CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")

version = v.literal(CONTRACT_VERSION)

# --- shared pieces -------------------------------------------------------

worker_identity = v.obj(
    {
        "worker_id": v.opaque_id,
        "role": v.enum(WorkerRole.values()),
        "build_version": v.string(min_len=1, max_len=64),
        "prompt_version": v.string(min_len=1, max_len=64),
    }
)

policy_binding = v.obj(
    {
        "policy_id": v.enum(POLICIES.keys()),
        "policy_version": v.string(min_len=1, max_len=16),
        "policy_hash": v.sha256,
    }
)

span = v.obj({"start": v.integer(), "end": v.integer()})

# Source references: resource ID, view hash and a half-open Unicode
# code-point span in that exact hashed view.
source_ref = v.obj(
    {"resource_id": v.opaque_id, "view_hash": v.sha256, "start": v.integer(), "end": v.integer()}
)

limits = v.obj(
    {
        "max_findings": v.integer(minimum=0, maximum=1000),
        "max_artifacts": v.integer(minimum=0, maximum=100),
        "max_artifact_chars": v.integer(minimum=0, maximum=100_000),
        "model_token_budget": v.integer(minimum=0, maximum=10_000_000),
    }
)

# --- public request bodies ----------------------------------------------

resource_upload_request = v.obj(
    {
        "contract_version": version,
        "media_type": v.string(min_len=1, max_len=64),
        "content_base64": v.string(min_len=0, max_len=4_000_000, pattern=BASE64_PATTERN),
    },
    {"filename": v.string(min_len=1, max_len=255)},
)

task_session_request = v.obj(
    {
        "contract_version": version,
        "policy_id": v.enum(POLICIES.keys()),
        "resource_ids": v.list_of(v.opaque_id, min_items=1, max_items=100, unique=True),
    }
)

task_session_update_request = v.obj(
    {
        "contract_version": version,
        "resource_ids": v.list_of(v.opaque_id, min_items=1, max_items=100, unique=True),
    }
)

scan_request = v.obj({"contract_version": version, "task_session_id": v.opaque_id})

empty_request = v.obj({"contract_version": version})

review_request = v.obj(
    {
        "contract_version": version,
        "action": v.enum(ReviewAction.values()),
        "reason": v.string(min_len=1, max_len=500),
    },
    {"result_digest": v.sha256, "expires_in_seconds": v.integer(minimum=60, maximum=86_400)},
)

simulated_send_arguments = v.obj(
    {
        "to": v.string(min_len=3, max_len=254, pattern=EMAIL_PATTERN),
        "subject": v.string(min_len=0, max_len=200),
        "body": v.string(min_len=0, max_len=20_000),
        "attachment_resource_ids": v.list_of(v.opaque_id, max_items=5, unique=True),
    }
)

typed_action = v.obj(
    {"operation": v.literal(SIMULATED_SEND_OPERATION), "arguments": simulated_send_arguments}
)

action_request = v.obj(
    {"contract_version": version, "task_session_id": v.opaque_id, "action": typed_action}
)

confirm_request = v.obj(
    {"contract_version": version, "digest": v.sha256},
    {"recipient_selected_by_user": v.boolean},
)

# --- runtime messages ---------------------------------------------------

extraction_assignment = v.obj(
    {
        "contract_version": version,
        "assignment_id": v.opaque_id,
        "scan_id": v.opaque_id,
        "attempt": v.integer(minimum=1, maximum=10),
        "resource_id": v.opaque_id,
        "original_hash": v.sha256,
        "media_type": v.enum(SUPPORTED_MEDIA_TYPES),
        "limits": v.obj(
            {
                "max_source_bytes": v.integer(minimum=1),
                "max_extracted_chars": v.integer(minimum=1),
            }
        ),
        "deadline": v.timestamp,
    }
)

source_map_segment = v.list_of(v.integer(), min_items=4, max_items=4)

extracted_view = v.obj(
    {
        "view_id": v.opaque_id,
        "kind": v.string(min_len=1, max_len=64),
        "text": v.string(min_len=0, max_len=1_000_000),
        "view_hash": v.sha256,
        # [view_start, view_end, original_start, original_end] segments.
        "source_map": v.list_of(source_map_segment, max_items=100_000),
    }
)

unsupported_part = v.obj(
    {
        "part_id": v.opaque_id,
        "media_type": v.string(min_len=1, max_len=128),
        "task_relevant": v.boolean,
        "reason": v.string(min_len=1, max_len=64),
    }
)

extraction_result = v.obj(
    {
        "contract_version": version,
        "assignment_id": v.opaque_id,
        "resource_id": v.opaque_id,
        "original_hash": v.sha256,
        "extractor_version": v.string(min_len=1, max_len=64),
        "status": v.enum(ExtractionStatus.values()),
        "views": v.list_of(extracted_view, max_items=32),
        "unsupported_parts": v.list_of(unsupported_part, max_items=256),
    }
)

assigned_view = v.obj({"view_id": v.opaque_id, "view_hash": v.sha256, "length": v.integer()})

assigned_resource = v.obj(
    {
        "resource_id": v.opaque_id,
        "original_hash": v.sha256,
        "views": v.list_of(assigned_view, min_items=1, max_items=32),
    }
)

_binding_fields = {
    "assignment_id": v.opaque_id,
    "scan_id": v.opaque_id,
    "attempt": v.integer(minimum=1, maximum=10),
    "worker": worker_identity,
    "task_session_id": v.opaque_id,
    "task_scope_version": v.integer(minimum=1),
    "policy": policy_binding,
    "resource_set_hash": v.sha256,
    "context_hash": v.sha256,
    "model_configuration_hash": v.sha256,
}

inspection_assignment = v.obj(
    {
        "contract_version": version,
        **_binding_fields,
        "resources": v.list_of(assigned_resource, min_items=1, max_items=10),
        "limits": limits,
        "deadline": v.timestamp,
    }
)

checked_view = v.obj({"resource_id": v.opaque_id, "view_id": v.opaque_id, "view_hash": v.sha256})

finding = v.obj(
    {
        "category": v.enum(FindingCategory.values()),
        "resource_id": v.opaque_id,
        "view_hash": v.sha256,
        "evidence_ids": v.list_of(v.opaque_id, max_items=20, unique=True),
    },
    {"span": span},
)

worker_artifact = v.obj(
    {
        "artifact_id": v.opaque_id,
        "kind": v.enum({"EXPLANATION", "EXCERPT", "COMPLETION_REPORT"}),
        "text": v.string(min_len=0, max_len=100_000),
    }
)

_sourced_value = v.obj(
    {"value": v.string(min_len=1, max_len=256), "source_refs": v.list_of(source_ref, min_items=1, max_items=10)}
)
_absent_value = v.obj({"absent": v.literal(True)})

invoice_output = v.obj(
    {
        "kind": v.literal(OUTPUT_INVOICE),
        "fields": v.obj({name: v.one_of(_sourced_value, _absent_value) for name in INVOICE_FIELDS}),
    }
)

summary_output = v.obj(
    {
        "kind": v.literal(OUTPUT_SUMMARY),
        "statements": v.list_of(
            v.obj(
                {
                    "text": v.string(min_len=1, max_len=2000),
                    "source_refs": v.list_of(source_ref, min_items=1, max_items=10),
                }
            ),
            min_items=1,
            max_items=50,
        ),
    }
)

task_output = v.one_of(invoice_output, summary_output)

worker_result = v.obj(
    {
        "contract_version": version,
        **_binding_fields,
        "nonce": v.string(min_len=16, max_len=128, pattern=v.ID_PATTERN),
        "inspection_status": v.enum(InspectionStatus.values()),
        "checked_views": v.list_of(checked_view, max_items=320),
        "findings": v.list_of(finding, max_items=1000),
    },
    {
        "artifacts": v.list_of(worker_artifact, max_items=100),
        # Behavior tester only: collector event IDs observed during the run.
        "telemetry_event_ids": v.list_of(v.opaque_id, max_items=1000, unique=True),
        "coverage_limits": v.list_of(v.string(min_len=1, max_len=64), max_items=32),
        "task_output": task_output,
    },
)

collector_event = v.obj(
    {
        "contract_version": version,
        "event_id": v.opaque_id,
        "scan_id": v.opaque_id,
        # run_id is the behavior tester assignment_id for this scan.
        "run_id": v.opaque_id,
        "sequence": v.integer(minimum=0),
        "operation": v.string(min_len=1, max_len=64, pattern=re.compile(r"^[a-z_]{1,64}$")),
        "argument_digest": v.sha256,
        "attempted_outcome": v.enum(CollectorOutcome.values()),
        "policy_check": v.enum(PolicyCheck.values()),
        "timestamp": v.timestamp,
    }
)

collector_identity = v.obj({"collector_id": v.opaque_id})


def validate(checker: v.Checker, value: Any, name: str = "$") -> Any:
    return checker(value, name)


def validate_invoice_values(output: dict) -> None:
    """Typed checks on invoice values beyond shape."""
    from .errors import ContractError

    fields = output["fields"]
    checks = {"amount": DECIMAL_PATTERN, "currency": CURRENCY_PATTERN, "due_date": DATE_PATTERN}
    for name, pattern in checks.items():
        field = fields[name]
        if "value" in field and not pattern.match(field["value"]):
            raise ContractError(f"$.task_output.fields.{name}.value", "invalid typed value")
