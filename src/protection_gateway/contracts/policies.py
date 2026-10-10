"""Fixed v1 task policies.

Task classification may suggest one of these; only an authorized user
selection binds it to a task session. Content can never add an operation.
"""

from __future__ import annotations

from dataclasses import dataclass

from .canonical import canonical_digest

# Operation names used by the gateway action gate and by B's simulated-tool
# collector. Anything not listed as permitted for a policy is forbidden.
KNOWN_OPERATIONS = frozenset(
    {
        "read_selected",
        "send_email",
        "modify_email",
        "delete_email",
        "export_data",
        "fetch_url",
        "make_payment",
        "change_bank_details",
    }
)

SIMULATED_SEND_OPERATION = "simulated_send_email"

OUTPUT_SUMMARY = "summary"
OUTPUT_INVOICE = "invoice"

INVOICE_FIELDS = ("invoice_id", "amount", "currency", "due_date")


@dataclass(frozen=True)
class TaskPolicy:
    policy_id: str
    version: str
    output_kind: str
    permitted_operations: frozenset[str]
    permits_simulated_send: bool
    read_only: bool

    def as_canonical(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "output_kind": self.output_kind,
            "permitted_operations": sorted(self.permitted_operations),
            "permits_simulated_send": self.permits_simulated_send,
            "read_only": self.read_only,
        }

    @property
    def policy_hash(self) -> str:
        return canonical_digest(self.as_canonical())

    def operation_permitted(self, operation: str) -> bool:
        return operation in self.permitted_operations

    def binding(self) -> dict:
        return {"policy_id": self.policy_id, "policy_version": self.version, "policy_hash": self.policy_hash}


POLICIES: dict[str, TaskPolicy] = {
    "summarize_email": TaskPolicy(
        policy_id="summarize_email",
        version="1",
        output_kind=OUTPUT_SUMMARY,
        permitted_operations=frozenset({"read_selected"}),
        permits_simulated_send=False,
        read_only=True,
    ),
    "extract_invoice": TaskPolicy(
        policy_id="extract_invoice",
        version="1",
        output_kind=OUTPUT_INVOICE,
        permitted_operations=frozenset({"read_selected"}),
        permits_simulated_send=False,
        read_only=True,
    ),
    "simulate_send": TaskPolicy(
        policy_id="simulate_send",
        version="1",
        output_kind=OUTPUT_SUMMARY,
        # Inside the sandbox the behavior tester may attempt a dummy send;
        # in the gateway it still needs an exact user confirmation.
        permitted_operations=frozenset({"read_selected", "send_email"}),
        permits_simulated_send=True,
        read_only=False,
    ),
}


def get_policy(policy_id: str) -> TaskPolicy | None:
    return POLICIES.get(policy_id)
