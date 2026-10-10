"""Runtime callbacks the core consumes, provided by B via dependency injection.

The core never imports B, C or D. With no runtime injected, extraction and
dispatch return SERVICE_UNAVAILABLE and no content is released.
"""

from __future__ import annotations

from typing import Mapping, Protocol, Sequence


class RuntimeUnavailable(Exception):
    """Raised by a runtime callback when it cannot perform the request."""


class RuntimeCallbacks(Protocol):
    def extract(self, extraction_assignment: Mapping) -> Mapping:
        """Run C's extractor under B's restrictions; return an extraction_result.

        B provisions the extractor's resource capability privately by calling
        ``GatewayService.issue_job_capability(assignment_id)``; the extractor
        reads through ``GatewayService.read_assigned_original``.
        """

    def dispatch(self, inspection_assignments: Sequence[Mapping]) -> Sequence[Mapping]:
        """Deliver assignments over SLIM. Return receipts
        ``{"assignment_id": str, "delivered": bool}``. Delivery is not completion.
        B provisions each worker's capability privately through
        ``GatewayService.issue_job_capability``; it never travels in the
        assignment message.
        """

    def cancel(self, scan_id: str) -> None:
        """Revoke runtime capabilities and terminate the scan's process groups."""


class ActionExecutor(Protocol):
    """Executes a confirmed action. The v1 executor touches dummy state only."""

    def execute(self, conn, action: Mapping) -> tuple[str, str | None]:
        """Return (ExecutionOutcome value, effect_id). Runs inside the
        gateway's write transaction so simulated effects are atomic with the
        approval being consumed. A future provider returns UNKNOWN on an
        ambiguous response, which moves the action to UNKNOWN_OUTCOME.
        """
