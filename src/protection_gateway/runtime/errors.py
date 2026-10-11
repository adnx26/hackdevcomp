"""Runtime failure types. Neither ever maps to a successful result."""


class RuntimeUnavailable(Exception):
    """A required runtime capability is missing or could not be verified."""

    code = "SERVICE_UNAVAILABLE"

    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


class Rejected(Exception):
    """A request or message failed an identity, binding, scope or budget check."""

    def __init__(self, reason_code: str, status: int = 403):
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.status = status
