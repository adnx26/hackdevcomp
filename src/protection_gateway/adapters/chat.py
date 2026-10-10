"""Deterministic controlled workflow; optional planner has references only."""

from .boundary import AdapterError, bounded_json, core_call, exact_fields, opaque_id, resolve


class ChatAdapter:
    def __init__(self, core, model_client_factory=None):
        self.core = core
        self.model_client_factory = model_client_factory

    async def handle(self, context, request):
        exact_fields(request, ("contract_version", "scan_id"))
        if request["contract_version"] != "v1":
            raise AdapterError("INVALID_REQUEST")
        scan_id = opaque_id(request["scan_id"])
        # This public core call rechecks user, tenant, context, expiry and release.
        result = await core_call(self.core, "get_inspected_result", context, {"scan_id": scan_id})
        if "error" in result:
            return result
        data = {"scan_id": scan_id, "result": result["data"], "untrusted": True}
        if self.model_client_factory is not None:
            try:
                # B binds caller role/tenant/policy/budget in this factory. No
                # credential, raw source, released value or evidence goes to it.
                client = await resolve(self.model_client_factory(context))
                reply = await resolve(client.generate({
                    "operation": "describe_inspected_result",
                    "input": {"scan_id": scan_id}, "tools": [],
                }))
                if not isinstance(reply, dict) or set(reply) != {"text"}:
                    raise ValueError("Unsupported model output")
                if not isinstance(reply["text"], str) or len(reply["text"]) > 8000:
                    raise ValueError("Unbounded model output")
            except Exception:
                raise AdapterError("SERVICE_UNAVAILABLE", status=503) from None
            # Revalidate after a potentially slow broker call; cancellation or
            # context changes during inference must not release a stale result.
            result = await core_call(self.core, "get_inspected_result", context, {"scan_id": scan_id})
            if "error" in result:
                return result
            data["result"] = result["data"]
            data["assistant"] = {"text": reply["text"], "untrusted": True,
                                 "source_scan_id": scan_id}
        envelope = {"contract_version": "v1", "data": data}
        bounded_json(envelope)
        return envelope
