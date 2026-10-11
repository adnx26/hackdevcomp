"""Stateless JSON Streamable HTTP MCP tool dispatch. No action/evidence tools."""

import copy
import json

from .boundary import AdapterError, core_call, exact_fields, opaque_id, public_status


PROTOCOL_VERSIONS = ("2025-03-26", "2025-06-18")
COVERAGE = (
    "Protection covers this connector's content and tools. Native uploads, pasted "
    "text, built-in browsing, other connectors and the native app's final answer "
    "are outside gateway enforcement. Passing inspection does not confer trust."
)
TOOL_ARGUMENTS = {
    "inspect_folder": ("folder_id",),
    "get_folder_status": ("folder_id",),
    "inspect_resource": ("resource_id", "task_session_id"),
    "get_scan_status": ("scan_id",),
    "get_inspected_result": ("scan_id",),
}


def tool_metadata():
    descriptions = {
        "inspect_folder": "Inspect all supported files in a folder previously uploaded through the gateway UI. No filesystem paths accepted.",
        "get_folder_status": "Read per-file findings, pending checks and unsupported coverage for an uploaded folder; no source text.",
        "inspect_resource": "Start or resume inspection within an existing user-selected task scope.",
        "get_scan_status": "Read bounded progress, decision and evidence IDs; no evidence text.",
        "get_inspected_result": "Read a currently permitted task-scoped result, retaining source and disclosure labels.",
    }
    return [{
        "name": name, "description": descriptions[name] + " " + COVERAGE,
        "inputSchema": {"type": "object", "properties": {
            key: {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,128}$"}
            for key in fields
        }, "required": list(fields), "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "destructiveHint": False,
                        "idempotentHint": True, "openWorldHint": False},
    } for name, fields in TOOL_ARGUMENTS.items()]


class MCPAdapter:
    def __init__(self, core):
        self.core = core

    async def handle(self, context, message):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return self.rpc_error(None, -32600, "Invalid Request")
        request_id = message.get("id")
        if "id" in message and (isinstance(request_id, bool) or not isinstance(request_id, (str, int))):
            return self.rpc_error(None, -32600, "Invalid Request")
        if isinstance(request_id, str) and len(request_id) > 128:
            return self.rpc_error(None, -32600, "Invalid Request")
        method = message.get("method")
        if set(message) - {"jsonrpc", "id", "method", "params"} or not isinstance(method, str):
            return self.rpc_error(request_id, -32600, "Invalid Request")
        params = message.get("params", {})
        if not isinstance(params, dict):
            return self.rpc_error(request_id, -32602, "Invalid params")
        # MCP request/notification metadata is protocol data, never authority.
        # Accept it for initialize, ping and tools/list as well as tools/call.
        if "_meta" in params and not isinstance(params["_meta"], dict):
            return self.rpc_error(request_id, -32602, "Invalid params")
        params = {key: value for key, value in params.items() if key != "_meta"}
        if "id" not in message:
            # Notifications cannot invoke tools (especially inspection creation).
            if method == "notifications/initialized" and not params:
                return None
            raise AdapterError("INVALID_REQUEST")
        if method == "initialize":
            try:
                exact_fields(params, ("protocolVersion", "capabilities", "clientInfo"))
                if not isinstance(params["capabilities"], dict) or not isinstance(params["clientInfo"], dict):
                    raise AdapterError("INVALID_REQUEST")
                if not isinstance(params["protocolVersion"], str):
                    raise AdapterError("INVALID_REQUEST")
            except AdapterError:
                return self.rpc_error(request_id, -32602, "Invalid params")
            version = params["protocolVersion"]
            result = {"protocolVersion": version if version in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[-1],
                      "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": "protection-gateway", "version": "v1"},
                      "instructions": COVERAGE}
        elif method == "ping" and not params:
            result = {}
        elif method == "tools/list" and not params:
            result = {"tools": tool_metadata()}
        elif method == "tools/call":
            try:
                exact_fields(params, ("name", "arguments"), ("_meta",))
                name = params["name"]
                if not isinstance(name, str) or name not in TOOL_ARGUMENTS:
                    return self.rpc_error(request_id, -32602, "Unknown tool")
                arguments = params["arguments"]
                exact_fields(arguments, TOOL_ARGUMENTS[name])
                arguments = {key: opaque_id(value) for key, value in arguments.items()}
            except AdapterError:
                return self.rpc_error(request_id, -32602, "Invalid params")
            envelope = await core_call(self.core, name, context, arguments)
            if name in {"inspect_resource", "get_scan_status"}:
                envelope = public_status(envelope)
            # Preserve the entire result, including nested A-owned labels/spans.
            result = {"structuredContent": copy.deepcopy(envelope),
                      "content": [{"type": "text", "text": json.dumps(envelope, ensure_ascii=False)}],
                      "isError": "error" in envelope}
        else:
            return self.rpc_error(request_id, -32601, "Method not found")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def rpc_error(request_id, code, message):
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
