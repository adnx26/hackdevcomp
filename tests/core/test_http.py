"""Public HTTP contract: authentication, CSRF, envelopes and status mapping."""

import base64
import io
import json
import unittest

from protection_gateway.core.http import make_wsgi_app

from .support import INVOICE_TEXT, TOKENS, V, Harness


class Client:
    def __init__(self, app):
        self.app = app
        self.cookie = None
        self.csrf = None

    def call(self, method, path, body=None, *, bearer=None, headers=None, raw=None, content_type="application/json"):
        payload = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(payload)),
            "CONTENT_TYPE": content_type,
            "wsgi.input": io.BytesIO(payload),
        }
        if bearer:
            environ["HTTP_AUTHORIZATION"] = f"Bearer {bearer}"
        if self.cookie:
            environ["HTTP_COOKIE"] = f"pg_session={self.cookie}"
        for key, value in (headers or {}).items():
            environ["HTTP_" + key.upper().replace("-", "_")] = value
        captured = {}

        def start_response(status, response_headers):
            captured["status"] = int(status.split()[0])
            captured["headers"] = response_headers

        data = b"".join(self.app(environ, start_response))
        for name, value in captured["headers"]:
            if name == "Set-Cookie" and value.startswith("pg_session="):
                self.cookie = value.split(";")[0].split("=", 1)[1] or None
        return captured["status"], json.loads(data), dict(captured["headers"])


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.app = make_wsgi_app(self.h.service, self.h.auth)
        self.client = Client(self.app)

    def tearDown(self):
        self.h.close()

    def upload_body(self, text=INVOICE_TEXT):
        return {"contract_version": V, "media_type": "text/plain", "content_base64": base64.b64encode(text.encode()).decode()}

    def test_unauthenticated(self):
        status, body, headers = self.client.call("GET", "/v1/scans/scan_0001")
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "UNAUTHENTICATED")
        self.assertEqual(set(body["error"]), {"code", "retryable", "request_id"})
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self.client.call("GET", "/v1/scans/x", bearer="wrong")[0], 401)

    def test_full_flow_over_http(self):
        alice = TOKENS["alice"]
        status, body, _ = self.client.call("POST", "/v1/resources", self.upload_body(), bearer=alice)
        self.assertEqual((status, body["contract_version"]), (201, "v1"))
        resource_id = body["data"]["resource_id"]
        status, body, _ = self.client.call(
            "POST", "/v1/task-sessions", {"contract_version": V, "policy_id": "extract_invoice", "resource_ids": [resource_id]}, bearer=alice
        )
        self.assertEqual(status, 201)
        ts = body["data"]["task_session_id"]
        status, body, _ = self.client.call("POST", "/v1/scans", {"contract_version": V, "task_session_id": ts}, bearer=alice)
        self.assertEqual((status, body["error"]["code"]), (400, "INVALID_REQUEST"))  # idempotency key required
        status, body, _ = self.client.call(
            "POST", "/v1/scans", {"contract_version": V, "task_session_id": ts}, bearer=alice, headers={"Idempotency-Key": "abc"}
        )
        self.assertEqual(status, 202)
        scan_id = body["data"]["scan_id"]
        status, body, _ = self.client.call("GET", f"/v1/scans/{scan_id}/result", bearer=alice)
        self.assertEqual((status, body["error"]["code"], body["error"]["retryable"]), (409, "NOT_READY", True))
        self.h.complete_clean(scan_id)
        status, body, _ = self.client.call("GET", f"/v1/scans/{scan_id}/result", bearer=alice)
        self.assertEqual(status, 200)
        self.assertEqual(body["data"]["result"]["output"]["fields"]["amount"]["value"], "1250.00")
        # Cross-tenant lookup is a plain 404.
        status, body, _ = self.client.call("GET", f"/v1/scans/{scan_id}", bearer=TOKENS["mallory"])
        self.assertEqual((status, body["error"]["code"]), (404, "NOT_FOUND"))

    def test_cookie_session_requires_csrf_for_mutations(self):
        status, body, headers = self.client.call("POST", "/v1/session", bearer=TOKENS["alice"])
        self.assertEqual(status, 201)
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        csrf = body["data"]["csrf_token"]
        status, body, _ = self.client.call("POST", "/v1/resources", self.upload_body())
        self.assertEqual((status, body["error"]["code"]), (403, "FORBIDDEN"))
        status, _, _ = self.client.call("POST", "/v1/resources", self.upload_body(), headers={"X-CSRF-Token": "wrong"})
        self.assertEqual(status, 403)
        status, body, _ = self.client.call("POST", "/v1/resources", self.upload_body(), headers={"X-CSRF-Token": csrf})
        self.assertEqual(status, 201)
        # Reads do not need the CSRF header.
        self.assertEqual(self.client.call("GET", "/v1/scans/scan_9999")[0], 404)
        self.assertEqual(self.client.call("DELETE", "/v1/session", headers={"X-CSRF-Token": csrf})[0], 200)
        self.assertEqual(self.client.call("GET", "/v1/scans/scan_9999")[0], 401)

    def test_confirmation_flow_over_http(self):
        status, body, _ = self.client.call("POST", "/v1/session", bearer=TOKENS["alice"])
        hdr = {"X-CSRF-Token": body["data"]["csrf_token"]}
        _, body, _ = self.client.call("POST", "/v1/resources", self.upload_body("report"), headers=hdr)
        rid = body["data"]["resource_id"]
        _, body, _ = self.client.call("POST", "/v1/task-sessions", {"contract_version": V, "policy_id": "simulate_send", "resource_ids": [rid]}, headers=hdr)
        ts = body["data"]["task_session_id"]
        action_body = {"contract_version": V, "task_session_id": ts, "action": {"operation": "simulated_send_email",
                       "arguments": {"to": "dave@example.com", "subject": "s", "body": "b", "attachment_resource_ids": []}}}
        status, body, _ = self.client.call("POST", "/v1/actions", action_body, headers=hdr)
        self.assertEqual(status, 201)
        action = body["data"]
        # Bearer (API) clients cannot confirm; only the cookie session can.
        status, body, _ = self.client.call(
            "POST", f"/v1/actions/{action['action_id']}/confirm", {"contract_version": V, "digest": action["digest"], "recipient_selected_by_user": True},
            bearer=TOKENS["alice"],
        )
        self.assertEqual(status, 403)
        status, body, _ = self.client.call(
            "POST", f"/v1/actions/{action['action_id']}/confirm", {"contract_version": V, "digest": action["digest"]}, headers=hdr
        )
        self.assertEqual((status, body["error"]["code"]), (428, "APPROVAL_REQUIRED"))
        status, body, _ = self.client.call(
            "POST", f"/v1/actions/{action['action_id']}/confirm", {"contract_version": V, "digest": action["digest"], "recipient_selected_by_user": True}, headers=hdr
        )
        self.assertEqual(body["data"]["state"], "CONFIRMED")
        status, body, _ = self.client.call(
            "POST", f"/v1/actions/{action['action_id']}/execute", {"contract_version": V}, headers={**hdr, "Idempotency-Key": "e1"}
        )
        self.assertEqual((status, body["data"]["state"]), (200, "EXECUTED"))

    def test_malformed_requests(self):
        alice = TOKENS["alice"]
        cases = [
            dict(raw=b"{bad json"),
            dict(raw=b'{"contract_version":"v1","contract_version":"v1"}'),
            dict(raw=b'{"contract_version":"v1","x":NaN}'),
            dict(body=self.upload_body(), content_type="text/plain"),
            dict(body=dict(self.upload_body(), tenant_id="tenant-m")),
        ]
        for case in cases:
            status, body, _ = self.client.call("POST", "/v1/resources", bearer=alice, **case)
            self.assertEqual((status, body["error"]["code"]), (400, "INVALID_REQUEST"), case)
        status, body, _ = self.client.call("POST", "/v1/resources", bearer=alice, raw=b"x" * 2_000_000)
        self.assertEqual(status, 429)
        self.assertEqual(self.client.call("GET", "/v1/nope", bearer=alice)[0], 404)
        self.assertEqual(self.client.call("PATCH", "/v1/resources", bearer=alice)[0], 404)

    def test_service_unavailable_without_runtime(self):
        h = Harness(runtime=False)
        try:
            client = Client(make_wsgi_app(h.service, h.auth))
            _, body, _ = client.call("POST", "/v1/resources", self.upload_body(), bearer=TOKENS["alice"])
            rid = body["data"]["resource_id"]
            _, body, _ = client.call("POST", "/v1/task-sessions", {"contract_version": V, "policy_id": "summarize_email", "resource_ids": [rid]}, bearer=TOKENS["alice"])
            status, body, _ = client.call(
                "POST", "/v1/scans", {"contract_version": V, "task_session_id": body["data"]["task_session_id"]},
                bearer=TOKENS["alice"], headers={"Idempotency-Key": "k"},
            )
            self.assertEqual((status, body["error"]["code"], body["error"]["retryable"]), (503, "SERVICE_UNAVAILABLE", True))
        finally:
            h.close()


if __name__ == "__main__":
    unittest.main()
