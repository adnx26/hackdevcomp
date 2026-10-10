"""Request framing regressions found during the design merge review."""

import base64
import io
import json
import threading
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from protection_gateway.core.config import GatewayConfig
from protection_gateway.core.http import make_wsgi_app

from .support import TOKENS, V, Harness
from .test_http import Client

RESUME_HEADERS = {"X-PG-Session-Resume": "1"}


class ReadTrackingInput(io.BytesIO):
    def __init__(self, value):
        super().__init__(value)
        self.read_calls = []

    def read(self, size=-1):
        self.read_calls.append(size)
        return super().read(size)


class HttpReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.app = make_wsgi_app(self.h.service, self.h.auth)

    def tearDown(self):
        self.h.close()

    def request(self, content_length, payload):
        stream = ReadTrackingInput(payload)
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/v1/resources",
            "CONTENT_LENGTH": content_length,
            "CONTENT_TYPE": "application/json",
            "HTTP_AUTHORIZATION": "Bearer " + TOKENS["alice"],
            "wsgi.input": stream,
        }
        captured = {}

        def start_response(status, headers):
            captured["status"] = int(status.split()[0])

        body = json.loads(b"".join(self.app(environ, start_response)))
        return captured["status"], body, stream

    def test_negative_content_length_rejects_oversized_valid_json_before_read(self):
        # The valid small upload followed by JSON whitespace was previously
        # accepted because read(-1) consumed the entire unbounded body.
        document = {
            "contract_version": V,
            "media_type": "text/plain",
            "content_base64": base64.b64encode(b"report").decode(),
        }
        payload = json.dumps(document).encode() + b" " * self.h.config.limits.max_request_bytes
        self.assertGreater(len(payload), self.h.config.limits.max_request_bytes)
        for content_length in ("-1", "-2"):
            with self.subTest(content_length=content_length):
                status, body, stream = self.request(content_length, payload)
                self.assertEqual((status, body["error"]["code"]), (400, "INVALID_REQUEST"))
                self.assertEqual(stream.read_calls, [])
                self.assertEqual(stream.tell(), 0)
        self.assertEqual(self.h.service.db.query_one("SELECT COUNT(*) AS count FROM resources")["count"], 0)

    def test_positive_oversized_content_length_rejects_before_read(self):
        payload = b" " * (self.h.config.limits.max_request_bytes + 1)
        status, body, stream = self.request(str(len(payload)), payload)
        self.assertEqual((status, body["error"]["code"]), (429, "LIMIT_EXCEEDED"))
        self.assertEqual(stream.read_calls, [])

    def login(self):
        client = Client(self.app)
        status, body, _ = client.call("POST", "/v1/session", bearer=TOKENS["alice"])
        self.assertEqual(status, 201)
        return client, body["data"]

    def test_session_recovery_rotates_csrf_without_cookie_or_expiry_extension(self):
        client, original = self.login()
        original_cookie = client.cookie
        self.h.clock.advance(60)
        status, body, headers = client.call("GET", "/v1/session", headers=RESUME_HEADERS)
        self.assertEqual(status, 200)
        recovered = body["data"]
        self.assertEqual(set(recovered), {"user_id", "csrf_token", "expires_at"})
        self.assertEqual(recovered["user_id"], original["user_id"])
        self.assertEqual(recovered["expires_at"], original["expires_at"])
        self.assertNotEqual(recovered["csrf_token"], original["csrf_token"])
        self.assertEqual(client.cookie, original_cookie)
        self.assertNotIn("Set-Cookie", headers)
        self.assertEqual(headers["Cache-Control"], "no-store")
        upload = {"contract_version": V, "media_type": "text/plain", "content_base64": "cmVwb3J0"}
        status, body, _ = client.call(
            "POST", "/v1/resources", upload, headers={"X-CSRF-Token": original["csrf_token"]}
        )
        self.assertEqual((status, body["error"]["code"]), (403, "FORBIDDEN"))
        status, _, _ = client.call(
            "POST", "/v1/resources", upload, headers={"X-CSRF-Token": recovered["csrf_token"]}
        )
        self.assertEqual(status, 201)

    def test_session_recovery_requires_cookie_with_resume_header(self):
        client = Client(self.app)
        status, body, headers = client.call("GET", "/v1/session", headers=RESUME_HEADERS)
        self.assertEqual((status, body["error"]["code"]), (401, "UNAUTHENTICATED"))
        self.assertNotIn("Set-Cookie", headers)

    def test_session_recovery_rejects_any_authorization_header(self):
        client, _ = self.login()
        original = self.h.service.db.query_one("SELECT csrf_hash FROM browser_sessions")["csrf_hash"]
        for cookie in (client.cookie, None):
            client.cookie = cookie
            for authorization in ("Bearer " + TOKENS["alice"], "Basic ignored", ""):
                with self.subTest(cookie=bool(cookie), authorization=authorization):
                    status, body, _ = client.call(
                        "GET", "/v1/session", headers={**RESUME_HEADERS, "Authorization": authorization}
                    )
                    self.assertEqual((status, body["error"]["code"]), (403, "FORBIDDEN"))
        self.assertEqual(self.h.service.db.query_one("SELECT csrf_hash FROM browser_sessions")["csrf_hash"], original)

    def test_session_recovery_requires_exact_resume_header(self):
        client, _ = self.login()
        for headers in ({}, {"X-PG-Session-Resume": "0"}, {"X-PG-Session-Resume": "1 "}):
            with self.subTest(headers=headers):
                status, body, _ = client.call("GET", "/v1/session", headers=headers)
                self.assertEqual((status, body["error"]["code"]), (403, "FORBIDDEN"))

    def test_session_recovery_rejects_all_supplied_origins_until_configured(self):
        client, _ = self.login()
        self.assertIsNone(self.h.service.config.public_origin)
        for origin in ("https://gateway.example", "https://attacker.example", "null", ""):
            with self.subTest(origin=origin):
                status, body, _ = client.call(
                    "GET", "/v1/session", headers={**RESUME_HEADERS, "Origin": origin}
                )
                self.assertEqual((status, body["error"]["code"]), (403, "FORBIDDEN"))

    def test_session_recovery_accepts_only_configured_origin(self):
        client, _ = self.login()
        self.h.service.config = replace(self.h.service.config, public_origin="https://gateway.example")
        status, _, _ = client.call(
            "GET", "/v1/session",
            headers={**RESUME_HEADERS, "Origin": "https://gateway.example", "Sec-Fetch-Site": "same-origin"},
        )
        self.assertEqual(status, 200)
        for origin in ("https://attacker.example", "https://gateway.example:8443", "null"):
            with self.subTest(origin=origin):
                status, body, _ = client.call(
                    "GET", "/v1/session", headers={**RESUME_HEADERS, "Origin": origin}
                )
                self.assertEqual((status, body["error"]["code"]), (403, "FORBIDDEN"))

    def test_session_recovery_rejects_cross_site_and_same_site_fetches(self):
        client, _ = self.login()
        self.h.service.config = replace(self.h.service.config, public_origin="https://gateway.example")
        for fetch_site in ("same-site", "cross-site"):
            with self.subTest(fetch_site=fetch_site):
                status, body, _ = client.call(
                    "GET", "/v1/session",
                    headers={**RESUME_HEADERS, "Origin": "https://gateway.example", "Sec-Fetch-Site": fetch_site},
                )
                self.assertEqual((status, body["error"]["code"]), (403, "FORBIDDEN"))

    def test_session_recovery_rejects_expired_cookie(self):
        client, _ = self.login()
        self.h.clock.advance(self.h.config.retention.browser_session_seconds)
        status, body, _ = client.call("GET", "/v1/session", headers=RESUME_HEADERS)
        self.assertEqual((status, body["error"]["code"]), (401, "UNAUTHENTICATED"))

    def test_session_recovery_rejects_revoked_cookie(self):
        client, _ = self.login()
        self.h.auth.revoke_browser_session(client.cookie)
        status, body, _ = client.call("GET", "/v1/session", headers=RESUME_HEADERS)
        self.assertEqual((status, body["error"]["code"]), (401, "UNAUTHENTICATED"))

    def test_direct_recovery_preserves_browser_principal_and_cookie(self):
        original = self.h.auth.issue_browser_session(TOKENS["alice"])
        recovered = self.h.auth.recover_browser_session(original.cookie_value)
        self.assertEqual(recovered.cookie_value, original.cookie_value)
        self.assertEqual(recovered.principal, original.principal)
        self.assertEqual(recovered.expires_at, original.expires_at)

    def test_session_tokens_remain_hashed_in_database_after_recovery(self):
        original = self.h.auth.issue_browser_session(TOKENS["alice"])
        recovered = self.h.auth.recover_browser_session(original.cookie_value)
        row = self.h.service.db.query_one("SELECT * FROM browser_sessions")
        self.assertEqual(row["session_hash"], GatewayConfig.hash_token(original.cookie_value))
        self.assertEqual(row["csrf_hash"], GatewayConfig.hash_token(recovered.csrf_token))
        database_bytes = Path(self.h.config.database_path).read_bytes()
        for secret in (original.cookie_value, original.csrf_token, recovered.csrf_token):
            self.assertNotIn(secret.encode(), database_bytes)
            self.assertNotIn(secret, json.dumps(dict(row)))

    def test_concurrent_logout_commits_before_recovery_cannot_revive_session(self):
        logout_client, original = self.login()
        recovery_client = Client(self.app)
        recovery_client.cookie = logout_client.cookie
        transaction_entered = threading.Event()
        recovery_entered = threading.Event()
        release_logout = threading.Event()
        original_transaction = self.h.service.db.transaction
        original_recover = self.h.auth.recover_browser_session
        outcomes = {}

        @contextmanager
        def paused_logout_transaction():
            with original_transaction() as conn:
                if threading.current_thread().name == "session-logout":
                    transaction_entered.set()
                    if not release_logout.wait(3):
                        raise AssertionError("logout transaction was not released")
                yield conn

        def observed_recovery(cookie):
            recovery_entered.set()
            return original_recover(cookie)

        def logout():
            outcomes["logout"] = logout_client.call(
                "DELETE", "/v1/session", headers={"X-CSRF-Token": original["csrf_token"]}
            )

        def recovery():
            outcomes["recovery"] = recovery_client.call("GET", "/v1/session", headers=RESUME_HEADERS)

        logout_thread = threading.Thread(target=logout, name="session-logout")
        recovery_thread = threading.Thread(target=recovery, name="session-recovery")
        with patch.object(self.h.service.db, "transaction", paused_logout_transaction), patch.object(
            self.h.auth, "recover_browser_session", observed_recovery
        ):
            try:
                logout_thread.start()
                self.assertTrue(transaction_entered.wait(3))
                recovery_thread.start()
                self.assertTrue(recovery_entered.wait(3))
                self.assertNotIn("recovery", outcomes)
            finally:
                release_logout.set()
                logout_thread.join(3)
                if recovery_thread.ident is not None:
                    recovery_thread.join(3)
        self.assertFalse(logout_thread.is_alive())
        self.assertFalse(recovery_thread.is_alive())
        self.assertEqual(outcomes["logout"][0], 200)
        self.assertEqual((outcomes["recovery"][0], outcomes["recovery"][1]["error"]["code"]), (401, "UNAUTHENTICATED"))
        row = self.h.service.db.query_one("SELECT * FROM browser_sessions")
        self.assertIsNotNone(row["revoked_at"])
        self.assertEqual(row["csrf_hash"], GatewayConfig.hash_token(original["csrf_token"]))


if __name__ == "__main__":
    unittest.main()
