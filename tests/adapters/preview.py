"""Loopback-only UI test preview, with no scanner or working A/B/C fallback.

    PYTHONPATH=src python3 -B tests/adapters/preview.py

This authenticates a TEST-ONLY page session so browser tests can exercise static
assets. Every backend operation is unavailable. Never deploy this test server.
"""

import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from protection_gateway.adapters import AdapterApp


TEST_CONTEXT = object()
app = AdapterApp(
    authenticate=lambda scope, surface: TEST_CONTEXT,
    session_info=lambda context: {"display_name": "UI test session · backend unavailable", "csrf_token": "test_only_csrf"},
    allowed_origins=("http://127.0.0.1:8765",),
)


class Handler(BaseHTTPRequestHandler):
    def handle_request(self):
        # No upload/task/action test doubles are installed in this server.
        body = self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 16385))
        scope = {"type": "http", "path": self.path.split("?", 1)[0], "method": self.command,
                 "headers": [(k.lower().encode(), v.encode()) for k, v in self.headers.items()]}
        messages = [{"type": "http.request", "body": body}]
        responses = []

        async def receive():
            return messages.pop() if messages else {"type": "http.disconnect"}

        async def send(message):
            responses.append(message)

        asyncio.run(app(scope, receive, send))
        self.send_response(responses[0]["status"])
        for key, value in responses[0]["headers"]:
            self.send_header(key.decode(), value.decode())
        self.end_headers()
        self.wfile.write(responses[1]["body"])

    do_GET = handle_request
    do_POST = handle_request

    def log_message(self, *_):
        pass  # Do not log content, tokens or URLs containing identifiers.


if __name__ == "__main__":
    print("TEST ONLY: http://127.0.0.1:8765/ui; backend unavailable", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
