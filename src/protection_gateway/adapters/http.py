"""Dependency-free ASGI routes for B to mount alongside A's /v1 services."""

import json
from pathlib import Path
from urllib.parse import urlsplit

from .boundary import AdapterError, bounded_json, error_envelope, resolve
from .chat import ChatAdapter
from .mcp import MCPAdapter, PROTOCOL_VERSIONS


MAX_REQUEST_BYTES = 16 * 1024
SECURITY_HEADERS = [
    (b"cache-control", b"no-store"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"content-security-policy", b"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
]


class AdapterApp:
    """All authority is injected. There is no development identity fallback.

    authenticate(scope, surface) -> A-owned authenticated context or None
    verify_csrf(scope, context) -> bool (A handles cookie vs token semantics)
    session_info(context) -> {display_name, csrf_token} from A's session service
    error_status(code) -> A-owned HTTP status mapping
    """

    def __init__(self, *, core=None, authenticate=None, verify_csrf=None,
                 session_info=None, model_client_factory=None, error_status=None,
                 allowed_origins=(), web_root=None, sign_in_path=None, public_ui=False):
        for origin in allowed_origins:
            parsed = urlsplit(origin)
            if (parsed.scheme not in {"http", "https"} or not parsed.netloc
                    or parsed.path or parsed.query or parsed.fragment or parsed.username):
                raise ValueError("Configure exact origins")
        if sign_in_path is not None and (not sign_in_path.startswith("/")
                                        or sign_in_path.startswith("//")
                                        or any(c in sign_in_path for c in "\r\n\\")):
            raise ValueError("Sign-in must use a same-origin path")
        self.allowed_origins = frozenset(allowed_origins)
        self.allowed_hosts = {urlsplit(origin).netloc for origin in allowed_origins}
        self.authenticate = authenticate
        self.verify_csrf = verify_csrf
        self.session_info = session_info
        self.error_status = error_status
        self.sign_in_path = sign_in_path
        self.public_ui = public_ui
        self.web_root = Path(web_root) if web_root else Path(__file__).resolve().parents[3] / "web"
        self.assets = {}
        for filename in ("index.html", "app.js", "style.css"):
            try:
                self.assets[filename] = (self.web_root / filename).read_bytes()
            except OSError:
                pass  # Missing assets return SERVICE_UNAVAILABLE on their route.
        self.mcp = MCPAdapter(core)
        self.chat = ChatAdapter(core, model_client_factory)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            raise RuntimeError("Mount AdapterApp as an HTTP app in B's bootstrap")
        try:
            status, headers, body = await self.route(scope, receive)
        except AdapterError as error:
            status, headers, body = error.status, [], bounded_json(error_envelope(error))
        except Exception:
            # Never turn backend traces, content, tokens or model text into errors.
            status, headers, body = 503, [], bounded_json(error_envelope(
                AdapterError("SERVICE_UNAVAILABLE", status=503)))
        if not any(key == b"content-type" for key, _ in headers) and body:
            headers.append((b"content-type", b"application/json; charset=utf-8"))
        await send({"type": "http.response.start", "status": status,
                    "headers": headers + SECURITY_HEADERS})
        await send({"type": "http.response.body", "body": body})

    async def route(self, scope, receive):
        path = scope.get("path", "")
        if path not in {"/mcp", "/v1/chat", "/ui", "/ui/", "/ui/app.js", "/ui/style.css", "/ui/session"}:
            raise AdapterError("NOT_FOUND", status=404)
        pairs = scope.get("headers", [])
        headers = {}
        for key, value in pairs:
            key = key.lower()
            if key in headers:
                raise AdapterError("INVALID_REQUEST")
            headers[key] = value.decode("latin-1")
        if not self.allowed_origins:
            raise AdapterError("SERVICE_UNAVAILABLE", status=503)
        if headers.get(b"host") not in self.allowed_hosts:
            raise AdapterError("FORBIDDEN", status=403)
        origin = headers.get(b"origin")
        if origin is not None and origin not in self.allowed_origins:
            raise AdapterError("FORBIDDEN", status=403)
        if self.authenticate is None:
            raise AdapterError("SERVICE_UNAVAILABLE", status=503)
        surface = "mcp" if path == "/mcp" else "ui"
        if surface == "mcp" and not headers.get(b"authorization", "").startswith("Bearer "):
            raise AdapterError("UNAUTHENTICATED", status=401)
        public_asset = self.public_ui and path in {"/ui", "/ui/", "/ui/app.js", "/ui/style.css"} and scope.get("method") == "GET"
        context = True if public_asset else await resolve(self.authenticate(scope, surface))
        if context is None:
            if path in {"/ui", "/ui/"} and self.sign_in_path:
                return 303, [(b"location", self.sign_in_path.encode("ascii"))], b""
            raise AdapterError("UNAUTHENTICATED", status=401)
        method = scope.get("method")
        if path == "/mcp":
            version = headers.get(b"mcp-protocol-version", "2025-03-26")
            if version not in PROTOCOL_VERSIONS:
                raise AdapterError("INVALID_REQUEST")
            if method != "POST":
                return 405, [(b"allow", b"POST, GET")], b""
            accepted = {part.split(";", 1)[0].strip() for part in headers.get(b"accept", "").split(",")}
            if not {"application/json", "text/event-stream"} <= accepted:
                raise AdapterError("INVALID_REQUEST")
            request = await self.read_json(headers, receive)
            result = await self.mcp.handle(context, request)
            return (202, [], b"") if result is None else (200, [], bounded_json(result))
        if path == "/v1/chat":
            if method != "POST":
                return 405, [(b"allow", b"POST")], b""
            if self.verify_csrf is None or await resolve(self.verify_csrf(scope, context)) is not True:
                raise AdapterError("FORBIDDEN", status=403)
            request = await self.read_json(headers, receive)
            result = await self.chat.handle(context, request)
            status = 200
            if "error" in result:
                status = self.error_status(result["error"]["code"]) if self.error_status else 503
            return status, [], bounded_json(result)
        if method != "GET":
            return 405, [(b"allow", b"GET")], b""
        if path == "/ui/session":
            if self.session_info is None:
                raise AdapterError("SERVICE_UNAVAILABLE", status=503)
            info = await resolve(self.session_info(context))
            if (not isinstance(info, dict) or set(info) != {"display_name", "csrf_token"}
                    or not isinstance(info["display_name"], str) or len(info["display_name"]) > 100
                    or not isinstance(info["csrf_token"], str) or not 1 <= len(info["csrf_token"]) <= 256):
                raise AdapterError("SERVICE_UNAVAILABLE", status=503)
            return 200, [], bounded_json({"contract_version": "v1", "data": info})
        assets = {"/ui": ("index.html", "text/html"), "/ui/": ("index.html", "text/html"),
                  "/ui/app.js": ("app.js", "text/javascript"),
                  "/ui/style.css": ("style.css", "text/css")}
        filename, media_type = assets[path]
        body = self.assets.get(filename)
        if body is None:
            raise AdapterError("SERVICE_UNAVAILABLE", status=503)
        return 200, [(b"content-type", (media_type + "; charset=utf-8").encode())], body

    @staticmethod
    async def read_json(headers, receive):
        # One deadline covers the entire body; a slow client cannot extend it
        # indefinitely by sending each chunk just before a per-chunk timeout.
        return await resolve(AdapterApp._read_json(headers, receive))

    @staticmethod
    async def _read_json(headers, receive):
        if headers.get(b"content-type", "").split(";", 1)[0].strip() != "application/json":
            raise AdapterError("INVALID_REQUEST")
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                raise AdapterError("INVALID_REQUEST")
            if message["type"] != "http.request":
                raise AdapterError("INVALID_REQUEST")
            body.extend(message.get("body", b""))
            if len(body) > MAX_REQUEST_BYTES:
                raise AdapterError("LIMIT_EXCEEDED", status=413)
            if not message.get("more_body", False):
                break

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate key")
                result[key] = value
            return result

        try:
            return json.loads(body.decode("utf-8"), object_pairs_hook=unique_object,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (UnicodeError, ValueError, RecursionError):
            raise AdapterError("INVALID_REQUEST") from None
