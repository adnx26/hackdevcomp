"""Provider transports used by the model broker. Gateway process only."""

from __future__ import annotations

from pathlib import Path
import json
import os
import ssl
import sys
import urllib.request
import urllib.error

from .errors import RuntimeUnavailable
from .model_broker import ModelConfig


def _tls_context():
    context = ssl.create_default_context()
    # Python.org macOS installs can lack their optional cert.pem symlink.
    # Use the OS trust bundle only when no explicit trust configuration exists.
    if (sys.platform == 'darwin' and not context.get_ca_certs()
            and not os.environ.get('SSL_CERT_FILE') and not os.environ.get('SSL_CERT_DIR')):
        bundle = Path('/etc/ssl/cert.pem')
        if bundle.is_file():
            context.load_verify_locations(cafile=str(bundle))
    return context


class KimiTransport:
    """Pinned Kimi K3 chat API. Only the gateway holds the credential."""

    def __init__(self, config: ModelConfig, api_key: str | None = None, api_key_file: Path | None = None):
        if api_key_file:
            try:
                api_key = api_key_file.read_text().strip()
            except OSError:
                raise RuntimeUnavailable("MODEL_PROVIDER_CREDENTIAL_MISSING") from None
        if not api_key or "\n" in api_key or "\r" in api_key:
            raise RuntimeUnavailable("MODEL_PROVIDER_CREDENTIAL_MISSING")
        self._key = api_key
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                                   urllib.request.HTTPSHandler(context=_tls_context()))

    def generate(self, config: ModelConfig, *, system: str, user: str, max_output_tokens: int, timeout: float) -> dict:
        payload = {"model": config.model, "max_tokens": max_output_tokens,
                   "reasoning_effort": config.reasoning_effort, "response_format": {"type": "json_object"},
                   "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        request = urllib.request.Request(config.endpoint + "/chat/completions", data=json.dumps(payload).encode(),
                                        headers={"Authorization": "Bearer " + self._key, "Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=timeout) as response:
                raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("response size")
            data = json.loads(raw)
            choice = data["choices"][0]
            usage = data.get("usage", {})
            return {"stop_reason": "end_turn" if choice["finish_reason"] == "stop" else choice["finish_reason"],
                    "text": choice["message"]["content"],
                    "usage": {"input_tokens": usage.get("prompt_tokens", 0), "output_tokens": usage.get("completion_tokens", 0)}}
        except urllib.error.HTTPError as error:
            codes = {401: "MODEL_PROVIDER_UNAUTHENTICATED", 403: "MODEL_PROVIDER_FORBIDDEN",
                     429: "MODEL_PROVIDER_RATE_LIMITED", 400: "MODEL_PROVIDER_REQUEST_REJECTED"}
            raise RuntimeUnavailable(codes.get(error.code, "MODEL_PROVIDER_UNAVAILABLE")) from None
        except urllib.error.URLError as error:
            code = 'MODEL_PROVIDER_TLS_ERROR' if isinstance(error.reason, ssl.SSLCertVerificationError) else 'MODEL_PROVIDER_UNAVAILABLE'
            raise RuntimeUnavailable(code) from None
        except (OSError, ValueError, KeyError, IndexError, TypeError):
            raise RuntimeUnavailable("MODEL_PROVIDER_UNAVAILABLE") from None


class AnthropicTransport:
    """Claude Messages API through the official SDK.

    The endpoint is pinned (ANTHROPIC_BASE_URL is ignored) and SDK retries are
    off so the broker's call budget and timeout stay exact. Server-side model
    fallbacks are deliberately not enabled: a fallback would run a model other
    than the one bound into the scan's model-configuration hash.
    """

    def __init__(self, config: ModelConfig, api_key_file: Path):
        try:
            import anthropic
        except ImportError:
            raise RuntimeUnavailable("MODEL_PROVIDER_SDK_MISSING") from None
        try:
            api_key = Path(api_key_file).read_text().strip()
        except OSError:
            raise RuntimeUnavailable("MODEL_PROVIDER_CREDENTIAL_MISSING") from None
        if not api_key:
            raise RuntimeUnavailable("MODEL_PROVIDER_CREDENTIAL_MISSING")
        self._client = anthropic.Anthropic(api_key=api_key, base_url=config.endpoint, max_retries=0)

    def generate(self, config: ModelConfig, *, system: str, user: str, max_output_tokens: int, timeout: float) -> dict:
        response = self._client.with_options(timeout=timeout).messages.create(
            model=config.model, max_tokens=max_output_tokens, system=system, messages=[{"role": "user", "content": user}],
        )
        # "refusal" and "max_tokens" are passed through; the broker treats them as incomplete.
        return {
            "stop_reason": response.stop_reason,
            "text": "".join(block.text for block in response.content if block.type == "text"),
            "usage": {"input_tokens": response.usage.input_tokens, "output_tokens": response.usage.output_tokens},
        }
