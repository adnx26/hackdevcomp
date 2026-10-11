"""Provider transports used by the model broker. Gateway process only."""

from __future__ import annotations

from pathlib import Path

from .errors import RuntimeUnavailable
from .model_broker import ModelConfig


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
