"""LLM provider boundary: the only module that talks to a network SDK."""

from __future__ import annotations

from typing import Any, Protocol

from app.ai.config import LLMConfig
from app.ai.errors import ConfigurationError, InvalidResponseError, ProviderError


class LLMProvider(Protocol):
    """Anything that can turn (system prompt, user prompt) into reply text.

    A ``Protocol`` is structural typing: like a C++ concept / duck-typed
    interface, no inheritance is required. Tests pass a plain fake.
    """

    name: str
    model: str

    def complete(self, system: str, user: str) -> str:
        """Return the model's text reply or raise ``DiagnosticsError``."""
        ...


def _import_sdk() -> Any:
    """Import the optional ``anthropic`` SDK lazily."""
    try:
        import anthropic
    except ImportError as exc:
        raise ConfigurationError(
            "the 'anthropic' package is not installed; run: pip install 'anthropic>=1'"
        ) from exc
    return anthropic


class AnthropicProvider:
    """Claude via the official Anthropic SDK (non-streaming, one request)."""

    name = "anthropic"

    def __init__(self, config: LLMConfig, client: Any | None = None) -> None:
        self.model = config.model
        self._max_tokens = config.max_tokens
        if client is None:
            client = _import_sdk().Anthropic(
                api_key=config.api_key,
                timeout=config.timeout_s,
                max_retries=config.max_retries,
            )
        self._client = client

    def complete(self, system: str, user: str) -> str:
        """Send one request and return the concatenated text blocks."""
        sdk = _import_sdk()
        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=self._max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except sdk.APIError as exc:
            raise _translate(sdk, exc) from exc

        if response.stop_reason == "refusal":
            raise ProviderError("the model declined to answer this request")
        if response.stop_reason == "max_tokens":
            raise ProviderError(
                "the model's reply was cut off; raise FLC_LLM_MAX_TOKENS"
            )
        text = "".join(b.text for b in response.content if b.type == "text").strip()
        if not text:
            raise InvalidResponseError("the model returned no text content")
        return text


def _translate(sdk: Any, exc: Exception) -> ProviderError:
    """Map SDK exceptions to a user-facing message (most specific first)."""
    if isinstance(exc, sdk.AuthenticationError):
        msg = "authentication failed; check ANTHROPIC_API_KEY"
    elif isinstance(exc, sdk.PermissionDeniedError):
        msg = "the API key lacks permission for this request"
    elif isinstance(exc, sdk.NotFoundError):
        msg = "model or endpoint not found; check FLC_LLM_MODEL"
    elif isinstance(exc, sdk.RateLimitError):
        msg = "rate limited by the API; retry later"
    elif isinstance(exc, sdk.APITimeoutError):
        msg = "the request timed out; raise FLC_LLM_TIMEOUT or retry"
    elif isinstance(exc, sdk.APIConnectionError):
        msg = "network error reaching the API"
    elif isinstance(exc, sdk.APIStatusError):
        msg = f"API error (HTTP {exc.status_code})"
    else:
        msg = "unexpected API error"
    return ProviderError(msg)


def create_provider(config: LLMConfig) -> LLMProvider:
    """Instantiate the provider named in ``config``.

    Adding a provider = write a class with ``name``/``model``/``complete`` and
    add it here plus an entry in ``config.API_KEY_ENV``.
    """
    if config.provider == "anthropic":
        return AnthropicProvider(config)
    raise ConfigurationError(f"unsupported provider {config.provider!r}")
