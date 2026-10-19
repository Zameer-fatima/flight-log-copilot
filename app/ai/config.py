"""LLM configuration, read from environment variables (never from source code)."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TypeVar

from app.ai.errors import ConfigurationError

DEFAULT_PROVIDER = "anthropic"
DEFAULT_MODEL = "claude-opus-5-5"
DEFAULT_TIMEOUT_S = 120.0
DEFAULT_MAX_TOKENS = 16000
DEFAULT_MAX_RETRIES = 2

#: Which environment variable holds the API key for each supported provider.
API_KEY_ENV: dict[str, str] = {"anthropic": "ANTHROPIC_API_KEY"}

_N = TypeVar("_N", int, float)


@dataclass(frozen=True)
class LLMConfig:
    """Settings for one LLM provider. ``api_key`` is excluded from ``repr``."""

    provider: str
    model: str
    api_key: str = field(repr=False)
    timeout_s: float = DEFAULT_TIMEOUT_S
    max_tokens: int = DEFAULT_MAX_TOKENS
    max_retries: int = DEFAULT_MAX_RETRIES

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> LLMConfig:
        """Build a config from an environment mapping (pass ``os.environ``).

        Variables: ``FLC_LLM_PROVIDER``, ``FLC_LLM_MODEL``, ``FLC_LLM_TIMEOUT``
        (seconds), ``FLC_LLM_MAX_TOKENS``, ``FLC_LLM_MAX_RETRIES`` plus the
        provider's key variable (``ANTHROPIC_API_KEY``).

        Raises:
            ConfigurationError: unknown provider, missing key, or bad number.
        """
        provider = environ.get("FLC_LLM_PROVIDER", DEFAULT_PROVIDER).strip().lower()
        key_var = API_KEY_ENV.get(provider)
        if key_var is None:
            raise ConfigurationError(
                f"unsupported FLC_LLM_PROVIDER {provider!r}; "
                f"supported: {', '.join(sorted(API_KEY_ENV))}"
            )
        api_key = environ.get(key_var, "").strip()
        if not api_key:
            raise ConfigurationError(
                f"missing credentials: set the {key_var} environment variable "
                "(the key is never read from files or command-line arguments)"
            )
        return cls(
            provider=provider,
            model=environ.get("FLC_LLM_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL,
            api_key=api_key,
            timeout_s=_number(environ, "FLC_LLM_TIMEOUT", DEFAULT_TIMEOUT_S, float),
            max_tokens=_number(environ, "FLC_LLM_MAX_TOKENS", DEFAULT_MAX_TOKENS, int),
            max_retries=_number(environ, "FLC_LLM_MAX_RETRIES", DEFAULT_MAX_RETRIES, int),
        )


def _number(
    environ: Mapping[str, str], name: str, default: _N, kind: Callable[[str], _N]
) -> _N:
    """Parse a positive number from the environment or raise ConfigurationError."""
    raw = environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = kind(raw)
    except ValueError:
        raise ConfigurationError(f"{name} must be a number, got {raw!r}") from None
    if value < 0 or (value == 0 and name != "FLC_LLM_MAX_RETRIES"):
        raise ConfigurationError(f"{name} must be positive, got {raw!r}")
    return value
