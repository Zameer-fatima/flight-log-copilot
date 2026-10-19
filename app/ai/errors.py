"""Exception hierarchy so callers can catch AI failures with one ``except``."""

from __future__ import annotations


class DiagnosticsError(Exception):
    """Base class for every failure in the AI diagnostic layer."""


class ConfigurationError(DiagnosticsError):
    """Missing/invalid configuration (e.g. no API key, unknown provider)."""


class ProviderError(DiagnosticsError):
    """The LLM provider call failed (auth, rate limit, timeout, network, refusal)."""


class InvalidResponseError(DiagnosticsError):
    """The model replied, but not with a usable diagnosis."""
