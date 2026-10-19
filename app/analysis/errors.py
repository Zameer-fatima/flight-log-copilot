"""Errors raised while reading/analysing a source."""

from __future__ import annotations


class AnalysisError(Exception):
    """Base class: the source could not be analysed (message is user-facing)."""


class UnsupportedFormatError(AnalysisError):
    """The file is not a format we understand."""


class MissingDependencyError(AnalysisError):
    """An optional package (e.g. pymavlink) is not installed."""


class UnreadableLogError(AnalysisError):
    """The file has a known format but contains no readable data."""
