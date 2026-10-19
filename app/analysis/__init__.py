"""Format readers and deterministic analyzers for .tlog, .BIN and crash logs.

Every reader returns an :class:`~app.analysis.models.Analysis`: the same
``ParseResult`` the text parser produces, plus ``Finding`` objects computed by
plain code (never by an LLM) and source statistics.
"""
