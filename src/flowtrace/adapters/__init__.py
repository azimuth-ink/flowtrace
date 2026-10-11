"""Backend adapters. 0.1.0 ships one: otlp_duckdb (OTLP/JSON files -> DuckDB, dialect otel-sql).

`load_adapter(name, paths)` resolves a registered adapter by name so the CLI
can grow a `--adapter` flag without touching the engine."""
from __future__ import annotations

from .base import Adapter, LogRow, MetricRow, QueryError, QueryResult, SpanRow, UnsupportedDialect, Window

REGISTRY = {
    "otlp_duckdb": "flowtrace.adapters.otlp_duckdb:OtlpDuckDBAdapter",
}


def load_adapter(name: str, paths, **kwargs) -> Adapter:
    import importlib
    try:
        target = REGISTRY[name]
    except KeyError:
        raise ValueError(f"unknown adapter {name!r}; known: {sorted(REGISTRY)}") from None
    mod, cls = target.split(":")
    return getattr(importlib.import_module(mod), cls)(paths, **kwargs)


__all__ = ["Adapter", "LogRow", "MetricRow", "QueryError", "QueryResult", "SpanRow", "UnsupportedDialect",
           "Window", "REGISTRY", "load_adapter"]
