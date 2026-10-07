"""OpenTelemetry tracing: one span per investigation, model call and tool call.

Off unless configured, so tests and casual runs pay nothing:

    TRIAGE_TRACE_FILE=traces.jsonl          write spans as JSON lines (no extra install)
    OTEL_EXPORTER_OTLP_ENDPOINT=...         send spans to any OTLP backend: Jaeger, Grafana Tempo, or
                                            Langfuse (endpoint https://cloud.langfuse.com/api/public/otel,
                                            with OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic <base64 pk:sk>")
                                            needs: pip install opentelemetry-exporter-otlp-proto-http
"""

from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager

_tracer = None
_lock = threading.Lock()


class _JsonLinesExporter:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()

    def export(self, spans):
        from opentelemetry.sdk.trace.export import SpanExportResult

        with self._lock, open(self.path, "a") as f:
            for s in spans:
                f.write(json.dumps({
                    "name": s.name,
                    "trace_id": format(s.context.trace_id, "032x"),
                    "span_id": format(s.context.span_id, "016x"),
                    "parent_id": format(s.parent.span_id, "016x") if s.parent else None,
                    "start_ns": s.start_time,
                    "end_ns": s.end_time,
                    "attributes": dict(s.attributes or {}),
                    "status": s.status.status_code.name,
                }, default=str) + "\n")
        return SpanExportResult.SUCCESS

    def shutdown(self):
        pass

    def force_flush(self, timeout_millis=30000):
        return True


def get_tracer():
    global _tracer
    with _lock:
        if _tracer is not None:
            return _tracer
        trace_file = os.getenv("TRIAGE_TRACE_FILE")
        otlp = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        if not (trace_file or otlp):
            _tracer = False
            return _tracer
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor

        provider = TracerProvider(resource=Resource.create({"service.name": "soc-triage-agent"}))
        if trace_file:
            provider.add_span_processor(SimpleSpanProcessor(_JsonLinesExporter(trace_file)))
        if otlp:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("triage")
        return _tracer


@contextmanager
def span(name: str, **attributes):
    """``with span("tool", tool="run_sql") as s: s.set(rows=3)`` -- a no-op when tracing is off."""
    tracer = get_tracer()
    if not tracer:
        yield _NoSpan()
        return
    with tracer.start_as_current_span(name) as s:
        for k, v in attributes.items():
            if v is not None:
                s.set_attribute(k, v if isinstance(v, (str, int, float, bool)) else str(v))
        yield _Span(s)


class _NoSpan:
    def set(self, **_):
        pass


class _Span:
    def __init__(self, s):
        self._s = s

    def set(self, **attributes):
        for k, v in attributes.items():
            if v is not None:
                self._s.set_attribute(k, v if isinstance(v, (str, int, float, bool)) else str(v))
