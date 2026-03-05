"""
Shared Datadog APM helpers for Odoo-QB integration Lambdas.

Provides lightweight tracing and custom metrics that gracefully
degrade to no-ops when Datadog is not enabled (no layer present).

"""

import os
import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Try to import Datadog - graceful fallback if layer not present
try:
    from ddtrace import tracer
    from datadog_lambda.metric import lambda_metric
    DD_AVAILABLE = True
except ImportError:
    DD_AVAILABLE = False
    tracer = None

DD_SERVICE = os.environ.get("DD_SERVICE", "odoo-qb-integration")
DD_ENV = os.environ.get("DD_ENV", os.environ.get("ENVIRONMENT", "dev"))


@contextmanager
def trace_span(operation_name, service=None, resource=None, tags=None):
    """
    Context manager for tracing a block of code.
    No-ops gracefully when Datadog is not available.

    Usage:
        with trace_span("odoo.fetch_bills", tags={"company": "1MD"}) as span:
            bills = odoo.get_posted_vendor_bills()
            span.set_metric("bills.count", len(bills))
    """
    if DD_AVAILABLE and tracer:
        with tracer.trace(
            operation_name,
            service=service or DD_SERVICE,
            resource=resource,
        ) as span:
            if tags:
                for k, v in tags.items():
                    span.set_tag(k, v)
            yield span
    else:
        yield NullSpan()


class NullSpan:
    """No-op span when Datadog is not available."""
    def set_tag(self, key, value): pass
    def set_metric(self, key, value): pass
    def set_tags(self, tags): pass


def emit_metric(metric_name, value, tags=None):
    """
    Emit a custom Datadog metric.

    Usage:
        emit_metric("odoo_qb.invoices.processed", 5, tags=["company:1MD", "status:ready"])
    """
    if DD_AVAILABLE:
        try:
            tag_list = tags or []
            tag_list.extend([f"env:{DD_ENV}", f"service:{DD_SERVICE}"])
            lambda_metric(metric_name, value, tags=tag_list)
        except Exception as e:
            logger.debug(f"DD metric emit failed (non-fatal): {e}")


def tag_current_span(tags: dict):
    """Add tags to the current active trace span."""
    if DD_AVAILABLE and tracer:
        span = tracer.current_span()
        if span:
            for k, v in tags.items():
                span.set_tag(k, v)