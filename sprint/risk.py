"""Dollar-risk estimator (v5).

Turns an audit result into a planning estimate of annual exposure:
the weighted fraction of the six checks that is not passing, applied
to a small-business email-incident cost band. The model is printed
wherever the number is used — it is an estimate for prioritization,
not a quote, a guarantee, or an insurance figure.

Band basis: a single business-email-compromise or spoofing incident
for a small business (wire fraud recovery effort, downtime, client
trust) is routinely a five-figure event; $8k–$30k is the
conservative planning band the Sprint uses.
"""
from __future__ import annotations

from sprint.audit import WEIGHTS

INCIDENT_LOW = 8000
INCIDENT_HIGH = 30000


def estimate(result: dict) -> dict:
    """Return {low, high, drivers} for an audit result dict."""
    max_score = result.get("max_score") or 6
    missing = max(0.0, (max_score - result["score"]) / max_score)
    drivers = sorted(
        (n for n, c in result["checks"].items() if c["status"] != "pass"),
        key=lambda n: -WEIGHTS.get(n, 1.0),
    )
    return {
        "low": round(INCIDENT_LOW * missing),
        "high": round(INCIDENT_HIGH * missing),
        "drivers": drivers,
    }
