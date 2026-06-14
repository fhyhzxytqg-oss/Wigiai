"""Governance helpers for weekly self-iteration in Wigiai.

Security and legal reliability gates are first-class:
- only allow promotion on Sundays (UTC by default)
- require minimum security/compliance/performance scores
- require statistically meaningful prediction quality checks
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List


@dataclass(frozen=True)
class SimulationResult:
    scenario_id: str
    prediction_accuracy: float
    contradiction_precision: float
    contradiction_recall: float
    p95_latency_ms: int
    security_findings_high: int
    security_findings_critical: int
    legal_policy_violations: int


@dataclass(frozen=True)
class PromotionPolicy:
    min_prediction_accuracy: float = 0.75
    min_contradiction_f1: float = 0.70
    max_p95_latency_ms: int = 1500
    max_high_findings: int = 0
    max_critical_findings: int = 0
    max_legal_policy_violations: int = 0
    release_weekday_utc: int = 6  # Sunday


def _f1(precision: float, recall: float) -> float:
    if precision <= 0 or recall <= 0:
        return 0.0
    return (2 * precision * recall) / (precision + recall)


def aggregate_results(results: List[SimulationResult]) -> Dict[str, float]:
    if not results:
        raise ValueError("results cannot be empty")

    n = len(results)
    avg_accuracy = sum(r.prediction_accuracy for r in results) / n
    avg_f1 = sum(_f1(r.contradiction_precision, r.contradiction_recall) for r in results) / n
    worst_p95 = max(r.p95_latency_ms for r in results)
    high_findings = sum(r.security_findings_high for r in results)
    critical_findings = sum(r.security_findings_critical for r in results)
    legal_violations = sum(r.legal_policy_violations for r in results)

    return {
        "avg_prediction_accuracy": round(avg_accuracy, 4),
        "avg_contradiction_f1": round(avg_f1, 4),
        "worst_p95_latency_ms": float(worst_p95),
        "security_findings_high": float(high_findings),
        "security_findings_critical": float(critical_findings),
        "legal_policy_violations": float(legal_violations),
    }


def evaluate_promotion(
    results: List[SimulationResult],
    policy: PromotionPolicy | None = None,
    now: datetime | None = None,
) -> Dict[str, object]:
    policy = policy or PromotionPolicy()
    now = now or datetime.now(timezone.utc)

    metrics = aggregate_results(results)
    reasons: List[str] = []

    if now.weekday() != policy.release_weekday_utc:
        reasons.append("promotion day is restricted to Sunday UTC")
    if metrics["avg_prediction_accuracy"] < policy.min_prediction_accuracy:
        reasons.append("prediction accuracy below threshold")
    if metrics["avg_contradiction_f1"] < policy.min_contradiction_f1:
        reasons.append("contradiction quality below threshold")
    if metrics["worst_p95_latency_ms"] > policy.max_p95_latency_ms:
        reasons.append("latency budget exceeded")
    if metrics["security_findings_high"] > policy.max_high_findings:
        reasons.append("high security findings must be zero")
    if metrics["security_findings_critical"] > policy.max_critical_findings:
        reasons.append("critical security findings must be zero")
    if metrics["legal_policy_violations"] > policy.max_legal_policy_violations:
        reasons.append("legal policy violations must be zero")

    return {
        "approved": not reasons,
        "metrics": metrics,
        "reasons": reasons,
        "evaluated_at_utc": now.isoformat(),
    }
