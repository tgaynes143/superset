# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Multi-factor producer risk scoring engine.

Computes a composite risk score (0-100) for each insurance producer
based on weighted factors including:
- Commission rate deviation from norms
- Transaction volume anomalies
- Chargeback frequency
- License compliance status
- Historical finding severity
- Concentration risk (single-carrier dependence)
- Temporal patterns (end-of-period spikes)
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from superset.insurance_commission_audit.models import FindingSeverity

logger = logging.getLogger(__name__)


@dataclass
class RiskFactor:
    """A single scored risk factor contributing to composite risk."""

    name: str
    category: str
    raw_score: float  # 0.0 - 1.0
    weight: float
    weighted_score: float
    description: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProducerRiskProfile:
    """Complete risk assessment for a single producer."""

    producer_id: int
    composite_score: float  # 0 - 100
    risk_tier: str  # LOW, MODERATE, ELEVATED, HIGH, CRITICAL
    factors: list[RiskFactor] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    assessed_date: date | None = None


@dataclass
class ProducerMetrics:
    """Aggregated metrics for risk scoring a producer."""

    producer_id: int
    total_transactions: int = 0
    total_commission: float = 0.0
    total_premium: float = 0.0
    avg_commission_rate: float = 0.0
    max_commission_rate: float = 0.0
    chargeback_count: int = 0
    chargeback_amount: float = 0.0
    unique_carriers: int = 0
    dominant_carrier_pct: float = 0.0
    license_expired: bool = False
    days_until_license_expiry: int | None = None
    open_findings_count: int = 0
    critical_findings_count: int = 0
    high_findings_count: int = 0
    end_of_quarter_pct: float = 0.0
    peer_avg_commission_rate: float = 0.0
    peer_avg_volume: float = 0.0
    years_of_experience: float = 0.0


# Default risk factor weights (must sum to 1.0)
DEFAULT_WEIGHTS = {
    "commission_rate_deviation": 0.20,
    "volume_anomaly": 0.10,
    "chargeback_ratio": 0.15,
    "license_status": 0.15,
    "finding_history": 0.15,
    "concentration_risk": 0.10,
    "temporal_pattern": 0.10,
    "experience_factor": 0.05,
}


class RiskScoringEngine:
    """Computes multi-factor risk scores for insurance producers."""

    def __init__(
        self,
        weights: dict[str, float] | None = None,
    ) -> None:
        self.weights = weights or DEFAULT_WEIGHTS
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.01:
            raise ValueError(
                f"Risk factor weights must sum to 1.0, got {total:.4f}"
            )

    def score_producer(self, metrics: ProducerMetrics) -> ProducerRiskProfile:
        """Compute the composite risk profile for a single producer."""
        factors: list[RiskFactor] = []

        factors.append(self._score_commission_rate_deviation(metrics))
        factors.append(self._score_volume_anomaly(metrics))
        factors.append(self._score_chargeback_ratio(metrics))
        factors.append(self._score_license_status(metrics))
        factors.append(self._score_finding_history(metrics))
        factors.append(self._score_concentration_risk(metrics))
        factors.append(self._score_temporal_pattern(metrics))
        factors.append(self._score_experience_factor(metrics))

        composite = sum(f.weighted_score for f in factors) * 100
        composite = min(100.0, max(0.0, composite))
        risk_tier = self._determine_tier(composite)
        recommendations = self._generate_recommendations(factors, risk_tier)

        return ProducerRiskProfile(
            producer_id=metrics.producer_id,
            composite_score=round(composite, 1),
            risk_tier=risk_tier,
            factors=factors,
            recommendations=recommendations,
            assessed_date=date.today(),
        )

    def score_producers(
        self, metrics_list: list[ProducerMetrics]
    ) -> list[ProducerRiskProfile]:
        """Batch-score multiple producers and return sorted by risk."""
        profiles = [self.score_producer(m) for m in metrics_list]
        profiles.sort(key=lambda p: p.composite_score, reverse=True)
        return profiles

    def _score_commission_rate_deviation(
        self, metrics: ProducerMetrics
    ) -> RiskFactor:
        """Score based on how far the producer's avg rate deviates from peers."""
        weight = self.weights["commission_rate_deviation"]
        if metrics.peer_avg_commission_rate == 0:
            raw_score = 0.0
            desc = "No peer data available for comparison."
        else:
            deviation = abs(
                metrics.avg_commission_rate - metrics.peer_avg_commission_rate
            )
            relative_dev = deviation / metrics.peer_avg_commission_rate
            raw_score = min(1.0, relative_dev / 0.5)
            desc = (
                f"Average rate {metrics.avg_commission_rate:.4f} vs peer average "
                f"{metrics.peer_avg_commission_rate:.4f} "
                f"({relative_dev:.1%} deviation)."
            )

        return RiskFactor(
            name="Commission Rate Deviation",
            category="Financial",
            raw_score=round(raw_score, 4),
            weight=weight,
            weighted_score=round(raw_score * weight, 4),
            description=desc,
            details={
                "producer_avg_rate": round(metrics.avg_commission_rate, 4),
                "peer_avg_rate": round(metrics.peer_avg_commission_rate, 4),
                "max_rate": round(metrics.max_commission_rate, 4),
            },
        )

    def _score_volume_anomaly(self, metrics: ProducerMetrics) -> RiskFactor:
        """Score based on transaction volume compared to peers."""
        weight = self.weights["volume_anomaly"]
        if metrics.peer_avg_volume == 0:
            raw_score = 0.0
            desc = "No peer volume data available."
        else:
            volume_ratio = metrics.total_commission / metrics.peer_avg_volume
            if volume_ratio > 3.0:
                raw_score = 1.0
            elif volume_ratio > 2.0:
                raw_score = 0.7
            elif volume_ratio > 1.5:
                raw_score = 0.3
            else:
                raw_score = 0.0
            desc = (
                f"Commission volume ${metrics.total_commission:,.2f} is "
                f"{volume_ratio:.1f}x peer average "
                f"${metrics.peer_avg_volume:,.2f}."
            )

        return RiskFactor(
            name="Volume Anomaly",
            category="Financial",
            raw_score=round(raw_score, 4),
            weight=weight,
            weighted_score=round(raw_score * weight, 4),
            description=desc,
            details={
                "total_commission": round(metrics.total_commission, 2),
                "total_transactions": metrics.total_transactions,
                "peer_avg_volume": round(metrics.peer_avg_volume, 2),
            },
        )

    def _score_chargeback_ratio(self, metrics: ProducerMetrics) -> RiskFactor:
        """Score based on chargeback frequency relative to total transactions."""
        weight = self.weights["chargeback_ratio"]
        if metrics.total_transactions == 0:
            raw_score = 0.0
            desc = "No transactions to evaluate."
        else:
            cb_ratio = metrics.chargeback_count / metrics.total_transactions
            if cb_ratio > 0.10:
                raw_score = 1.0
            elif cb_ratio > 0.05:
                raw_score = 0.7
            elif cb_ratio > 0.02:
                raw_score = 0.3
            else:
                raw_score = cb_ratio / 0.02 * 0.1
            desc = (
                f"{metrics.chargeback_count} chargebacks out of "
                f"{metrics.total_transactions} transactions "
                f"({cb_ratio:.1%}), totaling ${metrics.chargeback_amount:,.2f}."
            )

        return RiskFactor(
            name="Chargeback Ratio",
            category="Quality",
            raw_score=round(raw_score, 4),
            weight=weight,
            weighted_score=round(raw_score * weight, 4),
            description=desc,
            details={
                "chargeback_count": metrics.chargeback_count,
                "chargeback_amount": round(metrics.chargeback_amount, 2),
                "total_transactions": metrics.total_transactions,
            },
        )

    def _score_license_status(self, metrics: ProducerMetrics) -> RiskFactor:
        """Score based on license validity and proximity to expiry."""
        weight = self.weights["license_status"]
        if metrics.license_expired:
            raw_score = 1.0
            desc = "Producer license is EXPIRED."
        elif metrics.days_until_license_expiry is not None:
            if metrics.days_until_license_expiry <= 30:
                raw_score = 0.7
                desc = f"License expires in {metrics.days_until_license_expiry} days."
            elif metrics.days_until_license_expiry <= 90:
                raw_score = 0.3
                desc = f"License expires in {metrics.days_until_license_expiry} days."
            else:
                raw_score = 0.0
                desc = f"License valid for {metrics.days_until_license_expiry} more days."
        else:
            raw_score = 0.1
            desc = "License expiry date not available."

        return RiskFactor(
            name="License Status",
            category="Compliance",
            raw_score=round(raw_score, 4),
            weight=weight,
            weighted_score=round(raw_score * weight, 4),
            description=desc,
            details={
                "license_expired": metrics.license_expired,
                "days_until_expiry": metrics.days_until_license_expiry,
            },
        )

    def _score_finding_history(self, metrics: ProducerMetrics) -> RiskFactor:
        """Score based on prior audit findings severity and count."""
        weight = self.weights["finding_history"]

        severity_score = (
            metrics.critical_findings_count * 1.0
            + metrics.high_findings_count * 0.6
            + max(0, metrics.open_findings_count - metrics.critical_findings_count - metrics.high_findings_count) * 0.2
        )
        raw_score = min(1.0, severity_score / 3.0)

        desc = (
            f"{metrics.open_findings_count} open findings "
            f"({metrics.critical_findings_count} critical, "
            f"{metrics.high_findings_count} high)."
        )

        return RiskFactor(
            name="Finding History",
            category="Compliance",
            raw_score=round(raw_score, 4),
            weight=weight,
            weighted_score=round(raw_score * weight, 4),
            description=desc,
            details={
                "open_findings": metrics.open_findings_count,
                "critical_findings": metrics.critical_findings_count,
                "high_findings": metrics.high_findings_count,
            },
        )

    def _score_concentration_risk(self, metrics: ProducerMetrics) -> RiskFactor:
        """Score based on carrier concentration (over-reliance on one carrier)."""
        weight = self.weights["concentration_risk"]

        if metrics.unique_carriers <= 1:
            raw_score = 0.8
            desc = "All business placed with a single carrier."
        elif metrics.dominant_carrier_pct > 0.80:
            raw_score = 0.6
            desc = (
                f"Dominant carrier represents {metrics.dominant_carrier_pct:.0%} "
                f"of business across {metrics.unique_carriers} carriers."
            )
        elif metrics.dominant_carrier_pct > 0.60:
            raw_score = 0.3
            desc = (
                f"Dominant carrier represents {metrics.dominant_carrier_pct:.0%} "
                f"across {metrics.unique_carriers} carriers."
            )
        else:
            raw_score = 0.0
            desc = (
                f"Well-diversified across {metrics.unique_carriers} carriers "
                f"(dominant: {metrics.dominant_carrier_pct:.0%})."
            )

        return RiskFactor(
            name="Concentration Risk",
            category="Business",
            raw_score=round(raw_score, 4),
            weight=weight,
            weighted_score=round(raw_score * weight, 4),
            description=desc,
            details={
                "unique_carriers": metrics.unique_carriers,
                "dominant_carrier_pct": round(metrics.dominant_carrier_pct, 2),
            },
        )

    def _score_temporal_pattern(self, metrics: ProducerMetrics) -> RiskFactor:
        """Score based on end-of-quarter/period clustering of transactions."""
        weight = self.weights["temporal_pattern"]

        if metrics.end_of_quarter_pct > 0.50:
            raw_score = 0.8
            desc = (
                f"{metrics.end_of_quarter_pct:.0%} of transactions clustered "
                f"in final week of quarters. Suggests quota gaming."
            )
        elif metrics.end_of_quarter_pct > 0.35:
            raw_score = 0.4
            desc = (
                f"{metrics.end_of_quarter_pct:.0%} of transactions in "
                f"end-of-quarter periods."
            )
        else:
            raw_score = 0.0
            desc = f"Normal temporal distribution ({metrics.end_of_quarter_pct:.0%} end-of-quarter)."

        return RiskFactor(
            name="Temporal Pattern",
            category="Behavioral",
            raw_score=round(raw_score, 4),
            weight=weight,
            weighted_score=round(raw_score * weight, 4),
            description=desc,
            details={"end_of_quarter_pct": round(metrics.end_of_quarter_pct, 2)},
        )

    def _score_experience_factor(self, metrics: ProducerMetrics) -> RiskFactor:
        """Score inversely related to producer experience (new producers = higher risk)."""
        weight = self.weights["experience_factor"]

        if metrics.years_of_experience < 1:
            raw_score = 0.8
            desc = f"New producer ({metrics.years_of_experience:.1f} years)."
        elif metrics.years_of_experience < 3:
            raw_score = 0.4
            desc = f"Junior producer ({metrics.years_of_experience:.1f} years)."
        elif metrics.years_of_experience < 5:
            raw_score = 0.2
            desc = f"Mid-career producer ({metrics.years_of_experience:.1f} years)."
        else:
            raw_score = 0.0
            desc = f"Experienced producer ({metrics.years_of_experience:.1f} years)."

        return RiskFactor(
            name="Experience Factor",
            category="Behavioral",
            raw_score=round(raw_score, 4),
            weight=weight,
            weighted_score=round(raw_score * weight, 4),
            description=desc,
            details={"years_of_experience": round(metrics.years_of_experience, 1)},
        )

    @staticmethod
    def _determine_tier(score: float) -> str:
        """Map composite score to risk tier."""
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 40:
            return "ELEVATED"
        if score >= 20:
            return "MODERATE"
        return "LOW"

    @staticmethod
    def _generate_recommendations(
        factors: list[RiskFactor], risk_tier: str
    ) -> list[str]:
        """Generate actionable recommendations based on risk factors."""
        recommendations: list[str] = []

        high_factors = sorted(
            factors, key=lambda f: f.raw_score, reverse=True
        )

        for factor in high_factors:
            if factor.raw_score >= 0.7:
                if factor.name == "License Status":
                    recommendations.append(
                        "URGENT: Verify producer license status and suspend "
                        "commission payments until license is confirmed valid."
                    )
                elif factor.name == "Commission Rate Deviation":
                    recommendations.append(
                        "Review all commission rate agreements for this producer. "
                        "Compare against approved rate schedules and state maximums."
                    )
                elif factor.name == "Chargeback Ratio":
                    recommendations.append(
                        "Investigate high chargeback rate. Review policy "
                        "persistency and sales practices for potential churning."
                    )
                elif factor.name == "Finding History":
                    recommendations.append(
                        "Prioritize remediation of open findings. Consider "
                        "enhanced monitoring or production restrictions."
                    )
                elif factor.name == "Concentration Risk":
                    recommendations.append(
                        "Review carrier agreements for potential conflicts of "
                        "interest or steering concerns."
                    )
                elif factor.name == "Temporal Pattern":
                    recommendations.append(
                        "Audit end-of-quarter transactions for proper "
                        "documentation and legitimate business purpose."
                    )
                elif factor.name == "Volume Anomaly":
                    recommendations.append(
                        "Conduct detailed review of transaction volume. Verify "
                        "all policies are legitimate with proper underwriting."
                    )
                elif factor.name == "Experience Factor":
                    recommendations.append(
                        "Assign enhanced supervision and mentoring for new producer. "
                        "Review first-year transactions more frequently."
                    )

        if risk_tier == "CRITICAL":
            recommendations.insert(
                0,
                "CRITICAL RISK: Recommend immediate suspension of unsupervised "
                "commission activity pending full investigation.",
            )
        elif risk_tier == "HIGH":
            recommendations.insert(
                0,
                "HIGH RISK: Recommend quarterly detailed audit and enhanced "
                "transaction monitoring.",
            )

        return recommendations
