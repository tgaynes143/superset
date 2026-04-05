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
"""Tests for the risk scoring engine."""

from __future__ import annotations

import pytest

from superset.insurance_commission_audit.risk_scoring import (
    ProducerMetrics,
    RiskScoringEngine,
)


def _low_risk_metrics() -> ProducerMetrics:
    return ProducerMetrics(
        producer_id=1,
        total_transactions=100,
        total_commission=50000.0,
        total_premium=500000.0,
        avg_commission_rate=0.10,
        max_commission_rate=0.12,
        chargeback_count=0,
        chargeback_amount=0.0,
        unique_carriers=5,
        dominant_carrier_pct=0.30,
        license_expired=False,
        days_until_license_expiry=365,
        open_findings_count=0,
        critical_findings_count=0,
        high_findings_count=0,
        end_of_quarter_pct=0.15,
        peer_avg_commission_rate=0.10,
        peer_avg_volume=50000.0,
        years_of_experience=10.0,
    )


def _high_risk_metrics() -> ProducerMetrics:
    return ProducerMetrics(
        producer_id=2,
        total_transactions=200,
        total_commission=200000.0,
        total_premium=1000000.0,
        avg_commission_rate=0.20,
        max_commission_rate=0.35,
        chargeback_count=25,
        chargeback_amount=12500.0,
        unique_carriers=1,
        dominant_carrier_pct=1.0,
        license_expired=True,
        days_until_license_expiry=-30,
        open_findings_count=5,
        critical_findings_count=2,
        high_findings_count=3,
        end_of_quarter_pct=0.55,
        peer_avg_commission_rate=0.10,
        peer_avg_volume=50000.0,
        years_of_experience=0.5,
    )


def test_low_risk_producer() -> None:
    engine = RiskScoringEngine()
    profile = engine.score_producer(_low_risk_metrics())
    assert profile.composite_score < 20
    assert profile.risk_tier == "LOW"


def test_high_risk_producer() -> None:
    engine = RiskScoringEngine()
    profile = engine.score_producer(_high_risk_metrics())
    assert profile.composite_score > 60
    assert profile.risk_tier in ("HIGH", "CRITICAL")
    assert len(profile.recommendations) > 0


def test_risk_tier_boundaries() -> None:
    assert RiskScoringEngine._determine_tier(5) == "LOW"
    assert RiskScoringEngine._determine_tier(25) == "MODERATE"
    assert RiskScoringEngine._determine_tier(45) == "ELEVATED"
    assert RiskScoringEngine._determine_tier(65) == "HIGH"
    assert RiskScoringEngine._determine_tier(85) == "CRITICAL"


def test_batch_scoring_sorted_by_risk() -> None:
    engine = RiskScoringEngine()
    profiles = engine.score_producers([_low_risk_metrics(), _high_risk_metrics()])
    assert len(profiles) == 2
    assert profiles[0].composite_score >= profiles[1].composite_score
    assert profiles[0].producer_id == 2  # high risk first


def test_risk_factors_count() -> None:
    engine = RiskScoringEngine()
    profile = engine.score_producer(_low_risk_metrics())
    assert len(profile.factors) == 8


def test_recommendations_for_critical_risk() -> None:
    engine = RiskScoringEngine()
    profile = engine.score_producer(_high_risk_metrics())
    recs = profile.recommendations
    assert any("CRITICAL" in r or "suspension" in r.lower() for r in recs)


def test_invalid_weights_rejected() -> None:
    with pytest.raises(ValueError, match="must sum to 1.0"):
        RiskScoringEngine(weights={"commission_rate_deviation": 0.5})


def test_expired_license_high_score() -> None:
    engine = RiskScoringEngine()
    metrics = _low_risk_metrics()
    metrics.license_expired = True
    metrics.days_until_license_expiry = -10
    profile = engine.score_producer(metrics)
    license_factor = next(f for f in profile.factors if f.name == "License Status")
    assert license_factor.raw_score == 1.0


def test_new_producer_experience_risk() -> None:
    engine = RiskScoringEngine()
    metrics = _low_risk_metrics()
    metrics.years_of_experience = 0.3
    profile = engine.score_producer(metrics)
    exp_factor = next(f for f in profile.factors if f.name == "Experience Factor")
    assert exp_factor.raw_score == 0.8
