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
"""Tests for the anomaly detection engine."""

from __future__ import annotations

from datetime import date, timedelta

from superset.insurance_commission_audit.anomaly_detection import (
    AnomalyDetector,
    TransactionRecord,
)


def _make_tx(
    id: int,
    amount: float,
    rate: float = 0.10,
    premium: float = 10000.0,
    producer_id: int = 1,
    tx_date: date | None = None,
    policy: str = "POL-001",
    carrier: str = "ABC Insurance",
    lob: str = "life",
) -> TransactionRecord:
    return TransactionRecord(
        id=id,
        producer_id=producer_id,
        commission_amount=amount,
        commission_rate=rate,
        premium_amount=premium,
        transaction_date=tx_date or date(2026, 1, 15),
        policy_number=policy,
        line_of_business=lob,
        carrier_name=carrier,
    )


def test_zscore_no_outliers() -> None:
    detector = AnomalyDetector()
    txns = [_make_tx(i, 1000.0 + i) for i in range(20)]
    result = detector.check_zscore_outliers(txns)
    assert result.score == 0.0
    assert len(result.flagged_transaction_ids) == 0


def test_zscore_detects_outlier() -> None:
    detector = AnomalyDetector(z_score_threshold=2.0)
    txns = [_make_tx(i, 1000.0) for i in range(20)]
    txns.append(_make_tx(99, 50000.0))  # extreme outlier
    result = detector.check_zscore_outliers(txns)
    assert 99 in result.flagged_transaction_ids
    assert result.score > 0


def test_zscore_insufficient_data() -> None:
    detector = AnomalyDetector()
    txns = [_make_tx(1, 100.0), _make_tx(2, 200.0)]
    result = detector.check_zscore_outliers(txns)
    assert result.score == 0.0


def test_duplicate_detection() -> None:
    detector = AnomalyDetector()
    txns = [
        _make_tx(1, 1500.0, tx_date=date(2026, 1, 15), policy="POL-001"),
        _make_tx(2, 1500.0, tx_date=date(2026, 1, 15), policy="POL-001"),
        _make_tx(3, 2000.0, tx_date=date(2026, 1, 16), policy="POL-002"),
    ]
    result = detector.check_duplicates(txns)
    assert len(result.flagged_transaction_ids) == 2
    assert 1 in result.flagged_transaction_ids
    assert 2 in result.flagged_transaction_ids


def test_no_duplicates() -> None:
    detector = AnomalyDetector()
    txns = [
        _make_tx(1, 1500.0, tx_date=date(2026, 1, 15), policy="POL-001"),
        _make_tx(2, 2500.0, tx_date=date(2026, 1, 15), policy="POL-002"),
    ]
    result = detector.check_duplicates(txns)
    assert len(result.flagged_transaction_ids) == 0


def test_round_number_normal() -> None:
    detector = AnomalyDetector(round_number_threshold=0.50)
    txns = [_make_tx(i, 1234.56 + i * 0.01) for i in range(20)]
    result = detector.check_round_numbers(txns)
    assert len(result.violations) == 0


def test_round_number_suspicious() -> None:
    detector = AnomalyDetector(round_number_threshold=0.20)
    txns = [_make_tx(i, float(1000 * (i + 1))) for i in range(20)]
    result = detector.check_round_numbers(txns)
    assert len(result.violations) > 0
    assert result.details["round_pct"] > 20


def test_split_transaction_detection() -> None:
    detector = AnomalyDetector(
        split_threshold_amount=5000.0,
        split_window_days=3,
    )
    base_date = date(2026, 3, 1)
    txns = [
        _make_tx(1, 2500.0, tx_date=base_date, policy="POL-001"),
        _make_tx(2, 2600.0, tx_date=base_date + timedelta(days=1), policy="POL-001"),
    ]
    result = detector.check_split_transactions(txns)
    assert len(result.flagged_transaction_ids) >= 2


def test_velocity_normal() -> None:
    detector = AnomalyDetector(velocity_max_transactions=10, velocity_window_days=7)
    txns = [
        _make_tx(i, 100.0, tx_date=date(2026, 1, 1) + timedelta(days=i * 3))
        for i in range(5)
    ]
    result = detector.check_velocity_anomalies(txns)
    assert len(result.violations) == 0


def test_velocity_spike() -> None:
    detector = AnomalyDetector(velocity_max_transactions=5, velocity_window_days=7)
    base = date(2026, 3, 1)
    txns = [_make_tx(i, 100.0, tx_date=base + timedelta(days=i % 2)) for i in range(10)]
    result = detector.check_velocity_anomalies(txns)
    assert len(result.violations) > 0


def test_rate_consistency_normal() -> None:
    detector = AnomalyDetector()
    txns = [_make_tx(i, 1000.0, rate=0.10, carrier="ABC") for i in range(10)]
    result = detector.check_rate_consistency(txns)
    assert len(result.flagged_transaction_ids) == 0


def test_run_all_checks_returns_all() -> None:
    detector = AnomalyDetector()
    txns = [_make_tx(i, 1000.0 + i * 10) for i in range(20)]
    results = detector.run_all_checks(txns)
    assert len(results) == 7
    check_names = {r.check_name for r in results}
    assert "Z-Score Outlier Detection" in check_names
    assert "Benford's Law Analysis" in check_names
    assert "Transaction Velocity Analysis" in check_names
    assert "Duplicate Transaction Detection" in check_names
    assert "Round Number Analysis" in check_names
    assert "Split Transaction Detection" in check_names
    assert "Rate Consistency Analysis" in check_names


def test_empty_transactions() -> None:
    detector = AnomalyDetector()
    results = detector.run_all_checks([])
    assert len(results) == 0
