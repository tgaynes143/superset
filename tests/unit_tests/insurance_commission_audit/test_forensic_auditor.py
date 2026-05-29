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
"""Tests for the forensic auditor engine."""

from __future__ import annotations

from datetime import date

from superset.insurance_commission_audit.forensic_auditor import (
    CarrierPayment,
    ForensicAuditor,
    PolicyRecord,
    RateScheduleEntry,
)


def _policy(
    num: str = "POL-001",
    carrier_code: str = "CARR-A",
    carrier_name: str = "Alpha Insurance",
    lob: str = "life",
    product: str = "Term Life",
    premium: float = 12000.0,
    eff: date = date(2026, 1, 1),
    exp: date | None = None,
    status: str = "active",
    cancel_date: date | None = None,
) -> PolicyRecord:
    return PolicyRecord(
        policy_number=num,
        carrier_code=carrier_code,
        carrier_name=carrier_name,
        line_of_business=lob,
        product_name=product,
        insured_name="Test Insured",
        effective_date=eff,
        expiry_date=exp or date(2027, 1, 1),
        annual_premium=premium,
        policy_status=status,
        cancel_date=cancel_date,
    )


def _rate(
    carrier_code: str = "CARR-A",
    carrier_name: str = "Alpha Insurance",
    lob: str = "life",
    product: str = "",
    rate: float = 0.55,
    eff: date | None = None,
) -> RateScheduleEntry:
    return RateScheduleEntry(
        carrier_code=carrier_code,
        carrier_name=carrier_name,
        line_of_business=lob,
        product_name=product,
        contracted_rate=rate,
        effective_date=eff,
    )


def _payment(
    pid: str = "PMT-001",
    carrier_code: str = "CARR-A",
    carrier_name: str = "Alpha Insurance",
    stmt_date: date = date(2026, 3, 15),
    policy_num: str = "POL-001",
    tx_type: str = "commission",
    amount: float = 6600.0,
    rate_applied: float = 0.55,
    premium_basis: float = 12000.0,
) -> CarrierPayment:
    return CarrierPayment(
        payment_id=pid,
        carrier_code=carrier_code,
        carrier_name=carrier_name,
        statement_date=stmt_date,
        policy_number=policy_num,
        transaction_type=tx_type,
        amount_paid=amount,
        commission_rate_applied=rate_applied,
        premium_basis=premium_basis,
    )


def _auditor(
    policies: list[PolicyRecord] | None = None,
    rates: list[RateScheduleEntry] | None = None,
    payments: list[CarrierPayment] | None = None,
) -> ForensicAuditor:
    return ForensicAuditor(
        policies=policies or [_policy()],
        rate_schedules=rates or [_rate()],
        carrier_payments=payments or [_payment()],
        audit_period_start=date(2026, 1, 1),
        audit_period_end=date(2026, 12, 31),
    )


# --- Basic reconciliation tests ---


def test_exact_match() -> None:
    auditor = _auditor()
    result = auditor.run_audit()
    matched = [r for r in result.reconciliation if r.status == "matched"]
    assert len(matched) == 1
    assert result.total_variance == 0.0


def test_underpayment_detected() -> None:
    auditor = _auditor(
        payments=[_payment(amount=5000.0, rate_applied=0.42)]
    )
    result = auditor.run_audit()
    underpaid = [r for r in result.reconciliation if r.status == "underpaid"]
    assert len(underpaid) == 1
    assert result.net_underpayment > 0


def test_missing_payment_detected() -> None:
    auditor = _auditor(payments=[])
    result = auditor.run_audit()
    missing = [r for r in result.reconciliation if r.status == "missing"]
    assert len(missing) == 1
    assert result.total_missing_payments == 1
    assert result.net_underpayment > 0


def test_overpayment_detected() -> None:
    auditor = _auditor(
        payments=[_payment(amount=10000.0, rate_applied=0.83)]
    )
    result = auditor.run_audit()
    overpaid = [r for r in result.reconciliation if r.status == "overpaid"]
    assert len(overpaid) == 1
    assert result.net_overpayment > 0


def test_unexpected_payment() -> None:
    payments = [
        _payment(),
        _payment(
            pid="PMT-EXTRA",
            policy_num="POL-UNKNOWN",
            amount=500.0,
        ),
    ]
    auditor = _auditor(payments=payments)
    result = auditor.run_audit()
    unexpected = [r for r in result.reconciliation if r.status == "unexpected"]
    assert len(unexpected) == 1


# --- Rate mismatch tests ---


def test_rate_mismatch_generates_evidence() -> None:
    auditor = _auditor(
        payments=[_payment(amount=4800.0, rate_applied=0.40)]
    )
    result = auditor.run_audit()
    rate_evidence = [
        e for e in result.evidence_package if e.category == "rate_mismatch"
    ]
    assert len(rate_evidence) >= 1
    assert rate_evidence[0].recovery_amount > 0


def test_no_rate_schedule_generates_gap_evidence() -> None:
    auditor = _auditor(rates=[])
    result = auditor.run_audit()
    gaps = [
        e for e in result.evidence_package if e.category == "rate_schedule_gap"
    ]
    assert len(gaps) == 1


# --- Chargeback tests ---


def test_chargeback_on_active_policy_flagged() -> None:
    payments = [
        _payment(),
        _payment(
            pid="CB-001",
            tx_type="chargeback",
            amount=-1000.0,
        ),
    ]
    auditor = _auditor(payments=payments)
    result = auditor.run_audit()
    assert result.chargeback_analysis["suspicious_count"] > 0
    cb_evidence = [
        e for e in result.evidence_package if e.category == "chargeback"
    ]
    assert len(cb_evidence) >= 1


def test_chargeback_without_notes_flagged() -> None:
    payments = [
        _payment(),
        CarrierPayment(
            payment_id="CB-002",
            carrier_code="CARR-A",
            carrier_name="Alpha Insurance",
            statement_date=date(2026, 4, 1),
            policy_number="POL-001",
            transaction_type="chargeback",
            amount_paid=-500.0,
            notes="",
        ),
    ]
    auditor = _auditor(payments=payments)
    result = auditor.run_audit()
    suspicious = result.chargeback_analysis.get("suspicious", [])
    no_reason = [s for s in suspicious if "No chargeback reason" in s.get("reason", "")]
    assert len(no_reason) >= 1


# --- Payment lag tests ---


def test_payment_lag_analysis() -> None:
    auditor = _auditor()
    result = auditor.run_audit()
    assert "carriers" in result.payment_lag_analysis
    assert "overall" in result.payment_lag_analysis


def test_slow_carrier_flagged() -> None:
    payments = [
        _payment(stmt_date=date(2026, 6, 1))  # 5 months after policy eff
    ]
    auditor = _auditor(
        payments=payments,
    )
    result = auditor.run_audit()
    lag_evidence = [
        e for e in result.evidence_package if e.category == "timing"
    ]
    assert len(lag_evidence) >= 1


# --- Earnings gap tests ---


def test_earnings_gap_with_underpayment() -> None:
    auditor = _auditor(payments=[_payment(amount=3000.0)])
    result = auditor.run_audit()
    gap = result.earnings_gap_analysis
    assert gap["totals"]["total_gap"] > 0


def test_earnings_gap_no_variance() -> None:
    auditor = _auditor()
    result = auditor.run_audit()
    gap = result.earnings_gap_analysis
    assert abs(gap["totals"]["total_gap"]) < 10


# --- Carrier scorecard tests ---


def test_carrier_scorecard_generated() -> None:
    auditor = _auditor()
    result = auditor.run_audit()
    assert len(result.carrier_scorecards) >= 1
    sc = result.carrier_scorecards[0]
    assert sc.carrier_code == "CARR-A"
    assert sc.grade in ("A", "B", "C", "D", "F")


def test_bad_carrier_scores_low() -> None:
    policies = [
        _policy(num=f"POL-{i:03d}") for i in range(5)
    ]
    payments = [
        _payment(pid=f"PMT-{i}", policy_num=f"POL-{i:03d}", amount=1000.0)
        for i in range(3)
    ]  # 2 missing payments
    auditor = _auditor(policies=policies, payments=payments)
    result = auditor.run_audit()
    sc = result.carrier_scorecards[0]
    assert sc.missing_payment_count >= 2
    assert sc.completeness_score < 100


# --- Evidence package tests ---


def test_evidence_has_recovery_amounts() -> None:
    auditor = _auditor(payments=[_payment(amount=3000.0)])
    result = auditor.run_audit()
    assert result.total_recovery_opportunity > 0
    recoverable = [e for e in result.evidence_package if e.recovery_amount > 0]
    assert len(recoverable) > 0


def test_evidence_has_statute_of_limitations() -> None:
    auditor = _auditor(payments=[])
    result = auditor.run_audit()
    for e in result.evidence_package:
        if e.recovery_amount > 0:
            assert e.statute_of_limitations_date is not None


def test_evidence_ids_unique() -> None:
    policies = [_policy(num=f"POL-{i:03d}") for i in range(5)]
    auditor = _auditor(policies=policies, payments=[])
    result = auditor.run_audit()
    ids = [e.evidence_id for e in result.evidence_package]
    assert len(ids) == len(set(ids))


# --- Forensic timeline tests ---


def test_timeline_ordered() -> None:
    auditor = _auditor()
    result = auditor.run_audit()
    dates = [e["date"] for e in result.timeline]
    assert dates == sorted(dates)


def test_timeline_includes_policy_and_payments() -> None:
    auditor = _auditor()
    result = auditor.run_audit()
    types = {e["type"] for e in result.timeline}
    assert "policy_effective" in types
    assert "payment_commission" in types


# --- Action generation tests ---


def test_immediate_actions_generated_for_missing() -> None:
    auditor = _auditor(payments=[])
    result = auditor.run_audit()
    assert any("MISSING" in a for a in result.immediate_actions)


def test_recovery_actions_sorted_by_amount() -> None:
    policies = [
        _policy(num="POL-001", premium=10000.0),
        _policy(num="POL-002", premium=50000.0),
    ]
    auditor = _auditor(policies=policies, payments=[])
    result = auditor.run_audit()
    if len(result.recovery_actions) >= 2:
        amounts = [a["recovery_amount"] for a in result.recovery_actions]
        assert amounts == sorted(amounts, reverse=True)


def test_process_improvements_generated() -> None:
    auditor = _auditor()
    result = auditor.run_audit()
    assert len(result.process_improvements) > 0
    assert any("reconciliation" in p.lower() for p in result.process_improvements)


# --- Multi-carrier tests ---


def test_multi_carrier_reconciliation() -> None:
    policies = [
        _policy(num="POL-A", carrier_code="CARR-A", carrier_name="Alpha"),
        _policy(num="POL-B", carrier_code="CARR-B", carrier_name="Beta"),
    ]
    rates = [
        _rate(carrier_code="CARR-A", carrier_name="Alpha"),
        _rate(carrier_code="CARR-B", carrier_name="Beta", rate=0.45),
    ]
    payments = [
        _payment(pid="P1", policy_num="POL-A"),
        _payment(
            pid="P2",
            carrier_code="CARR-B",
            carrier_name="Beta",
            policy_num="POL-B",
            amount=5400.0,
            rate_applied=0.45,
        ),
    ]
    auditor = _auditor(policies=policies, rates=rates, payments=payments)
    result = auditor.run_audit()
    assert len(result.carrier_scorecards) == 2


# --- Premium proration tests ---


def test_premium_proration_full_year() -> None:
    result = ForensicAuditor._prorate_premium(
        annual_premium=12000.0,
        policy_start=date(2026, 1, 1),
        policy_end=date(2027, 1, 1),
        period_start=date(2026, 1, 1),
        period_end=date(2026, 12, 31),
    )
    assert abs(result - 12000.0) < 50  # close to full year


def test_premium_proration_cancelled_policy() -> None:
    result = ForensicAuditor._prorate_premium(
        annual_premium=12000.0,
        policy_start=date(2026, 1, 1),
        policy_end=date(2027, 1, 1),
        period_start=date(2026, 1, 1),
        period_end=date(2026, 12, 31),
        cancel_date=date(2026, 7, 1),
    )
    assert result < 12000.0
    assert result > 0


def test_premium_proration_mid_year_effective() -> None:
    result = ForensicAuditor._prorate_premium(
        annual_premium=12000.0,
        policy_start=date(2026, 7, 1),
        policy_end=date(2027, 7, 1),
        period_start=date(2026, 1, 1),
        period_end=date(2026, 12, 31),
    )
    assert result < 12000.0
    assert result > 0


def test_policy_year_calculation() -> None:
    assert ForensicAuditor._calculate_policy_year(date(2026, 1, 1), date(2026, 6, 1)) == 1
    assert ForensicAuditor._calculate_policy_year(date(2025, 1, 1), date(2026, 6, 1)) == 2
    assert ForensicAuditor._calculate_policy_year(date(2023, 1, 1), date(2026, 6, 1)) == 4


# --- Score to grade tests ---


def test_score_to_grade() -> None:
    assert ForensicAuditor._score_to_grade(95) == "A"
    assert ForensicAuditor._score_to_grade(85) == "B"
    assert ForensicAuditor._score_to_grade(75) == "C"
    assert ForensicAuditor._score_to_grade(65) == "D"
    assert ForensicAuditor._score_to_grade(50) == "F"
