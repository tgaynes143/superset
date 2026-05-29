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
"""Forensic auditor engine for carrier commission payment verification.

The core problem: carriers pay you commissions and you have no
independent way to verify those payments are correct. This engine
acts as your forensic auditor — it independently calculates what
you SHOULD have been paid, compares it against what you WERE paid,
and builds evidence packages for every discrepancy.

Capabilities:
- Expected commission calculation from policy/rate schedule data
- Carrier payment reconciliation against expected amounts
- Underpayment/overpayment/missing payment detection
- Payment lag analysis (how long carriers take to pay)
- Carrier reliability scoring
- Rate schedule verification against contracted rates
- Forensic timeline reconstruction
- Evidence package compilation for dispute/recovery
- Earnings-vs-paid gap analysis
- Chargeback legitimacy verification
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

logger = logging.getLogger(__name__)


# --- Data structures ---


@dataclass
class PolicyRecord:
    """A policy that should generate commission earnings."""

    policy_number: str
    carrier_name: str
    carrier_code: str
    line_of_business: str
    product_name: str
    insured_name: str
    effective_date: date
    expiry_date: date | None = None
    annual_premium: float = 0.0
    policy_status: str = "active"  # active, lapsed, cancelled, renewed
    writing_producer_npn: str = ""
    servicing_producer_npn: str = ""
    cancel_date: date | None = None
    cancel_reason: str = ""


@dataclass
class RateScheduleEntry:
    """A contracted commission rate from a carrier agreement."""

    carrier_code: str
    carrier_name: str
    line_of_business: str
    product_name: str = ""
    commission_type: str = "new_business"
    policy_year: int = 1
    contracted_rate: float = 0.0
    effective_date: date | None = None
    expiry_date: date | None = None
    tier_minimum_premium: float = 0.0
    tier_maximum_premium: float | None = None
    bonus_eligible: bool = False
    notes: str = ""


@dataclass
class CarrierPayment:
    """An actual commission payment received from a carrier."""

    payment_id: str
    carrier_code: str
    carrier_name: str
    statement_date: date
    policy_number: str
    transaction_type: str  # commission, chargeback, bonus, adjustment, override
    line_of_business: str = ""
    premium_basis: float = 0.0
    commission_rate_applied: float = 0.0
    amount_paid: float = 0.0
    payment_period_start: date | None = None
    payment_period_end: date | None = None
    check_number: str = ""
    eft_reference: str = ""
    producer_npn: str = ""
    notes: str = ""


@dataclass
class ExpectedCommission:
    """What we calculated the carrier SHOULD pay."""

    policy_number: str
    carrier_code: str
    line_of_business: str
    commission_type: str
    policy_year: int
    premium_basis: float
    expected_rate: float
    expected_amount: float
    earning_period_start: date
    earning_period_end: date
    rate_schedule_source: str = ""
    calculation_notes: str = ""


@dataclass
class ReconciliationItem:
    """A single line in the reconciliation — expected vs actual."""

    policy_number: str
    carrier_code: str
    carrier_name: str
    line_of_business: str
    expected_amount: float
    actual_amount: float
    variance: float
    variance_pct: float
    status: str  # matched, underpaid, overpaid, missing, unexpected, disputed
    expected_rate: float = 0.0
    actual_rate: float = 0.0
    premium_basis: float = 0.0
    payment_ids: list[str] = field(default_factory=list)
    evidence_notes: list[str] = field(default_factory=list)
    severity: str = "info"  # info, low, medium, high, critical
    days_outstanding: int | None = None


@dataclass
class CarrierScorecard:
    """Reliability scorecard for a single carrier."""

    carrier_code: str
    carrier_name: str
    accuracy_score: float  # 0-100: how often they pay correct amounts
    timeliness_score: float  # 0-100: how quickly they pay
    completeness_score: float  # 0-100: do they pay on all policies
    dispute_resolution_score: float  # 0-100: how well they resolve issues
    overall_score: float  # weighted composite
    grade: str  # A, B, C, D, F

    total_policies: int = 0
    total_expected: float = 0.0
    total_paid: float = 0.0
    total_variance: float = 0.0
    underpayment_count: int = 0
    missing_payment_count: int = 0
    avg_payment_lag_days: float = 0.0
    max_payment_lag_days: int = 0
    chargeback_rate: float = 0.0

    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class ForensicEvidence:
    """An evidence item for a specific discrepancy."""

    evidence_id: str
    category: str  # underpayment, missing, rate_mismatch, timing, chargeback
    severity: str
    policy_number: str
    carrier_code: str
    carrier_name: str
    description: str
    expected_value: str
    actual_value: str
    variance_amount: float
    supporting_facts: list[str] = field(default_factory=list)
    recommended_action: str = ""
    recovery_amount: float = 0.0
    statute_of_limitations_date: date | None = None


@dataclass
class ForensicAuditResult:
    """Complete result of running the forensic auditor."""

    # Summary
    total_policies_audited: int
    total_expected_commission: float
    total_actual_paid: float
    total_variance: float
    net_underpayment: float
    net_overpayment: float
    total_missing_payments: int
    total_recovery_opportunity: float

    # Detailed results
    reconciliation: list[ReconciliationItem]
    carrier_scorecards: list[CarrierScorecard]
    evidence_package: list[ForensicEvidence]
    payment_lag_analysis: dict[str, Any]
    earnings_gap_analysis: dict[str, Any]
    chargeback_analysis: dict[str, Any]
    timeline: list[dict[str, Any]]

    # Action items
    immediate_actions: list[str]
    recovery_actions: list[dict[str, Any]]
    process_improvements: list[str]


class ForensicAuditor:
    """Forensic auditor that independently verifies carrier commission payments.

    Feed it your policies, your carrier rate schedules, and the payments
    you received. It will tell you exactly where you're being shortchanged.
    """

    def __init__(
        self,
        policies: list[PolicyRecord],
        rate_schedules: list[RateScheduleEntry],
        carrier_payments: list[CarrierPayment],
        audit_period_start: date | None = None,
        audit_period_end: date | None = None,
        payment_lag_threshold_days: int = 45,
        variance_tolerance_pct: float = 0.005,
        variance_tolerance_abs: float = 1.00,
        statute_of_limitations_years: int = 3,
    ) -> None:
        self._policies = {p.policy_number: p for p in policies}
        self._rate_schedules = rate_schedules
        self._payments = carrier_payments
        self._period_start = audit_period_start or date.today().replace(
            month=1, day=1
        )
        self._period_end = audit_period_end or date.today()
        self._lag_threshold = payment_lag_threshold_days
        self._var_tol_pct = variance_tolerance_pct
        self._var_tol_abs = variance_tolerance_abs
        self._sol_years = statute_of_limitations_years

        # Indexes built during audit
        self._rate_index: dict[str, list[RateScheduleEntry]] = {}
        self._payment_index: dict[str, list[CarrierPayment]] = {}
        self._expected: list[ExpectedCommission] = []
        self._evidence: list[ForensicEvidence] = []
        self._evidence_counter = 0

    def run_audit(self) -> ForensicAuditResult:
        """Execute the complete forensic audit pipeline."""
        self._build_indexes()
        self._expected = self._calculate_all_expected()
        reconciliation = self._reconcile()
        scorecards = self._build_carrier_scorecards(reconciliation)
        lag_analysis = self._analyze_payment_lags()
        earnings_gap = self._analyze_earnings_gap()
        chargeback_analysis = self._analyze_chargebacks()
        timeline = self._build_forensic_timeline()

        total_expected = sum(e.expected_amount for e in self._expected)
        total_paid = sum(
            p.amount_paid
            for p in self._payments
            if p.transaction_type != "chargeback"
        )
        underpaid = sum(
            r.variance for r in reconciliation if r.status == "underpaid"
        )
        overpaid = sum(
            abs(r.variance) for r in reconciliation if r.status == "overpaid"
        )
        missing = [r for r in reconciliation if r.status == "missing"]
        missing_total = sum(r.expected_amount for r in missing)

        recovery_total = sum(e.recovery_amount for e in self._evidence)

        immediate = self._generate_immediate_actions(reconciliation, scorecards)
        recovery_actions = self._generate_recovery_actions()
        improvements = self._generate_process_improvements(
            scorecards, lag_analysis, chargeback_analysis
        )

        return ForensicAuditResult(
            total_policies_audited=len(self._policies),
            total_expected_commission=round(total_expected, 2),
            total_actual_paid=round(total_paid, 2),
            total_variance=round(total_expected - total_paid, 2),
            net_underpayment=round(abs(underpaid) + missing_total, 2),
            net_overpayment=round(overpaid, 2),
            total_missing_payments=len(missing),
            total_recovery_opportunity=round(recovery_total, 2),
            reconciliation=reconciliation,
            carrier_scorecards=scorecards,
            evidence_package=self._evidence,
            payment_lag_analysis=lag_analysis,
            earnings_gap_analysis=earnings_gap,
            chargeback_analysis=chargeback_analysis,
            timeline=timeline,
            immediate_actions=immediate,
            recovery_actions=recovery_actions,
            process_improvements=improvements,
        )

    # --- Index building ---

    def _build_indexes(self) -> None:
        """Build lookup indexes for fast matching."""
        self._rate_index = defaultdict(list)
        for rs in self._rate_schedules:
            key = f"{rs.carrier_code}:{rs.line_of_business}"
            self._rate_index[key].append(rs)
            if rs.product_name:
                pkey = f"{rs.carrier_code}:{rs.line_of_business}:{rs.product_name}"
                self._rate_index[pkey].append(rs)

        self._payment_index = defaultdict(list)
        for pmt in self._payments:
            self._payment_index[pmt.policy_number].append(pmt)

    # --- Expected commission calculation ---

    def _calculate_all_expected(self) -> list[ExpectedCommission]:
        """Calculate expected commissions for every in-scope policy."""
        expected: list[ExpectedCommission] = []
        for policy in self._policies.values():
            exps = self._calculate_expected_for_policy(policy)
            expected.extend(exps)
        return expected

    def _calculate_expected_for_policy(
        self, policy: PolicyRecord
    ) -> list[ExpectedCommission]:
        """Calculate all expected commission entries for a single policy."""
        results: list[ExpectedCommission] = []

        if policy.policy_status == "cancelled" and policy.cancel_date:
            if policy.cancel_date < self._period_start:
                return results

        rate_entry = self._find_rate_schedule(
            carrier_code=policy.carrier_code,
            line_of_business=policy.line_of_business,
            product_name=policy.product_name,
            premium=policy.annual_premium,
            effective_date=policy.effective_date,
        )

        if not rate_entry:
            self._add_evidence(
                category="rate_schedule_gap",
                severity="medium",
                policy_number=policy.policy_number,
                carrier_code=policy.carrier_code,
                carrier_name=policy.carrier_name,
                description=(
                    f"No rate schedule found for carrier {policy.carrier_name} "
                    f"({policy.carrier_code}), LOB {policy.line_of_business}, "
                    f"product {policy.product_name}. Cannot independently "
                    f"verify commission payments."
                ),
                expected_value="Rate schedule on file",
                actual_value="No rate schedule found",
                variance_amount=0.0,
                facts=[
                    f"Policy: {policy.policy_number}",
                    f"Carrier: {policy.carrier_name}",
                    f"Premium: ${policy.annual_premium:,.2f}",
                ],
                action="Obtain carrier contract and rate schedule.",
            )
            return results

        policy_year = self._calculate_policy_year(
            policy.effective_date, self._period_start
        )
        commission_type = "renewal" if policy_year > 1 else "new_business"

        # Calculate the premium basis for the audit period
        premium_basis = self._prorate_premium(
            policy.annual_premium,
            policy.effective_date,
            policy.expiry_date or (policy.effective_date.replace(
                year=policy.effective_date.year + 1
            )),
            self._period_start,
            self._period_end,
            policy.cancel_date,
        )

        if premium_basis <= 0:
            return results

        expected_amount = premium_basis * rate_entry.contracted_rate

        results.append(
            ExpectedCommission(
                policy_number=policy.policy_number,
                carrier_code=policy.carrier_code,
                line_of_business=policy.line_of_business,
                commission_type=commission_type,
                policy_year=policy_year,
                premium_basis=premium_basis,
                expected_rate=rate_entry.contracted_rate,
                expected_amount=round(expected_amount, 2),
                earning_period_start=self._period_start,
                earning_period_end=self._period_end,
                rate_schedule_source=(
                    f"{rate_entry.carrier_name} schedule "
                    f"eff. {rate_entry.effective_date}"
                ),
                calculation_notes=(
                    f"Year {policy_year} {commission_type} @ "
                    f"{rate_entry.contracted_rate:.4f} on "
                    f"${premium_basis:,.2f} premium basis"
                ),
            )
        )

        return results

    def _find_rate_schedule(
        self,
        carrier_code: str,
        line_of_business: str,
        product_name: str,
        premium: float,
        effective_date: date,
    ) -> RateScheduleEntry | None:
        """Find the best matching rate schedule for a policy."""
        # Try product-specific first
        pkey = f"{carrier_code}:{line_of_business}:{product_name}"
        candidates = self._rate_index.get(pkey, [])

        if not candidates:
            key = f"{carrier_code}:{line_of_business}"
            candidates = self._rate_index.get(key, [])

        if not candidates:
            return None

        # Filter by date and premium tier
        valid: list[RateScheduleEntry] = []
        for rs in candidates:
            if rs.effective_date and effective_date < rs.effective_date:
                continue
            if rs.expiry_date and effective_date > rs.expiry_date:
                continue
            if rs.tier_minimum_premium and premium < rs.tier_minimum_premium:
                continue
            if rs.tier_maximum_premium and premium > rs.tier_maximum_premium:
                continue
            valid.append(rs)

        if not valid:
            return candidates[0] if candidates else None

        # Prefer product-specific, then highest tier match
        valid.sort(
            key=lambda r: (
                bool(r.product_name),
                r.tier_minimum_premium,
            ),
            reverse=True,
        )
        return valid[0]

    # --- Reconciliation ---

    def _reconcile(self) -> list[ReconciliationItem]:
        """Match expected commissions against actual carrier payments."""
        items: list[ReconciliationItem] = []

        # Group expected by policy
        expected_by_policy: dict[str, float] = defaultdict(float)
        expected_rate_by_policy: dict[str, float] = {}
        expected_premium_by_policy: dict[str, float] = defaultdict(float)
        expected_carrier: dict[str, tuple[str, str, str]] = {}

        for exp in self._expected:
            expected_by_policy[exp.policy_number] += exp.expected_amount
            expected_rate_by_policy[exp.policy_number] = exp.expected_rate
            expected_premium_by_policy[exp.policy_number] += exp.premium_basis
            policy = self._policies.get(exp.policy_number)
            if policy:
                expected_carrier[exp.policy_number] = (
                    exp.carrier_code,
                    policy.carrier_name,
                    exp.line_of_business,
                )

        # Group actual payments by policy (exclude chargebacks for main recon)
        actual_by_policy: dict[str, float] = defaultdict(float)
        actual_rate_by_policy: dict[str, float] = {}
        payment_ids_by_policy: dict[str, list[str]] = defaultdict(list)

        for pmt in self._payments:
            if pmt.transaction_type == "chargeback":
                continue
            actual_by_policy[pmt.policy_number] += pmt.amount_paid
            if pmt.commission_rate_applied > 0:
                actual_rate_by_policy[pmt.policy_number] = (
                    pmt.commission_rate_applied
                )
            payment_ids_by_policy[pmt.policy_number].append(pmt.payment_id)

        # Reconcile: expected policies
        all_policies = set(expected_by_policy.keys()) | set(
            actual_by_policy.keys()
        )

        for pol_num in sorted(all_policies):
            exp_amt = expected_by_policy.get(pol_num, 0.0)
            act_amt = actual_by_policy.get(pol_num, 0.0)
            variance = exp_amt - act_amt
            var_pct = (variance / exp_amt) if exp_amt != 0 else 0.0

            carrier_info = expected_carrier.get(pol_num, ("", "", ""))
            # Fallback to payment data for unexpected
            if not carrier_info[0]:
                pmts = self._payment_index.get(pol_num, [])
                if pmts:
                    carrier_info = (
                        pmts[0].carrier_code,
                        pmts[0].carrier_name,
                        pmts[0].line_of_business,
                    )

            status = self._determine_recon_status(exp_amt, act_amt, variance)
            severity = self._determine_variance_severity(
                variance, exp_amt, status
            )

            evidence_notes: list[str] = []
            if status == "underpaid":
                evidence_notes.append(
                    f"Carrier underpaid by ${abs(variance):,.2f} "
                    f"({abs(var_pct):.1%})"
                )
                self._add_underpayment_evidence(
                    pol_num, carrier_info, exp_amt, act_amt, variance,
                    expected_rate_by_policy.get(pol_num, 0),
                    actual_rate_by_policy.get(pol_num, 0),
                    expected_premium_by_policy.get(pol_num, 0),
                )
            elif status == "missing":
                evidence_notes.append(
                    f"No payment received for ${exp_amt:,.2f} expected"
                )
                self._add_missing_payment_evidence(
                    pol_num, carrier_info, exp_amt,
                    expected_rate_by_policy.get(pol_num, 0),
                    expected_premium_by_policy.get(pol_num, 0),
                )
            elif status == "unexpected":
                evidence_notes.append(
                    f"Payment of ${act_amt:,.2f} received with no "
                    f"matching policy expectation"
                )

            # Check rate mismatch
            exp_rate = expected_rate_by_policy.get(pol_num, 0)
            act_rate = actual_rate_by_policy.get(pol_num, 0)
            if exp_rate > 0 and act_rate > 0 and abs(exp_rate - act_rate) > 0.001:
                evidence_notes.append(
                    f"Rate mismatch: contracted {exp_rate:.4f} vs "
                    f"paid {act_rate:.4f}"
                )
                self._add_rate_mismatch_evidence(
                    pol_num, carrier_info, exp_rate, act_rate,
                    expected_premium_by_policy.get(pol_num, 0),
                )

            items.append(
                ReconciliationItem(
                    policy_number=pol_num,
                    carrier_code=carrier_info[0],
                    carrier_name=carrier_info[1],
                    line_of_business=carrier_info[2],
                    expected_amount=round(exp_amt, 2),
                    actual_amount=round(act_amt, 2),
                    variance=round(variance, 2),
                    variance_pct=round(var_pct, 4),
                    status=status,
                    expected_rate=exp_rate,
                    actual_rate=act_rate,
                    premium_basis=expected_premium_by_policy.get(pol_num, 0),
                    payment_ids=payment_ids_by_policy.get(pol_num, []),
                    evidence_notes=evidence_notes,
                    severity=severity,
                )
            )

        return items

    def _determine_recon_status(
        self, expected: float, actual: float, variance: float
    ) -> str:
        """Classify the reconciliation status."""
        if expected == 0 and actual > 0:
            return "unexpected"
        if actual == 0 and expected > 0:
            return "missing"
        if abs(variance) <= self._var_tol_abs:
            return "matched"
        if expected > 0 and abs(variance / expected) <= self._var_tol_pct:
            return "matched"
        if variance > 0:
            return "underpaid"
        return "overpaid"

    def _determine_variance_severity(
        self, variance: float, expected: float, status: str
    ) -> str:
        """Determine severity of a variance."""
        if status == "matched":
            return "info"
        abs_var = abs(variance)
        if status == "missing":
            if expected > 5000:
                return "critical"
            if expected > 1000:
                return "high"
            return "medium"
        if abs_var > 5000:
            return "critical"
        if abs_var > 1000:
            return "high"
        if abs_var > 100:
            return "medium"
        return "low"

    # --- Payment lag analysis ---

    def _analyze_payment_lags(self) -> dict[str, Any]:
        """Analyze how long carriers take to pay commissions."""
        carrier_lags: dict[str, list[int]] = defaultdict(list)

        for pmt in self._payments:
            if pmt.transaction_type == "chargeback":
                continue
            policy = self._policies.get(pmt.policy_number)
            if not policy:
                continue

            # Lag = statement date - policy effective (for new biz)
            #   or statement date - renewal date (for renewals)
            reference_date = policy.effective_date
            lag_days = (pmt.statement_date - reference_date).days
            if 0 < lag_days < 365:
                carrier_lags[pmt.carrier_code].append(lag_days)

        result: dict[str, Any] = {"carriers": {}, "overall": {}}
        all_lags: list[int] = []

        for carrier_code, lags in carrier_lags.items():
            if not lags:
                continue
            all_lags.extend(lags)
            avg_lag = sum(lags) / len(lags)
            max_lag = max(lags)
            late_count = sum(1 for l in lags if l > self._lag_threshold)

            carrier_name = ""
            for pmt in self._payments:
                if pmt.carrier_code == carrier_code:
                    carrier_name = pmt.carrier_name
                    break

            result["carriers"][carrier_code] = {
                "carrier_name": carrier_name,
                "avg_lag_days": round(avg_lag, 1),
                "max_lag_days": max_lag,
                "min_lag_days": min(lags),
                "payment_count": len(lags),
                "late_payments": late_count,
                "late_pct": round(late_count / len(lags) * 100, 1),
                "threshold_days": self._lag_threshold,
            }

            if avg_lag > self._lag_threshold:
                self._add_evidence(
                    category="timing",
                    severity="medium",
                    policy_number="AGGREGATE",
                    carrier_code=carrier_code,
                    carrier_name=carrier_name,
                    description=(
                        f"Carrier {carrier_name} averages {avg_lag:.0f} days "
                        f"to pay commissions (threshold: {self._lag_threshold} "
                        f"days). {late_count} of {len(lags)} payments were late."
                    ),
                    expected_value=f"<= {self._lag_threshold} days",
                    actual_value=f"{avg_lag:.0f} days average",
                    variance_amount=0.0,
                    facts=[
                        f"Max lag: {max_lag} days",
                        f"Late payment rate: {late_count / len(lags):.0%}",
                    ],
                    action="Escalate payment timeliness with carrier.",
                )

        if all_lags:
            result["overall"] = {
                "avg_lag_days": round(sum(all_lags) / len(all_lags), 1),
                "max_lag_days": max(all_lags),
                "total_payments_analyzed": len(all_lags),
            }

        return result

    # --- Earnings gap analysis ---

    def _analyze_earnings_gap(self) -> dict[str, Any]:
        """Analyze the gap between earned commissions and actual payments."""
        carrier_gaps: dict[str, dict[str, float]] = defaultdict(
            lambda: {"expected": 0.0, "actual": 0.0}
        )

        for exp in self._expected:
            carrier_gaps[exp.carrier_code]["expected"] += exp.expected_amount

        for pmt in self._payments:
            if pmt.transaction_type != "chargeback":
                carrier_gaps[pmt.carrier_code]["actual"] += pmt.amount_paid

        result: dict[str, Any] = {"carriers": {}, "totals": {}}
        total_exp = 0.0
        total_act = 0.0

        for code, data in carrier_gaps.items():
            gap = data["expected"] - data["actual"]
            gap_pct = gap / data["expected"] if data["expected"] > 0 else 0
            total_exp += data["expected"]
            total_act += data["actual"]

            carrier_name = ""
            for pmt in self._payments:
                if pmt.carrier_code == code:
                    carrier_name = pmt.carrier_name
                    break

            result["carriers"][code] = {
                "carrier_name": carrier_name,
                "expected": round(data["expected"], 2),
                "actual": round(data["actual"], 2),
                "gap": round(gap, 2),
                "gap_pct": round(gap_pct * 100, 1),
            }

        result["totals"] = {
            "total_expected": round(total_exp, 2),
            "total_actual": round(total_act, 2),
            "total_gap": round(total_exp - total_act, 2),
            "gap_pct": round(
                (total_exp - total_act) / total_exp * 100, 1
            )
            if total_exp > 0
            else 0,
        }

        return result

    # --- Chargeback analysis ---

    def _analyze_chargebacks(self) -> dict[str, Any]:
        """Forensic analysis of carrier chargebacks."""
        chargebacks = [
            p for p in self._payments if p.transaction_type == "chargeback"
        ]

        if not chargebacks:
            return {
                "total_chargebacks": 0,
                "total_amount": 0,
                "carriers": {},
                "suspicious": [],
            }

        carrier_cbs: dict[str, list[CarrierPayment]] = defaultdict(list)
        for cb in chargebacks:
            carrier_cbs[cb.carrier_code].append(cb)

        suspicious: list[dict[str, Any]] = []
        carrier_details: dict[str, dict[str, Any]] = {}

        for code, cbs in carrier_cbs.items():
            total_cb = sum(abs(c.amount_paid) for c in cbs)
            carrier_name = cbs[0].carrier_name

            # Check for chargebacks on active policies
            for cb in cbs:
                policy = self._policies.get(cb.policy_number)
                if policy and policy.policy_status == "active":
                    suspicious.append(
                        {
                            "payment_id": cb.payment_id,
                            "policy_number": cb.policy_number,
                            "carrier": carrier_name,
                            "amount": abs(cb.amount_paid),
                            "reason": "Chargeback on active policy",
                            "policy_status": policy.policy_status,
                        }
                    )
                    self._add_evidence(
                        category="chargeback",
                        severity="high",
                        policy_number=cb.policy_number,
                        carrier_code=code,
                        carrier_name=carrier_name,
                        description=(
                            f"Chargeback of ${abs(cb.amount_paid):,.2f} on "
                            f"policy {cb.policy_number} which is still ACTIVE. "
                            f"Active policies should not be charged back."
                        ),
                        expected_value="No chargeback (policy active)",
                        actual_value=f"Chargeback ${abs(cb.amount_paid):,.2f}",
                        variance_amount=abs(cb.amount_paid),
                        facts=[
                            f"Policy status: {policy.policy_status}",
                            f"Statement date: {cb.statement_date}",
                        ],
                        action="Dispute chargeback with carrier.",
                        recovery=abs(cb.amount_paid),
                    )

                # Check for chargebacks without documentation
                if not cb.notes:
                    suspicious.append(
                        {
                            "payment_id": cb.payment_id,
                            "policy_number": cb.policy_number,
                            "carrier": carrier_name,
                            "amount": abs(cb.amount_paid),
                            "reason": "No chargeback reason provided",
                        }
                    )

            carrier_details[code] = {
                "carrier_name": carrier_name,
                "chargeback_count": len(cbs),
                "total_amount": round(total_cb, 2),
            }

        return {
            "total_chargebacks": len(chargebacks),
            "total_amount": round(
                sum(abs(c.amount_paid) for c in chargebacks), 2
            ),
            "carriers": carrier_details,
            "suspicious": suspicious,
            "suspicious_count": len(suspicious),
        }

    # --- Forensic timeline ---

    def _build_forensic_timeline(self) -> list[dict[str, Any]]:
        """Reconstruct a timeline of policy and payment events."""
        events: list[dict[str, Any]] = []

        for policy in self._policies.values():
            events.append(
                {
                    "date": policy.effective_date.isoformat(),
                    "type": "policy_effective",
                    "policy_number": policy.policy_number,
                    "carrier": policy.carrier_name,
                    "description": (
                        f"Policy {policy.policy_number} effective "
                        f"(${policy.annual_premium:,.2f} premium)"
                    ),
                    "amount": None,
                }
            )
            if policy.cancel_date:
                events.append(
                    {
                        "date": policy.cancel_date.isoformat(),
                        "type": "policy_cancelled",
                        "policy_number": policy.policy_number,
                        "carrier": policy.carrier_name,
                        "description": (
                            f"Policy {policy.policy_number} cancelled: "
                            f"{policy.cancel_reason}"
                        ),
                        "amount": None,
                    }
                )

        for pmt in self._payments:
            events.append(
                {
                    "date": pmt.statement_date.isoformat(),
                    "type": f"payment_{pmt.transaction_type}",
                    "policy_number": pmt.policy_number,
                    "carrier": pmt.carrier_name,
                    "description": (
                        f"{pmt.transaction_type.title()} payment "
                        f"${pmt.amount_paid:,.2f} for {pmt.policy_number}"
                    ),
                    "amount": pmt.amount_paid,
                    "payment_id": pmt.payment_id,
                }
            )

        events.sort(key=lambda e: e["date"])
        return events

    # --- Carrier scorecards ---

    def _build_carrier_scorecards(
        self, reconciliation: list[ReconciliationItem]
    ) -> list[CarrierScorecard]:
        """Build reliability scorecards for each carrier."""
        carrier_recon: dict[str, list[ReconciliationItem]] = defaultdict(list)
        for item in reconciliation:
            if item.carrier_code:
                carrier_recon[item.carrier_code].append(item)

        scorecards: list[CarrierScorecard] = []
        for code, items in carrier_recon.items():
            carrier_name = items[0].carrier_name if items else ""
            total = len(items)
            matched = sum(1 for i in items if i.status == "matched")
            underpaid = sum(1 for i in items if i.status == "underpaid")
            missing = sum(1 for i in items if i.status == "missing")
            total_exp = sum(i.expected_amount for i in items)
            total_act = sum(i.actual_amount for i in items)
            total_var = sum(abs(i.variance) for i in items if i.status != "matched")

            accuracy = (matched / total * 100) if total > 0 else 0
            completeness = (
                ((total - missing) / total * 100) if total > 0 else 0
            )

            # Chargeback rate
            cbs = [
                p
                for p in self._payments
                if p.carrier_code == code and p.transaction_type == "chargeback"
            ]
            all_for_carrier = [
                p for p in self._payments if p.carrier_code == code
            ]
            cb_rate = (
                len(cbs) / len(all_for_carrier) if all_for_carrier else 0
            )

            timeliness = 80.0  # default
            dispute_score = 50.0  # default

            overall = (
                accuracy * 0.40
                + timeliness * 0.25
                + completeness * 0.25
                + dispute_score * 0.10
            )
            grade = self._score_to_grade(overall)

            issues: list[str] = []
            recs: list[str] = []

            if accuracy < 80:
                issues.append(
                    f"Low accuracy: only {accuracy:.0f}% of payments "
                    f"match expected amounts."
                )
                recs.append("Audit all commission statements line-by-line.")
            if missing > 0:
                issues.append(f"{missing} policies with missing payments.")
                recs.append("Send payment inquiry for all missing policies.")
            if underpaid > 0:
                underpaid_total = sum(
                    abs(i.variance) for i in items if i.status == "underpaid"
                )
                issues.append(
                    f"{underpaid} underpaid policies "
                    f"(${underpaid_total:,.2f} shortfall)."
                )
                recs.append("File formal dispute for underpayment recovery.")
            if cb_rate > 0.05:
                issues.append(
                    f"High chargeback rate: {cb_rate:.1%}."
                )
                recs.append("Review chargeback legitimacy and dispute invalid ones.")

            scorecards.append(
                CarrierScorecard(
                    carrier_code=code,
                    carrier_name=carrier_name,
                    accuracy_score=round(accuracy, 1),
                    timeliness_score=round(timeliness, 1),
                    completeness_score=round(completeness, 1),
                    dispute_resolution_score=round(dispute_score, 1),
                    overall_score=round(overall, 1),
                    grade=grade,
                    total_policies=total,
                    total_expected=round(total_exp, 2),
                    total_paid=round(total_act, 2),
                    total_variance=round(total_var, 2),
                    underpayment_count=underpaid,
                    missing_payment_count=missing,
                    chargeback_rate=round(cb_rate, 4),
                    issues=issues,
                    recommendations=recs,
                )
            )

        scorecards.sort(key=lambda s: s.overall_score)
        return scorecards

    # --- Evidence building ---

    def _add_evidence(
        self,
        category: str,
        severity: str,
        policy_number: str,
        carrier_code: str,
        carrier_name: str,
        description: str,
        expected_value: str,
        actual_value: str,
        variance_amount: float,
        facts: list[str] | None = None,
        action: str = "",
        recovery: float = 0.0,
    ) -> None:
        """Add a forensic evidence item."""
        self._evidence_counter += 1
        sol_date = None
        if self._period_end:
            sol_date = self._period_end.replace(
                year=self._period_end.year + self._sol_years
            )

        self._evidence.append(
            ForensicEvidence(
                evidence_id=f"FE-{self._evidence_counter:04d}",
                category=category,
                severity=severity,
                policy_number=policy_number,
                carrier_code=carrier_code,
                carrier_name=carrier_name,
                description=description,
                expected_value=expected_value,
                actual_value=actual_value,
                variance_amount=variance_amount,
                supporting_facts=facts or [],
                recommended_action=action,
                recovery_amount=recovery,
                statute_of_limitations_date=sol_date,
            )
        )

    def _add_underpayment_evidence(
        self,
        policy_number: str,
        carrier_info: tuple[str, str, str],
        expected: float,
        actual: float,
        variance: float,
        expected_rate: float,
        actual_rate: float,
        premium_basis: float,
    ) -> None:
        """Build evidence for an underpayment."""
        facts = [
            f"Expected: ${expected:,.2f}",
            f"Received: ${actual:,.2f}",
            f"Shortfall: ${abs(variance):,.2f}",
            f"Premium basis: ${premium_basis:,.2f}",
        ]
        if expected_rate and actual_rate:
            facts.append(f"Contracted rate: {expected_rate:.4f}")
            facts.append(f"Rate applied: {actual_rate:.4f}")

        self._add_evidence(
            category="underpayment",
            severity="high" if abs(variance) > 1000 else "medium",
            policy_number=policy_number,
            carrier_code=carrier_info[0],
            carrier_name=carrier_info[1],
            description=(
                f"Carrier {carrier_info[1]} underpaid by "
                f"${abs(variance):,.2f} on policy {policy_number}."
            ),
            expected_value=f"${expected:,.2f}",
            actual_value=f"${actual:,.2f}",
            variance_amount=abs(variance),
            facts=facts,
            action="Submit payment adjustment request to carrier.",
            recovery=abs(variance),
        )

    def _add_missing_payment_evidence(
        self,
        policy_number: str,
        carrier_info: tuple[str, str, str],
        expected: float,
        expected_rate: float,
        premium_basis: float,
    ) -> None:
        """Build evidence for a completely missing payment."""
        self._add_evidence(
            category="missing",
            severity="critical" if expected > 5000 else "high",
            policy_number=policy_number,
            carrier_code=carrier_info[0],
            carrier_name=carrier_info[1],
            description=(
                f"No commission payment received from {carrier_info[1]} "
                f"for policy {policy_number}. Expected ${expected:,.2f} "
                f"based on contracted rate {expected_rate:.4f} on "
                f"${premium_basis:,.2f} premium."
            ),
            expected_value=f"${expected:,.2f}",
            actual_value="$0.00 (no payment received)",
            variance_amount=expected,
            facts=[
                f"Policy: {policy_number}",
                f"Premium: ${premium_basis:,.2f}",
                f"Rate: {expected_rate:.4f}",
                f"Expected commission: ${expected:,.2f}",
            ],
            action="Demand immediate payment from carrier with documentation.",
            recovery=expected,
        )

    def _add_rate_mismatch_evidence(
        self,
        policy_number: str,
        carrier_info: tuple[str, str, str],
        expected_rate: float,
        actual_rate: float,
        premium_basis: float,
    ) -> None:
        """Build evidence for a rate mismatch."""
        rate_diff = expected_rate - actual_rate
        amount_diff = premium_basis * rate_diff

        self._add_evidence(
            category="rate_mismatch",
            severity="high" if abs(amount_diff) > 500 else "medium",
            policy_number=policy_number,
            carrier_code=carrier_info[0],
            carrier_name=carrier_info[1],
            description=(
                f"Carrier {carrier_info[1]} applied rate {actual_rate:.4f} "
                f"instead of contracted rate {expected_rate:.4f} on "
                f"policy {policy_number}. Difference: "
                f"${abs(amount_diff):,.2f}."
            ),
            expected_value=f"Rate: {expected_rate:.4f}",
            actual_value=f"Rate: {actual_rate:.4f}",
            variance_amount=abs(amount_diff),
            facts=[
                f"Contracted rate: {expected_rate:.4f}",
                f"Applied rate: {actual_rate:.4f}",
                f"Premium basis: ${premium_basis:,.2f}",
                f"Commission shortfall: ${abs(amount_diff):,.2f}",
            ],
            action="Submit rate correction request with carrier contract.",
            recovery=abs(amount_diff) if rate_diff > 0 else 0,
        )

    # --- Action generation ---

    def _generate_immediate_actions(
        self,
        reconciliation: list[ReconciliationItem],
        scorecards: list[CarrierScorecard],
    ) -> list[str]:
        """Generate prioritized immediate action items."""
        actions: list[str] = []

        critical = [
            e for e in self._evidence if e.severity == "critical"
        ]
        if critical:
            total_recovery = sum(e.recovery_amount for e in critical)
            actions.append(
                f"URGENT: {len(critical)} critical issues identified with "
                f"${total_recovery:,.2f} in potential recovery. Begin "
                f"carrier dispute process immediately."
            )

        missing = [r for r in reconciliation if r.status == "missing"]
        if missing:
            missing_total = sum(r.expected_amount for r in missing)
            actions.append(
                f"MISSING PAYMENTS: {len(missing)} policies with no "
                f"commission payment received (${missing_total:,.2f} total). "
                f"Send payment inquiry to each carrier."
            )

        underpaid = [r for r in reconciliation if r.status == "underpaid"]
        if underpaid:
            underpaid_total = sum(abs(r.variance) for r in underpaid)
            actions.append(
                f"UNDERPAYMENTS: {len(underpaid)} policies underpaid by "
                f"${underpaid_total:,.2f} total. File adjustment requests."
            )

        bad_carriers = [s for s in scorecards if s.grade in ("D", "F")]
        if bad_carriers:
            names = ", ".join(s.carrier_name for s in bad_carriers)
            actions.append(
                f"CARRIER ISSUES: {names} scored below acceptable "
                f"thresholds. Schedule carrier review meetings."
            )

        return actions

    def _generate_recovery_actions(self) -> list[dict[str, Any]]:
        """Generate specific recovery action items with amounts."""
        recovery_items: list[dict[str, Any]] = []

        for evidence in self._evidence:
            if evidence.recovery_amount <= 0:
                continue
            recovery_items.append(
                {
                    "evidence_id": evidence.evidence_id,
                    "carrier": evidence.carrier_name,
                    "policy_number": evidence.policy_number,
                    "category": evidence.category,
                    "recovery_amount": round(evidence.recovery_amount, 2),
                    "action": evidence.recommended_action,
                    "severity": evidence.severity,
                    "sol_date": (
                        evidence.statute_of_limitations_date.isoformat()
                        if evidence.statute_of_limitations_date
                        else None
                    ),
                }
            )

        recovery_items.sort(key=lambda x: x["recovery_amount"], reverse=True)
        return recovery_items

    def _generate_process_improvements(
        self,
        scorecards: list[CarrierScorecard],
        lag_analysis: dict[str, Any],
        chargeback_analysis: dict[str, Any],
    ) -> list[str]:
        """Generate process improvement recommendations."""
        improvements: list[str] = []

        improvements.append(
            "Implement monthly carrier statement reconciliation process "
            "using this forensic auditor to catch discrepancies early."
        )

        if any(s.missing_payment_count > 0 for s in scorecards):
            improvements.append(
                "Set up automated payment tracking with alerts when "
                "expected commission payments are not received within "
                f"{self._lag_threshold} days of policy effective date."
            )

        if any(s.accuracy_score < 90 for s in scorecards):
            improvements.append(
                "Require carriers to include policy number, premium basis, "
                "and rate applied on all commission statements for "
                "automated matching."
            )

        cb_count = chargeback_analysis.get("suspicious_count", 0)
        if cb_count > 0:
            improvements.append(
                f"Implement chargeback dispute workflow. {cb_count} "
                f"suspicious chargebacks identified that may be recoverable."
            )

        improvements.append(
            "Maintain digital copies of all carrier contracts and rate "
            "schedules in a central repository for automated rate "
            "verification."
        )

        return improvements

    # --- Utility methods ---

    @staticmethod
    def _calculate_policy_year(
        effective_date: date, as_of_date: date
    ) -> int:
        """Calculate which policy year a date falls in."""
        years = as_of_date.year - effective_date.year
        if (as_of_date.month, as_of_date.day) < (
            effective_date.month,
            effective_date.day,
        ):
            years -= 1
        return max(1, years + 1)

    @staticmethod
    def _prorate_premium(
        annual_premium: float,
        policy_start: date,
        policy_end: date,
        period_start: date,
        period_end: date,
        cancel_date: date | None = None,
    ) -> float:
        """Prorate annual premium to the audit period."""
        actual_end = cancel_date if cancel_date and cancel_date < policy_end else policy_end
        actual_end = min(actual_end, period_end)
        actual_start = max(policy_start, period_start)

        if actual_start >= actual_end:
            return 0.0

        policy_days = (policy_end - policy_start).days
        if policy_days <= 0:
            return 0.0

        overlap_days = (actual_end - actual_start).days
        daily_premium = annual_premium / policy_days
        return round(daily_premium * overlap_days, 2)

    @staticmethod
    def _score_to_grade(score: float) -> str:
        """Convert numeric score to letter grade."""
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"
