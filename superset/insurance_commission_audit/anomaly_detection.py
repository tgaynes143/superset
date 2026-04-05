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
"""Statistical anomaly detection for commission transaction patterns.

Implements multiple detection strategies:
- Z-score analysis for outlier commission amounts and rates
- Benford's Law conformance for first-digit distribution fraud detection
- Velocity analysis for unusual transaction frequency patterns
- Duplicate detection for potential double-payment identification
- Round-number analysis for suspicious even-dollar amounts
- Split-transaction detection for threshold avoidance
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from superset.insurance_commission_audit.compliance_engine import ComplianceViolation
from superset.insurance_commission_audit.models import FindingSeverity

logger = logging.getLogger(__name__)

# Benford's Law expected first-digit distribution
BENFORD_EXPECTED = {
    1: 0.301, 2: 0.176, 3: 0.125, 4: 0.097,
    5: 0.079, 6: 0.067, 7: 0.058, 8: 0.051, 9: 0.046,
}


@dataclass
class AnomalyResult:
    """Result of running an anomaly detection check on a dataset."""

    check_name: str
    description: str
    score: float  # 0.0 = no anomaly, 1.0 = maximum anomaly
    flagged_transaction_ids: list[int] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    violations: list[ComplianceViolation] = field(default_factory=list)


@dataclass
class TransactionRecord:
    """Lightweight transaction data for anomaly analysis."""

    id: int
    producer_id: int
    commission_amount: float
    commission_rate: float
    premium_amount: float
    transaction_date: date
    policy_number: str
    line_of_business: str
    carrier_name: str
    is_chargeback: bool = False


class AnomalyDetector:
    """Multi-strategy anomaly detection engine for commission transactions."""

    def __init__(
        self,
        z_score_threshold: float = 3.0,
        benford_chi_sq_threshold: float = 15.507,
        velocity_window_days: int = 7,
        velocity_max_transactions: int = 50,
        round_number_threshold: float = 0.30,
        split_threshold_amount: float = 10000.0,
        split_window_days: int = 3,
    ) -> None:
        self.z_score_threshold = z_score_threshold
        self.benford_chi_sq_threshold = benford_chi_sq_threshold
        self.velocity_window_days = velocity_window_days
        self.velocity_max_transactions = velocity_max_transactions
        self.round_number_threshold = round_number_threshold
        self.split_threshold_amount = split_threshold_amount
        self.split_window_days = split_window_days

    def run_all_checks(
        self, transactions: list[TransactionRecord]
    ) -> list[AnomalyResult]:
        """Run all anomaly detection checks and return results."""
        if not transactions:
            return []

        results: list[AnomalyResult] = []
        results.append(self.check_zscore_outliers(transactions))
        results.append(self.check_benford_law(transactions))
        results.append(self.check_velocity_anomalies(transactions))
        results.append(self.check_duplicates(transactions))
        results.append(self.check_round_numbers(transactions))
        results.append(self.check_split_transactions(transactions))
        results.append(self.check_rate_consistency(transactions))
        return results

    def check_zscore_outliers(
        self, transactions: list[TransactionRecord]
    ) -> AnomalyResult:
        """Identify transactions with commission amounts that are statistical outliers."""
        amounts = [t.commission_amount for t in transactions if not t.is_chargeback]
        if len(amounts) < 3:
            return AnomalyResult(
                check_name="Z-Score Outlier Detection",
                description="Insufficient data for Z-score analysis.",
                score=0.0,
            )

        mean = sum(amounts) / len(amounts)
        variance = sum((x - mean) ** 2 for x in amounts) / len(amounts)
        std_dev = math.sqrt(variance) if variance > 0 else 0.0

        if std_dev == 0:
            return AnomalyResult(
                check_name="Z-Score Outlier Detection",
                description="No variance in commission amounts.",
                score=0.0,
            )

        flagged: list[int] = []
        violations: list[ComplianceViolation] = []
        max_z = 0.0

        for tx in transactions:
            if tx.is_chargeback:
                continue
            z_score = abs(tx.commission_amount - mean) / std_dev
            if z_score > self.z_score_threshold:
                flagged.append(tx.id)
                max_z = max(max_z, z_score)
                violations.append(
                    ComplianceViolation(
                        rule_name="ZSCORE_OUTLIER",
                        severity=(
                            FindingSeverity.HIGH
                            if z_score > 4.0
                            else FindingSeverity.MEDIUM
                        ),
                        transaction_id=tx.id,
                        producer_id=tx.producer_id,
                        description=(
                            f"Commission amount ${tx.commission_amount:.2f} is a "
                            f"statistical outlier (Z-score: {z_score:.2f}, threshold: "
                            f"{self.z_score_threshold:.1f}). Mean: ${mean:.2f}, "
                            f"Std Dev: ${std_dev:.2f}."
                        ),
                        regulation_reference="Statistical Audit Methodology",
                        expected_value=f"Within {self.z_score_threshold} std devs of ${mean:.2f}",
                        actual_value=f"${tx.commission_amount:.2f} (Z={z_score:.2f})",
                        variance_amount=abs(tx.commission_amount - mean),
                        finding_code="AN-001",
                    )
                )

        anomaly_score = min(1.0, len(flagged) / max(1, len(amounts)))
        return AnomalyResult(
            check_name="Z-Score Outlier Detection",
            description=(
                f"Analyzed {len(amounts)} transactions. "
                f"Found {len(flagged)} outliers beyond {self.z_score_threshold} "
                f"standard deviations."
            ),
            score=anomaly_score,
            flagged_transaction_ids=flagged,
            details={
                "mean": round(mean, 2),
                "std_dev": round(std_dev, 2),
                "max_z_score": round(max_z, 2),
                "total_analyzed": len(amounts),
                "outlier_count": len(flagged),
            },
            violations=violations,
        )

    def check_benford_law(
        self, transactions: list[TransactionRecord]
    ) -> AnomalyResult:
        """Check if commission amounts conform to Benford's Law distribution.

        Significant deviation from Benford's Law suggests potential
        fabrication or manipulation of commission amounts.
        """
        amounts = [
            t.commission_amount
            for t in transactions
            if t.commission_amount > 0 and not t.is_chargeback
        ]
        if len(amounts) < 50:
            return AnomalyResult(
                check_name="Benford's Law Analysis",
                description=(
                    f"Insufficient data ({len(amounts)} transactions, need 50+) "
                    f"for Benford's Law analysis."
                ),
                score=0.0,
            )

        first_digits: list[int] = []
        for amount in amounts:
            first_digit = int(str(amount).lstrip("0").lstrip(".").lstrip("0")[0])
            if 1 <= first_digit <= 9:
                first_digits.append(first_digit)

        if not first_digits:
            return AnomalyResult(
                check_name="Benford's Law Analysis",
                description="Could not extract first digits.",
                score=0.0,
            )

        observed = Counter(first_digits)
        total = len(first_digits)
        chi_squared = 0.0
        digit_analysis: dict[str, dict[str, float]] = {}

        for digit in range(1, 10):
            observed_freq = observed.get(digit, 0) / total
            expected_freq = BENFORD_EXPECTED[digit]
            expected_count = expected_freq * total
            observed_count = observed.get(digit, 0)

            if expected_count > 0:
                chi_squared += (
                    (observed_count - expected_count) ** 2 / expected_count
                )

            digit_analysis[str(digit)] = {
                "observed_pct": round(observed_freq * 100, 1),
                "expected_pct": round(expected_freq * 100, 1),
                "deviation_pct": round((observed_freq - expected_freq) * 100, 1),
            }

        # Chi-squared critical value for 8 degrees of freedom at p=0.05 = 15.507
        is_anomalous = chi_squared > self.benford_chi_sq_threshold
        anomaly_score = min(1.0, chi_squared / (self.benford_chi_sq_threshold * 2))

        violations: list[ComplianceViolation] = []
        if is_anomalous:
            violations.append(
                ComplianceViolation(
                    rule_name="BENFORD_LAW_VIOLATION",
                    severity=FindingSeverity.HIGH,
                    transaction_id=None,
                    producer_id=None,
                    description=(
                        f"Commission amount first-digit distribution significantly "
                        f"deviates from Benford's Law (chi-squared: {chi_squared:.2f}, "
                        f"threshold: {self.benford_chi_sq_threshold:.2f}). "
                        f"This pattern suggests possible data fabrication or "
                        f"systematic manipulation of commission amounts."
                    ),
                    regulation_reference="Forensic Audit Methodology - Benford's Law",
                    expected_value=f"Chi-squared < {self.benford_chi_sq_threshold}",
                    actual_value=f"Chi-squared = {chi_squared:.2f}",
                    variance_amount=0.0,
                    finding_code="AN-002",
                    metadata={"digit_analysis": digit_analysis},
                )
            )

        return AnomalyResult(
            check_name="Benford's Law Analysis",
            description=(
                f"Analyzed {total} transaction amounts. "
                f"Chi-squared statistic: {chi_squared:.2f} "
                f"(threshold: {self.benford_chi_sq_threshold:.2f}). "
                f"{'ANOMALOUS' if is_anomalous else 'Normal'} distribution."
            ),
            score=anomaly_score,
            details={
                "chi_squared": round(chi_squared, 2),
                "threshold": self.benford_chi_sq_threshold,
                "is_anomalous": is_anomalous,
                "sample_size": total,
                "digit_analysis": digit_analysis,
            },
            violations=violations,
        )

    def check_velocity_anomalies(
        self, transactions: list[TransactionRecord]
    ) -> AnomalyResult:
        """Detect unusual transaction frequency spikes per producer."""
        producer_txns: dict[int, list[TransactionRecord]] = {}
        for tx in transactions:
            producer_txns.setdefault(tx.producer_id, []).append(tx)

        flagged: list[int] = []
        violations: list[ComplianceViolation] = []
        high_velocity_producers: list[dict[str, Any]] = []

        for producer_id, txns in producer_txns.items():
            sorted_txns = sorted(txns, key=lambda t: t.transaction_date)

            for i, tx in enumerate(sorted_txns):
                window_start = tx.transaction_date - timedelta(
                    days=self.velocity_window_days
                )
                window_txns = [
                    t
                    for t in sorted_txns
                    if window_start <= t.transaction_date <= tx.transaction_date
                ]
                if len(window_txns) > self.velocity_max_transactions:
                    tx_ids = [t.id for t in window_txns]
                    flagged.extend(tx_ids)
                    total_amount = sum(t.commission_amount for t in window_txns)
                    high_velocity_producers.append(
                        {
                            "producer_id": producer_id,
                            "window_start": str(window_start),
                            "window_end": str(tx.transaction_date),
                            "transaction_count": len(window_txns),
                            "total_amount": round(total_amount, 2),
                        }
                    )
                    violations.append(
                        ComplianceViolation(
                            rule_name="HIGH_VELOCITY",
                            severity=FindingSeverity.MEDIUM,
                            transaction_id=tx.id,
                            producer_id=producer_id,
                            description=(
                                f"Producer {producer_id} had {len(window_txns)} "
                                f"transactions in {self.velocity_window_days} days "
                                f"(${total_amount:.2f} total). "
                                f"Threshold: {self.velocity_max_transactions}."
                            ),
                            regulation_reference="Internal Audit - Velocity Check",
                            expected_value=f"<= {self.velocity_max_transactions} per {self.velocity_window_days} days",
                            actual_value=f"{len(window_txns)} transactions",
                            variance_amount=total_amount,
                            finding_code="AN-003",
                        )
                    )
                    break  # one violation per producer

        flagged = list(set(flagged))
        return AnomalyResult(
            check_name="Transaction Velocity Analysis",
            description=(
                f"Analyzed {len(producer_txns)} producers. "
                f"Found {len(high_velocity_producers)} with high velocity."
            ),
            score=min(1.0, len(high_velocity_producers) / max(1, len(producer_txns))),
            flagged_transaction_ids=flagged,
            details={
                "producers_analyzed": len(producer_txns),
                "high_velocity_count": len(high_velocity_producers),
                "high_velocity_producers": high_velocity_producers,
            },
            violations=violations,
        )

    def check_duplicates(
        self, transactions: list[TransactionRecord]
    ) -> AnomalyResult:
        """Detect potential duplicate commission payments."""
        seen: dict[str, list[TransactionRecord]] = {}
        for tx in transactions:
            key = (
                f"{tx.producer_id}:{tx.policy_number}:{tx.commission_amount:.2f}"
                f":{tx.transaction_date}:{tx.line_of_business}"
            )
            seen.setdefault(key, []).append(tx)

        flagged: list[int] = []
        violations: list[ComplianceViolation] = []
        duplicate_groups: list[dict[str, Any]] = []

        for key, dupes in seen.items():
            if len(dupes) > 1:
                tx_ids = [d.id for d in dupes]
                flagged.extend(tx_ids)
                total_excess = dupes[0].commission_amount * (len(dupes) - 1)
                duplicate_groups.append(
                    {
                        "transaction_ids": tx_ids,
                        "count": len(dupes),
                        "amount_each": round(dupes[0].commission_amount, 2),
                        "total_excess": round(total_excess, 2),
                    }
                )
                violations.append(
                    ComplianceViolation(
                        rule_name="DUPLICATE_TRANSACTION",
                        severity=FindingSeverity.HIGH,
                        transaction_id=dupes[0].id,
                        producer_id=dupes[0].producer_id,
                        description=(
                            f"Found {len(dupes)} identical transactions "
                            f"(policy {dupes[0].policy_number}, "
                            f"${dupes[0].commission_amount:.2f} each). "
                            f"Potential duplicate payment: ${total_excess:.2f}."
                        ),
                        regulation_reference="Internal Audit - Duplicate Detection",
                        expected_value="1 transaction",
                        actual_value=f"{len(dupes)} identical transactions",
                        variance_amount=total_excess,
                        finding_code="AN-004",
                    )
                )

        return AnomalyResult(
            check_name="Duplicate Transaction Detection",
            description=(
                f"Analyzed {len(transactions)} transactions. "
                f"Found {len(duplicate_groups)} potential duplicate groups."
            ),
            score=min(1.0, len(flagged) / max(1, len(transactions))),
            flagged_transaction_ids=flagged,
            details={
                "duplicate_groups": duplicate_groups,
                "total_excess_amount": round(
                    sum(g["total_excess"] for g in duplicate_groups), 2
                ),
            },
            violations=violations,
        )

    def check_round_numbers(
        self, transactions: list[TransactionRecord]
    ) -> AnomalyResult:
        """Detect suspiciously high proportion of round-number commissions."""
        non_chargeback = [t for t in transactions if not t.is_chargeback]
        if not non_chargeback:
            return AnomalyResult(
                check_name="Round Number Analysis",
                description="No transactions to analyze.",
                score=0.0,
            )

        round_txns: list[int] = []
        for tx in non_chargeback:
            if tx.commission_amount == round(tx.commission_amount, 0):
                round_txns.append(tx.id)

        round_pct = len(round_txns) / len(non_chargeback)
        is_suspicious = round_pct > self.round_number_threshold

        violations: list[ComplianceViolation] = []
        if is_suspicious:
            violations.append(
                ComplianceViolation(
                    rule_name="EXCESSIVE_ROUND_NUMBERS",
                    severity=FindingSeverity.MEDIUM,
                    transaction_id=None,
                    producer_id=None,
                    description=(
                        f"{round_pct:.1%} of commission amounts are round numbers "
                        f"(threshold: {self.round_number_threshold:.0%}). "
                        f"High round-number frequency may indicate manual "
                        f"override or fabrication of commission amounts."
                    ),
                    regulation_reference="Forensic Audit - Round Number Test",
                    expected_value=f"<= {self.round_number_threshold:.0%}",
                    actual_value=f"{round_pct:.1%}",
                    variance_amount=0.0,
                    finding_code="AN-005",
                )
            )

        return AnomalyResult(
            check_name="Round Number Analysis",
            description=(
                f"{round_pct:.1%} of {len(non_chargeback)} transactions are "
                f"round numbers. {'Suspicious' if is_suspicious else 'Normal'}."
            ),
            score=min(1.0, round_pct / self.round_number_threshold) if is_suspicious else round_pct,
            flagged_transaction_ids=round_txns if is_suspicious else [],
            details={
                "round_count": len(round_txns),
                "total_count": len(non_chargeback),
                "round_pct": round(round_pct * 100, 1),
                "threshold_pct": round(self.round_number_threshold * 100, 1),
            },
            violations=violations,
        )

    def check_split_transactions(
        self, transactions: list[TransactionRecord]
    ) -> AnomalyResult:
        """Detect potential split transactions designed to avoid review thresholds.

        Looks for multiple transactions from the same producer to the same
        policy within a short window that individually fall below the
        threshold but collectively exceed it.
        """
        producer_policy: dict[str, list[TransactionRecord]] = {}
        for tx in transactions:
            if tx.is_chargeback:
                continue
            key = f"{tx.producer_id}:{tx.policy_number}"
            producer_policy.setdefault(key, []).append(tx)

        flagged: list[int] = []
        violations: list[ComplianceViolation] = []
        split_groups: list[dict[str, Any]] = []

        for key, txns in producer_policy.items():
            if len(txns) < 2:
                continue

            sorted_txns = sorted(txns, key=lambda t: t.transaction_date)
            for i, anchor in enumerate(sorted_txns):
                window_end = anchor.transaction_date + timedelta(
                    days=self.split_window_days
                )
                cluster = [
                    t
                    for t in sorted_txns[i:]
                    if t.transaction_date <= window_end
                    and t.commission_amount < self.split_threshold_amount
                ]
                total = sum(t.commission_amount for t in cluster)
                if (
                    len(cluster) >= 2
                    and total >= self.split_threshold_amount
                ):
                    tx_ids = [t.id for t in cluster]
                    flagged.extend(tx_ids)
                    split_groups.append(
                        {
                            "transaction_ids": tx_ids,
                            "individual_amounts": [
                                round(t.commission_amount, 2) for t in cluster
                            ],
                            "combined_total": round(total, 2),
                            "producer_id": cluster[0].producer_id,
                            "policy_number": cluster[0].policy_number,
                        }
                    )
                    violations.append(
                        ComplianceViolation(
                            rule_name="SPLIT_TRANSACTION",
                            severity=FindingSeverity.HIGH,
                            transaction_id=anchor.id,
                            producer_id=anchor.producer_id,
                            description=(
                                f"{len(cluster)} transactions on policy "
                                f"{anchor.policy_number} within "
                                f"{self.split_window_days} days total "
                                f"${total:.2f} (each below "
                                f"${self.split_threshold_amount:.2f} threshold). "
                                f"Potential structuring to avoid review."
                            ),
                            regulation_reference="Internal Audit - Anti-Structuring",
                            expected_value=f"Single transaction >= ${self.split_threshold_amount:.2f}",
                            actual_value=f"{len(cluster)} transactions totaling ${total:.2f}",
                            variance_amount=total,
                            finding_code="AN-006",
                        )
                    )
                    break  # one per group

        flagged = list(set(flagged))
        return AnomalyResult(
            check_name="Split Transaction Detection",
            description=(
                f"Found {len(split_groups)} potential split transaction groups."
            ),
            score=min(1.0, len(split_groups) / max(1, len(producer_policy))),
            flagged_transaction_ids=flagged,
            details={"split_groups": split_groups},
            violations=violations,
        )

    def check_rate_consistency(
        self, transactions: list[TransactionRecord]
    ) -> AnomalyResult:
        """Check for inconsistent commission rates within the same LOB/carrier."""
        lob_carrier_rates: dict[str, list[tuple[int, float]]] = {}
        for tx in transactions:
            if tx.is_chargeback:
                continue
            key = f"{tx.line_of_business}:{tx.carrier_name}"
            lob_carrier_rates.setdefault(key, []).append(
                (tx.id, tx.commission_rate)
            )

        flagged: list[int] = []
        violations: list[ComplianceViolation] = []
        inconsistent_groups: list[dict[str, Any]] = []

        for key, rates in lob_carrier_rates.items():
            if len(rates) < 5:
                continue

            values = [r[1] for r in rates]
            mean = sum(values) / len(values)
            variance = sum((x - mean) ** 2 for x in values) / len(values)
            std_dev = math.sqrt(variance) if variance > 0 else 0.0

            # Flag individual transactions with rates far from the group mean
            if std_dev > 0:
                for tx_id, rate in rates:
                    z = abs(rate - mean) / std_dev
                    if z > self.z_score_threshold:
                        flagged.append(tx_id)

                if flagged:
                    lob, carrier = key.split(":", 1)
                    inconsistent_groups.append(
                        {
                            "lob": lob,
                            "carrier": carrier,
                            "mean_rate": round(mean, 4),
                            "std_dev": round(std_dev, 4),
                            "outlier_count": len(
                                [1 for _, r in rates if abs(r - mean) / std_dev > self.z_score_threshold]
                            ),
                        }
                    )

        flagged = list(set(flagged))
        return AnomalyResult(
            check_name="Rate Consistency Analysis",
            description=(
                f"Found {len(inconsistent_groups)} LOB/carrier groups with "
                f"inconsistent commission rates."
            ),
            score=min(1.0, len(flagged) / max(1, len(transactions))),
            flagged_transaction_ids=flagged,
            details={"inconsistent_groups": inconsistent_groups},
            violations=violations,
        )
