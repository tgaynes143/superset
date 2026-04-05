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
"""Automated audit execution command.

Orchestrates the full audit pipeline:
1. Load transactions and producers for the audit scope
2. Run compliance engine (rate limits, license checks, chargeback validation)
3. Run anomaly detection (Z-score, Benford, velocity, duplicates, splits)
4. Compute producer risk scores
5. Auto-generate audit findings from violations
6. Produce regulatory report with executive summary
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict
from datetime import date
from typing import Any

from superset.commands.base import BaseCommand
from superset.insurance_commission_audit.anomaly_detection import (
    AnomalyDetector,
    TransactionRecord,
)
from superset.insurance_commission_audit.audit_trail import AuditTrailManager
from superset.insurance_commission_audit.compliance_engine import (
    ComplianceEngine,
    ComplianceViolation,
)
from superset.insurance_commission_audit.models import (
    AuditStatus,
    FindingSeverity,
)
from superset.insurance_commission_audit.regulatory_report import (
    RegulatoryReportGenerator,
)
from superset.insurance_commission_audit.risk_scoring import (
    ProducerMetrics,
    RiskScoringEngine,
)

logger = logging.getLogger(__name__)


class RunAuditCommand(BaseCommand):
    """Execute a comprehensive automated audit on commission data.

    This is the main orchestrator that ties together all intelligence
    layers into a single pipeline. It accepts pre-loaded data (no direct
    DB access) so it can be tested independently and used in both
    API and batch contexts.
    """

    def __init__(
        self,
        audit_report_data: dict[str, Any],
        producers: list[dict[str, Any]],
        transactions: list[dict[str, Any]],
        compliance_engine: ComplianceEngine | None = None,
        anomaly_detector: AnomalyDetector | None = None,
        risk_engine: RiskScoringEngine | None = None,
        report_generator: RegulatoryReportGenerator | None = None,
        audit_trail: AuditTrailManager | None = None,
    ) -> None:
        self._audit_data = audit_report_data
        self._producers = producers
        self._transactions = transactions
        self._compliance = compliance_engine or ComplianceEngine()
        self._anomaly = anomaly_detector or AnomalyDetector()
        self._risk = risk_engine or RiskScoringEngine()
        self._report_gen = report_generator or RegulatoryReportGenerator()
        self._trail = audit_trail or AuditTrailManager()

    def run(self) -> dict[str, Any]:
        """Execute the full audit pipeline and return results."""
        self.validate()

        audit_id = self._audit_data.get("id", 0)
        state = self._audit_data.get("state_jurisdiction", "")

        self._trail.record(
            entity_type="audit_report",
            entity_id=audit_id,
            action="audit_execution_started",
            metadata={"transaction_count": len(self._transactions)},
        )

        # Step 1: Run compliance checks
        all_violations = self._run_compliance_checks(state)

        # Step 2: Run anomaly detection
        anomaly_results = self._run_anomaly_detection()
        for result in anomaly_results:
            all_violations.extend(result.violations)

        # Step 3: Compute risk scores
        risk_profiles = self._compute_risk_scores(all_violations)

        # Step 4: Build findings from violations
        findings = self._violations_to_findings(all_violations)

        # Step 5: Compute statistics
        transaction_stats = self._compute_transaction_stats()

        # Step 6: Generate regulatory report
        regulatory_report = self._report_gen.generate(
            audit_report_data=self._audit_data,
            findings=findings,
            producer_data=self._producers,
            transaction_stats=transaction_stats,
            risk_profiles=[asdict(rp) for rp in risk_profiles],
        )

        self._trail.record(
            entity_type="audit_report",
            entity_id=audit_id,
            action="audit_execution_completed",
            metadata={
                "total_violations": len(all_violations),
                "total_findings": len(findings),
                "risk_profiles_computed": len(risk_profiles),
            },
        )

        return {
            "audit_report_id": audit_id,
            "status": "completed",
            "compliance_violations": len(all_violations),
            "findings_generated": len(findings),
            "findings": findings,
            "anomaly_results": [
                {
                    "check_name": r.check_name,
                    "score": r.score,
                    "description": r.description,
                    "flagged_count": len(r.flagged_transaction_ids),
                    "details": r.details,
                }
                for r in anomaly_results
            ],
            "risk_profiles": [
                {
                    "producer_id": rp.producer_id,
                    "composite_score": rp.composite_score,
                    "risk_tier": rp.risk_tier,
                    "recommendations": rp.recommendations,
                    "factors": [
                        {
                            "name": f.name,
                            "category": f.category,
                            "raw_score": f.raw_score,
                            "weighted_score": f.weighted_score,
                            "description": f.description,
                        }
                        for f in rp.factors
                    ],
                }
                for rp in risk_profiles
            ],
            "regulatory_report": {
                "executive_summary": regulatory_report.executive_summary,
                "recommendations": regulatory_report.recommendations,
                "corrective_actions": regulatory_report.required_corrective_actions,
                "compliance_deadlines": regulatory_report.compliance_deadlines,
                "financial_impact": {
                    "total_variance": regulatory_report.financial_impact.total_variance_identified,
                    "estimated_refund": regulatory_report.financial_impact.estimated_refund_due,
                    "penalty_exposure": regulatory_report.financial_impact.estimated_penalty_exposure,
                    "by_severity": regulatory_report.financial_impact.variance_by_severity,
                    "by_category": regulatory_report.financial_impact.variance_by_category,
                },
                "certification": regulatory_report.certification_statement,
            },
            "audit_trail": self._trail.get_summary(),
            "transaction_stats": transaction_stats,
        }

    def validate(self) -> None:
        """Validate that minimum required data is present."""
        if not self._audit_data:
            raise ValueError("Audit report data is required.")
        if not self._audit_data.get("state_jurisdiction"):
            raise ValueError("State jurisdiction is required.")
        if not self._audit_data.get("audit_period_start"):
            raise ValueError("Audit period start is required.")
        if not self._audit_data.get("audit_period_end"):
            raise ValueError("Audit period end is required.")

    def _run_compliance_checks(self, state: str) -> list[ComplianceViolation]:
        """Run compliance engine on all transactions and producers."""
        violations: list[ComplianceViolation] = []
        producer_map = {p["id"]: p for p in self._producers}

        for tx in self._transactions:
            # Rate compliance
            rate_violations = self._compliance.check_rate_compliance(
                transaction_id=tx["id"],
                producer_id=tx["producer_id"],
                state=state,
                line_of_business=tx["line_of_business"],
                commission_type=tx["commission_type"],
                commission_rate=tx["commission_rate"],
                premium_amount=tx["premium_amount"],
                commission_amount=tx["commission_amount"],
                transaction_date=tx.get("transaction_date"),
            )
            violations.extend(rate_violations)

            # License compliance
            producer = producer_map.get(tx["producer_id"])
            if producer:
                license_violations = self._compliance.check_license_compliance(
                    producer_id=tx["producer_id"],
                    license_state=producer.get("license_state", ""),
                    license_expiry_date=producer.get("license_expiry_date"),
                    transaction_state=state,
                    transaction_date=tx.get("transaction_date", date.today()),
                    lines_of_authority=producer.get("lines_of_authority"),
                    line_of_business=tx["line_of_business"],
                )
                violations.extend(license_violations)

            # Chargeback compliance
            cb_violations = self._compliance.check_chargeback_compliance(
                transaction_id=tx["id"],
                producer_id=tx["producer_id"],
                is_chargeback=tx.get("is_chargeback", False),
                chargeback_reason=tx.get("chargeback_reason"),
                original_transaction_id=tx.get("original_transaction_id"),
                commission_amount=tx["commission_amount"],
            )
            violations.extend(cb_violations)

        self._trail.record_compliance_check(
            entity_type="audit_report",
            entity_id=self._audit_data.get("id", 0),
            check_type="full_compliance_suite",
            violations_found=len(violations),
        )

        return violations

    def _run_anomaly_detection(self) -> list:
        """Convert transactions to records and run anomaly detection."""
        records: list[TransactionRecord] = []
        for tx in self._transactions:
            records.append(
                TransactionRecord(
                    id=tx["id"],
                    producer_id=tx["producer_id"],
                    commission_amount=tx["commission_amount"],
                    commission_rate=tx["commission_rate"],
                    premium_amount=tx["premium_amount"],
                    transaction_date=tx.get("transaction_date", date.today()),
                    policy_number=tx.get("policy_number", ""),
                    line_of_business=tx.get("line_of_business", ""),
                    carrier_name=tx.get("carrier_name", ""),
                    is_chargeback=tx.get("is_chargeback", False),
                )
            )

        results = self._anomaly.run_all_checks(records)

        self._trail.record_compliance_check(
            entity_type="audit_report",
            entity_id=self._audit_data.get("id", 0),
            check_type="anomaly_detection",
            violations_found=sum(len(r.violations) for r in results),
        )

        return results

    def _compute_risk_scores(
        self, violations: list[ComplianceViolation]
    ) -> list:
        """Compute risk scores for all producers."""
        from collections import Counter

        violation_by_producer: dict[int, list[ComplianceViolation]] = {}
        for v in violations:
            if v.producer_id:
                violation_by_producer.setdefault(v.producer_id, []).append(v)

        producer_map = {p["id"]: p for p in self._producers}
        tx_by_producer: dict[int, list[dict[str, Any]]] = {}
        for tx in self._transactions:
            tx_by_producer.setdefault(tx["producer_id"], []).append(tx)

        # Compute peer averages
        all_rates = [
            tx["commission_rate"]
            for tx in self._transactions
            if not tx.get("is_chargeback")
        ]
        peer_avg_rate = sum(all_rates) / len(all_rates) if all_rates else 0
        all_volumes = []
        for pid, txs in tx_by_producer.items():
            all_volumes.append(sum(t["commission_amount"] for t in txs))
        peer_avg_volume = sum(all_volumes) / len(all_volumes) if all_volumes else 0

        metrics_list: list[ProducerMetrics] = []
        for producer in self._producers:
            pid = producer["id"]
            txs = tx_by_producer.get(pid, [])
            pvs = violation_by_producer.get(pid, [])

            if not txs:
                continue

            rates = [t["commission_rate"] for t in txs if not t.get("is_chargeback")]
            carriers = Counter(t["carrier_name"] for t in txs)
            chargebacks = [t for t in txs if t.get("is_chargeback")]
            total_commission = sum(t["commission_amount"] for t in txs)

            dominant_carrier_count = carriers.most_common(1)[0][1] if carriers else 0
            dominant_pct = dominant_carrier_count / len(txs) if txs else 0

            # Experience estimate
            appt_date = producer.get("appointment_date")
            if appt_date:
                if isinstance(appt_date, str):
                    appt_date = date.fromisoformat(appt_date)
                years = (date.today() - appt_date).days / 365.25
            else:
                years = 5.0  # default assumption

            # End-of-quarter analysis
            quarter_end_count = 0
            for tx in txs:
                td = tx.get("transaction_date")
                if td:
                    if isinstance(td, str):
                        td = date.fromisoformat(td)
                    if td.month in (3, 6, 9, 12) and td.day >= 24:
                        quarter_end_count += 1
            eoq_pct = quarter_end_count / len(txs) if txs else 0

            critical_count = sum(
                1 for v in pvs if v.severity == FindingSeverity.CRITICAL
            )
            high_count = sum(
                1 for v in pvs if v.severity == FindingSeverity.HIGH
            )

            license_expiry = producer.get("license_expiry_date")
            days_to_expiry = None
            expired = False
            if license_expiry:
                if isinstance(license_expiry, str):
                    license_expiry = date.fromisoformat(license_expiry)
                days_to_expiry = (license_expiry - date.today()).days
                expired = days_to_expiry < 0

            metrics_list.append(
                ProducerMetrics(
                    producer_id=pid,
                    total_transactions=len(txs),
                    total_commission=total_commission,
                    total_premium=sum(t["premium_amount"] for t in txs),
                    avg_commission_rate=sum(rates) / len(rates) if rates else 0,
                    max_commission_rate=max(rates) if rates else 0,
                    chargeback_count=len(chargebacks),
                    chargeback_amount=sum(
                        t["commission_amount"] for t in chargebacks
                    ),
                    unique_carriers=len(carriers),
                    dominant_carrier_pct=dominant_pct,
                    license_expired=expired,
                    days_until_license_expiry=days_to_expiry,
                    open_findings_count=len(pvs),
                    critical_findings_count=critical_count,
                    high_findings_count=high_count,
                    end_of_quarter_pct=eoq_pct,
                    peer_avg_commission_rate=peer_avg_rate,
                    peer_avg_volume=peer_avg_volume,
                    years_of_experience=years,
                )
            )

        return self._risk.score_producers(metrics_list)

    @staticmethod
    def _violations_to_findings(
        violations: list[ComplianceViolation],
    ) -> list[dict[str, Any]]:
        """Convert compliance violations into finding dictionaries."""
        seen: set[str] = set()
        findings: list[dict[str, Any]] = []

        for v in violations:
            dedup_key = f"{v.rule_name}:{v.transaction_id}:{v.producer_id}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(
                {
                    "finding_code": v.finding_code,
                    "title": v.rule_name.replace("_", " ").title(),
                    "description": v.description,
                    "severity": v.severity,
                    "status": "open",
                    "regulation_reference": v.regulation_reference,
                    "expected_value": v.expected_value,
                    "actual_value": v.actual_value,
                    "variance_amount": v.variance_amount,
                    "transaction_id": v.transaction_id,
                    "producer_id": v.producer_id,
                }
            )

        return findings

    def _compute_transaction_stats(self) -> dict[str, Any]:
        """Compute aggregate transaction statistics."""
        if not self._transactions:
            return {
                "total_transactions": 0,
                "total_premium": 0,
                "total_commission": 0,
            }

        return {
            "total_transactions": len(self._transactions),
            "total_premium": sum(t["premium_amount"] for t in self._transactions),
            "total_commission": sum(
                t["commission_amount"] for t in self._transactions
            ),
            "total_net_commission": sum(
                t.get("net_commission", 0) for t in self._transactions
            ),
            "avg_commission_rate": sum(
                t["commission_rate"] for t in self._transactions
            )
            / len(self._transactions),
            "chargeback_count": sum(
                1 for t in self._transactions if t.get("is_chargeback")
            ),
        }
