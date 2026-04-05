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
"""NAIC-format regulatory report generator for insurance commissioner submission.

Generates structured audit reports conforming to NAIC Market Conduct
Annual Statement (MCAS) format with executive summaries, findings
matrices, financial impact analysis, and remediation tracking.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from superset.insurance_commission_audit.models import (
    AuditStatus,
    FindingSeverity,
    FindingStatus,
)

logger = logging.getLogger(__name__)


@dataclass
class FindingSummary:
    """Summarized finding for report inclusion."""

    finding_code: str
    title: str
    severity: str
    status: str
    regulation_reference: str
    variance_amount: float
    description: str
    remediation_status: str


@dataclass
class ProducerSummary:
    """Summarized producer data for report inclusion."""

    npn: str
    name: str
    license_state: str
    total_transactions: int
    total_commission: float
    findings_count: int
    risk_score: float | None = None
    risk_tier: str | None = None


@dataclass
class FinancialImpact:
    """Financial impact analysis section of the report."""

    total_premium_examined: float
    total_commission_examined: float
    total_variance_identified: float
    variance_by_severity: dict[str, float]
    variance_by_category: dict[str, float]
    estimated_refund_due: float
    estimated_penalty_exposure: float


@dataclass
class RegulatoryReport:
    """Complete NAIC-format regulatory report structure."""

    # Header
    report_title: str
    report_date: str
    report_id: str

    # Jurisdiction
    state: str
    commissioner_name: str
    examiner_name: str
    examiner_title: str
    company_name: str
    company_naic_code: str

    # Period
    audit_period_start: str
    audit_period_end: str

    # Scope
    scope_description: str
    methodology: str
    sampling_methodology: str

    # Statistics
    total_producers_examined: int
    total_transactions_examined: int
    total_commission_volume: float
    total_premium_volume: float

    # Executive Summary (auto-generated)
    executive_summary: str

    # Findings
    findings_summary: list[FindingSummary]
    findings_by_severity: dict[str, int]
    findings_by_status: dict[str, int]

    # Financial Impact
    financial_impact: FinancialImpact

    # Producer Analysis
    producer_summaries: list[ProducerSummary]
    high_risk_producers: list[ProducerSummary]

    # Recommendations
    recommendations: list[str]
    required_corrective_actions: list[str]
    compliance_deadlines: list[dict[str, str]]

    # Certification
    certification_statement: str
    generated_at: str


class RegulatoryReportGenerator:
    """Generates NAIC-format regulatory reports from audit data."""

    def generate(
        self,
        audit_report_data: dict[str, Any],
        findings: list[dict[str, Any]],
        producer_data: list[dict[str, Any]],
        transaction_stats: dict[str, Any],
        risk_profiles: list[dict[str, Any]] | None = None,
    ) -> RegulatoryReport:
        """Generate a complete regulatory report."""
        findings_summary = self._build_findings_summary(findings)
        producer_summaries = self._build_producer_summaries(
            producer_data, risk_profiles
        )
        financial_impact = self._compute_financial_impact(
            findings, transaction_stats
        )
        executive_summary = self._generate_executive_summary(
            audit_report_data, findings_summary, financial_impact, producer_summaries
        )
        recommendations = self._generate_recommendations(
            findings_summary, financial_impact, producer_summaries
        )
        corrective_actions = self._generate_corrective_actions(findings_summary)
        deadlines = self._generate_compliance_deadlines(findings_summary)
        sampling = self._describe_sampling_methodology(
            transaction_stats, audit_report_data
        )

        high_risk = [
            p for p in producer_summaries if (p.risk_tier or "").upper() in ("HIGH", "CRITICAL")
        ]

        state = audit_report_data.get("state_jurisdiction", "")
        company = audit_report_data.get("company_name", "")
        certification = self._generate_certification(
            audit_report_data.get("examiner_name", ""),
            audit_report_data.get("examiner_title", ""),
            state,
            company,
        )

        severity_counts: dict[str, int] = {}
        status_counts: dict[str, int] = {}
        for f in findings_summary:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            status_counts[f.status] = status_counts.get(f.status, 0) + 1

        return RegulatoryReport(
            report_title=audit_report_data.get("title", "Commission Audit Report"),
            report_date=date.today().isoformat(),
            report_id=str(audit_report_data.get("uuid", audit_report_data.get("id", ""))),
            state=state,
            commissioner_name=audit_report_data.get("commissioner_name", ""),
            examiner_name=audit_report_data.get("examiner_name", ""),
            examiner_title=audit_report_data.get("examiner_title", ""),
            company_name=company,
            company_naic_code=audit_report_data.get("company_naic_code", ""),
            audit_period_start=str(audit_report_data.get("audit_period_start", "")),
            audit_period_end=str(audit_report_data.get("audit_period_end", "")),
            scope_description=audit_report_data.get("scope_description", ""),
            methodology=audit_report_data.get("methodology_notes", ""),
            sampling_methodology=sampling,
            total_producers_examined=audit_report_data.get("total_producers_examined", 0),
            total_transactions_examined=audit_report_data.get("total_transactions_examined", 0),
            total_commission_volume=audit_report_data.get("total_commission_volume", 0.0),
            total_premium_volume=audit_report_data.get("total_premium_volume", 0.0),
            executive_summary=executive_summary,
            findings_summary=findings_summary,
            findings_by_severity=severity_counts,
            findings_by_status=status_counts,
            financial_impact=financial_impact,
            producer_summaries=producer_summaries,
            high_risk_producers=high_risk,
            recommendations=recommendations,
            required_corrective_actions=corrective_actions,
            compliance_deadlines=deadlines,
            certification_statement=certification,
            generated_at=datetime.utcnow().isoformat(),
        )

    @staticmethod
    def _build_findings_summary(
        findings: list[dict[str, Any]],
    ) -> list[FindingSummary]:
        """Convert raw finding data into report summary format."""
        summaries: list[FindingSummary] = []
        for f in findings:
            remediation_status = "Pending"
            if f.get("status") == FindingStatus.REMEDIATED:
                remediation_status = "Remediated"
            elif f.get("status") == FindingStatus.CLOSED:
                remediation_status = "Closed"
            elif f.get("status") == FindingStatus.ACKNOWLEDGED:
                remediation_status = "Acknowledged"
            elif f.get("remediation_plan"):
                remediation_status = "Plan in place"

            summaries.append(
                FindingSummary(
                    finding_code=f.get("finding_code", ""),
                    title=f.get("title", ""),
                    severity=f.get("severity", ""),
                    status=f.get("status", ""),
                    regulation_reference=f.get("regulation_reference", ""),
                    variance_amount=float(f.get("variance_amount", 0) or 0),
                    description=f.get("description", ""),
                    remediation_status=remediation_status,
                )
            )
        return summaries

    @staticmethod
    def _build_producer_summaries(
        producer_data: list[dict[str, Any]],
        risk_profiles: list[dict[str, Any]] | None = None,
    ) -> list[ProducerSummary]:
        """Build producer summary entries for the report."""
        risk_map: dict[int, dict[str, Any]] = {}
        if risk_profiles:
            for rp in risk_profiles:
                risk_map[rp["producer_id"]] = rp

        summaries: list[ProducerSummary] = []
        for p in producer_data:
            pid = p.get("id", 0)
            risk = risk_map.get(pid, {})
            name = p.get("display_name", "") or (
                f"{p.get('last_name', '')}, {p.get('first_name', '')}"
            )
            summaries.append(
                ProducerSummary(
                    npn=p.get("national_producer_number", ""),
                    name=name,
                    license_state=p.get("license_state", ""),
                    total_transactions=p.get("total_transactions", 0),
                    total_commission=float(p.get("total_commission", 0)),
                    findings_count=p.get("findings_count", 0),
                    risk_score=risk.get("composite_score"),
                    risk_tier=risk.get("risk_tier"),
                )
            )
        return summaries

    @staticmethod
    def _compute_financial_impact(
        findings: list[dict[str, Any]],
        transaction_stats: dict[str, Any],
    ) -> FinancialImpact:
        """Compute the financial impact analysis section."""
        total_variance = 0.0
        variance_by_severity: dict[str, float] = {}
        variance_by_category: dict[str, float] = {}

        for f in findings:
            v = float(f.get("variance_amount", 0) or 0)
            total_variance += v
            sev = f.get("severity", "unknown")
            variance_by_severity[sev] = variance_by_severity.get(sev, 0) + v
            code_prefix = f.get("finding_code", "XX")[:2]
            category_map = {
                "CR": "Commission Rate Violations",
                "LI": "License Violations",
                "CB": "Chargeback Issues",
                "AN": "Anomaly Detections",
            }
            cat = category_map.get(code_prefix, "Other")
            variance_by_category[cat] = variance_by_category.get(cat, 0) + v

        # Estimate penalties based on severity
        critical_variance = variance_by_severity.get(FindingSeverity.CRITICAL, 0)
        high_variance = variance_by_severity.get(FindingSeverity.HIGH, 0)
        estimated_penalty = critical_variance * 0.5 + high_variance * 0.25

        return FinancialImpact(
            total_premium_examined=transaction_stats.get("total_premium", 0),
            total_commission_examined=transaction_stats.get("total_commission", 0),
            total_variance_identified=total_variance,
            variance_by_severity=variance_by_severity,
            variance_by_category=variance_by_category,
            estimated_refund_due=total_variance,
            estimated_penalty_exposure=estimated_penalty,
        )

    def _generate_executive_summary(
        self,
        audit_data: dict[str, Any],
        findings: list[FindingSummary],
        financial_impact: FinancialImpact,
        producers: list[ProducerSummary],
    ) -> str:
        """Auto-generate an executive summary from audit data."""
        company = audit_data.get("company_name", "the company")
        state = audit_data.get("state_jurisdiction", "the jurisdiction")
        period_start = audit_data.get("audit_period_start", "")
        period_end = audit_data.get("audit_period_end", "")
        num_producers = audit_data.get("total_producers_examined", 0)
        num_transactions = audit_data.get("total_transactions_examined", 0)

        critical_count = sum(
            1 for f in findings if f.severity == FindingSeverity.CRITICAL
        )
        high_count = sum(
            1 for f in findings if f.severity == FindingSeverity.HIGH
        )
        total_findings = len(findings)
        high_risk = [p for p in producers if (p.risk_tier or "").upper() in ("HIGH", "CRITICAL")]

        severity_assessment = "satisfactory"
        if critical_count > 0:
            severity_assessment = "unsatisfactory with critical deficiencies"
        elif high_count > 3:
            severity_assessment = "needs significant improvement"
        elif high_count > 0:
            severity_assessment = "needs improvement"

        sections: list[str] = []

        sections.append(
            f"This report presents the findings of the market conduct examination "
            f"of {company}'s producer commission practices in {state} for the "
            f"period {period_start} through {period_end}."
        )

        sections.append(
            f"The examination reviewed {num_transactions:,} commission transactions "
            f"across {num_producers:,} producers, representing "
            f"${financial_impact.total_premium_examined:,.2f} in premium volume and "
            f"${financial_impact.total_commission_examined:,.2f} in commission payments."
        )

        sections.append(
            f"The examination identified {total_findings} findings, including "
            f"{critical_count} critical and {high_count} high-severity issues. "
            f"The total financial variance identified is "
            f"${financial_impact.total_variance_identified:,.2f}."
        )

        if high_risk:
            sections.append(
                f"{len(high_risk)} producer(s) were identified as high or critical "
                f"risk requiring enhanced monitoring or corrective action."
            )

        sections.append(
            f"The overall assessment of {company}'s commission practices is "
            f"{severity_assessment}. "
            f"{'Immediate corrective action is required.' if critical_count > 0 else ''}"
        )

        if financial_impact.estimated_penalty_exposure > 0:
            sections.append(
                f"Estimated financial exposure including potential penalties: "
                f"${financial_impact.estimated_penalty_exposure:,.2f}."
            )

        return "\n\n".join(sections)

    @staticmethod
    def _generate_recommendations(
        findings: list[FindingSummary],
        financial_impact: FinancialImpact,
        producers: list[ProducerSummary],
    ) -> list[str]:
        """Generate prioritized recommendations."""
        recs: list[str] = []

        critical = [f for f in findings if f.severity == FindingSeverity.CRITICAL]
        if critical:
            recs.append(
                f"PRIORITY 1: Address {len(critical)} critical findings immediately. "
                f"Suspend commission payments to affected producers until resolved."
            )

        if financial_impact.total_variance_identified > 0:
            recs.append(
                f"PRIORITY 2: Initiate refund process for "
                f"${financial_impact.total_variance_identified:,.2f} in "
                f"identified commission overpayments."
            )

        rate_violations = [f for f in findings if f.finding_code.startswith("CR")]
        if rate_violations:
            recs.append(
                "Implement automated commission rate validation against "
                "state regulatory limits before payment processing."
            )

        license_violations = [f for f in findings if f.finding_code.startswith("LI")]
        if license_violations:
            recs.append(
                "Establish automated license verification integrated with "
                "NIPR database before commission payment authorization."
            )

        anomaly_findings = [f for f in findings if f.finding_code.startswith("AN")]
        if anomaly_findings:
            recs.append(
                "Deploy continuous monitoring with statistical anomaly "
                "detection for real-time commission surveillance."
            )

        high_risk = [p for p in producers if (p.risk_tier or "").upper() == "CRITICAL"]
        if high_risk:
            recs.append(
                f"Place {len(high_risk)} critical-risk producers under "
                f"enhanced supervision with quarterly review cycles."
            )

        recs.append(
            "Conduct follow-up examination within 12 months to verify "
            "corrective actions have been implemented."
        )

        return recs

    @staticmethod
    def _generate_corrective_actions(
        findings: list[FindingSummary],
    ) -> list[str]:
        """Generate required corrective actions based on findings."""
        actions: list[str] = []
        seen_codes: set[str] = set()

        for f in findings:
            prefix = f.finding_code[:2]
            if prefix in seen_codes:
                continue
            seen_codes.add(prefix)

            if prefix == "CR":
                actions.append(
                    "Implement commission rate schedule validation system "
                    "that prevents payments exceeding state maximums."
                )
            elif prefix == "LI":
                actions.append(
                    "Establish producer license verification workflow "
                    "integrated with state licensing databases."
                )
            elif prefix == "CB":
                actions.append(
                    "Implement chargeback documentation requirements "
                    "with mandatory original transaction references."
                )
            elif prefix == "AN":
                actions.append(
                    "Deploy statistical monitoring system for ongoing "
                    "commission anomaly detection and alerting."
                )

        return actions

    @staticmethod
    def _generate_compliance_deadlines(
        findings: list[FindingSummary],
    ) -> list[dict[str, str]]:
        """Generate compliance deadlines based on finding severity."""
        deadlines: list[dict[str, str]] = []
        today = date.today()

        critical = [f for f in findings if f.severity == FindingSeverity.CRITICAL]
        if critical:
            deadline = today.replace(day=1)
            if deadline.month == 12:
                deadline = deadline.replace(year=deadline.year + 1, month=1)
            else:
                deadline = deadline.replace(month=deadline.month + 1)
            deadlines.append(
                {
                    "action": "Remediate all critical findings",
                    "deadline": deadline.isoformat(),
                    "severity": "critical",
                    "count": str(len(critical)),
                }
            )

        high = [f for f in findings if f.severity == FindingSeverity.HIGH]
        if high:
            deadline_high = today.replace(day=1)
            for _ in range(3):
                if deadline_high.month == 12:
                    deadline_high = deadline_high.replace(
                        year=deadline_high.year + 1, month=1
                    )
                else:
                    deadline_high = deadline_high.replace(
                        month=deadline_high.month + 1
                    )
            deadlines.append(
                {
                    "action": "Remediate all high-severity findings",
                    "deadline": deadline_high.isoformat(),
                    "severity": "high",
                    "count": str(len(high)),
                }
            )

        medium_low = [
            f
            for f in findings
            if f.severity in (FindingSeverity.MEDIUM, FindingSeverity.LOW)
        ]
        if medium_low:
            deadline_ml = today.replace(day=1)
            for _ in range(6):
                if deadline_ml.month == 12:
                    deadline_ml = deadline_ml.replace(
                        year=deadline_ml.year + 1, month=1
                    )
                else:
                    deadline_ml = deadline_ml.replace(month=deadline_ml.month + 1)
            deadlines.append(
                {
                    "action": "Remediate remaining findings",
                    "deadline": deadline_ml.isoformat(),
                    "severity": "medium/low",
                    "count": str(len(medium_low)),
                }
            )

        return deadlines

    @staticmethod
    def _describe_sampling_methodology(
        stats: dict[str, Any],
        audit_data: dict[str, Any],
    ) -> str:
        """Generate sampling methodology description."""
        total = stats.get("total_transactions", 0)
        examined = audit_data.get("total_transactions_examined", 0)

        if total > 0 and examined > 0:
            pct = (examined / total) * 100
            if pct >= 100:
                return (
                    f"Complete population examination: all {total:,} transactions "
                    f"were reviewed."
                )
            return (
                f"Statistical sampling: {examined:,} of {total:,} transactions "
                f"({pct:.1f}%) were selected using stratified random sampling "
                f"weighted by commission amount and producer risk score."
            )
        return "Sampling methodology details not available."

    @staticmethod
    def _generate_certification(
        examiner_name: str,
        examiner_title: str,
        state: str,
        company: str,
    ) -> str:
        """Generate the official certification statement."""
        return (
            f"I, {examiner_name or '[Examiner Name]'}, "
            f"{examiner_title or '[Title]'}, hereby certify that "
            f"this examination of {company}'s producer commission practices "
            f"in {state} has been conducted in accordance with NAIC "
            f"Market Regulation Handbook standards and applicable state "
            f"insurance laws. The findings, conclusions, and recommendations "
            f"contained herein are based on a thorough review of the "
            f"company's records, documents, and data during the examination "
            f"period. This report is submitted for the consideration of "
            f"the Insurance Commissioner."
        )
