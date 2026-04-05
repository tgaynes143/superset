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
"""Tests for the regulatory report generator."""

from __future__ import annotations

from superset.insurance_commission_audit.regulatory_report import (
    RegulatoryReportGenerator,
)


def _sample_audit_data() -> dict:
    return {
        "id": 1,
        "title": "Q1 2026 TX Commission Audit",
        "state_jurisdiction": "TX",
        "audit_period_start": "2026-01-01",
        "audit_period_end": "2026-03-31",
        "commissioner_name": "Jane Commissioner",
        "examiner_name": "John Examiner",
        "examiner_title": "Senior Market Conduct Examiner",
        "company_name": "ABC Insurance Corp",
        "company_naic_code": "12345",
        "total_producers_examined": 25,
        "total_transactions_examined": 500,
        "total_commission_volume": 250000.0,
        "total_premium_volume": 2500000.0,
        "methodology_notes": "Statistical sampling with risk-based selection.",
        "scope_description": "All producer commissions in TX for Q1 2026.",
    }


def _sample_findings() -> list[dict]:
    return [
        {
            "finding_code": "CR-001",
            "title": "Rate Exceeds State Limit",
            "severity": "critical",
            "status": "open",
            "regulation_reference": "TX Insurance Code Chapter 4005",
            "variance_amount": 5000.0,
            "description": "Commission rate exceeds TX maximum.",
        },
        {
            "finding_code": "LIC-001",
            "title": "Expired License",
            "severity": "high",
            "status": "acknowledged",
            "regulation_reference": "TX Insurance Licensing Statute",
            "variance_amount": 2000.0,
            "description": "Producer license expired.",
        },
        {
            "finding_code": "AN-004",
            "title": "Duplicate Transaction",
            "severity": "medium",
            "status": "remediated",
            "regulation_reference": "Internal Audit Standard",
            "variance_amount": 1500.0,
            "description": "Duplicate payment detected.",
            "remediation_plan": "Refund processed.",
        },
    ]


def _sample_producers() -> list[dict]:
    return [
        {
            "id": 1,
            "national_producer_number": "1234567",
            "first_name": "John",
            "last_name": "Smith",
            "license_state": "TX",
            "total_transactions": 100,
            "total_commission": 50000.0,
            "findings_count": 2,
        },
    ]


def _sample_stats() -> dict:
    return {
        "total_transactions": 500,
        "total_premium": 2500000.0,
        "total_commission": 250000.0,
    }


def test_generate_report_structure() -> None:
    gen = RegulatoryReportGenerator()
    report = gen.generate(
        audit_report_data=_sample_audit_data(),
        findings=_sample_findings(),
        producer_data=_sample_producers(),
        transaction_stats=_sample_stats(),
    )
    assert report.report_title == "Q1 2026 TX Commission Audit"
    assert report.state == "TX"
    assert report.company_name == "ABC Insurance Corp"
    assert len(report.findings_summary) == 3


def test_executive_summary_generated() -> None:
    gen = RegulatoryReportGenerator()
    report = gen.generate(
        audit_report_data=_sample_audit_data(),
        findings=_sample_findings(),
        producer_data=_sample_producers(),
        transaction_stats=_sample_stats(),
    )
    assert "ABC Insurance Corp" in report.executive_summary
    assert "TX" in report.executive_summary
    assert "500" in report.executive_summary
    assert "critical" in report.executive_summary.lower() or "1 critical" in report.executive_summary


def test_financial_impact_calculated() -> None:
    gen = RegulatoryReportGenerator()
    report = gen.generate(
        audit_report_data=_sample_audit_data(),
        findings=_sample_findings(),
        producer_data=_sample_producers(),
        transaction_stats=_sample_stats(),
    )
    assert report.financial_impact.total_variance_identified == 8500.0
    assert report.financial_impact.total_premium_examined == 2500000.0
    assert report.financial_impact.estimated_refund_due == 8500.0
    assert report.financial_impact.estimated_penalty_exposure > 0


def test_recommendations_generated() -> None:
    gen = RegulatoryReportGenerator()
    report = gen.generate(
        audit_report_data=_sample_audit_data(),
        findings=_sample_findings(),
        producer_data=_sample_producers(),
        transaction_stats=_sample_stats(),
    )
    assert len(report.recommendations) > 0
    assert any("rate" in r.lower() for r in report.recommendations)


def test_corrective_actions_generated() -> None:
    gen = RegulatoryReportGenerator()
    report = gen.generate(
        audit_report_data=_sample_audit_data(),
        findings=_sample_findings(),
        producer_data=_sample_producers(),
        transaction_stats=_sample_stats(),
    )
    assert len(report.required_corrective_actions) > 0


def test_compliance_deadlines_generated() -> None:
    gen = RegulatoryReportGenerator()
    report = gen.generate(
        audit_report_data=_sample_audit_data(),
        findings=_sample_findings(),
        producer_data=_sample_producers(),
        transaction_stats=_sample_stats(),
    )
    assert len(report.compliance_deadlines) > 0
    critical_deadlines = [
        d for d in report.compliance_deadlines if d["severity"] == "critical"
    ]
    assert len(critical_deadlines) > 0


def test_certification_statement() -> None:
    gen = RegulatoryReportGenerator()
    report = gen.generate(
        audit_report_data=_sample_audit_data(),
        findings=_sample_findings(),
        producer_data=_sample_producers(),
        transaction_stats=_sample_stats(),
    )
    assert "John Examiner" in report.certification_statement
    assert "ABC Insurance Corp" in report.certification_statement
    assert "NAIC" in report.certification_statement


def test_findings_by_severity() -> None:
    gen = RegulatoryReportGenerator()
    report = gen.generate(
        audit_report_data=_sample_audit_data(),
        findings=_sample_findings(),
        producer_data=_sample_producers(),
        transaction_stats=_sample_stats(),
    )
    assert report.findings_by_severity.get("critical", 0) == 1
    assert report.findings_by_severity.get("high", 0) == 1
    assert report.findings_by_severity.get("medium", 0) == 1


def test_empty_findings() -> None:
    gen = RegulatoryReportGenerator()
    report = gen.generate(
        audit_report_data=_sample_audit_data(),
        findings=[],
        producer_data=_sample_producers(),
        transaction_stats=_sample_stats(),
    )
    assert report.financial_impact.total_variance_identified == 0
    assert len(report.findings_summary) == 0
    assert "0 findings" in report.executive_summary


def test_variance_by_category() -> None:
    gen = RegulatoryReportGenerator()
    report = gen.generate(
        audit_report_data=_sample_audit_data(),
        findings=_sample_findings(),
        producer_data=_sample_producers(),
        transaction_stats=_sample_stats(),
    )
    categories = report.financial_impact.variance_by_category
    assert "Commission Rate Violations" in categories
    assert categories["Commission Rate Violations"] == 5000.0
