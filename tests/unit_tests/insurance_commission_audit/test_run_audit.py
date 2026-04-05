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
"""Tests for the automated audit execution command."""

from __future__ import annotations

from datetime import date

import pytest

from superset.commands.insurance_commission_audit.run_audit import RunAuditCommand


def _sample_audit_data() -> dict:
    return {
        "id": 1,
        "title": "Q1 2026 Audit",
        "state_jurisdiction": "TX",
        "audit_period_start": "2026-01-01",
        "audit_period_end": "2026-03-31",
        "company_name": "Test Insurance",
        "examiner_name": "Test Examiner",
        "examiner_title": "Examiner",
        "company_naic_code": "12345",
        "total_producers_examined": 2,
        "total_transactions_examined": 10,
    }


def _sample_producers() -> list[dict]:
    return [
        {
            "id": 1,
            "national_producer_number": "1234567",
            "first_name": "John",
            "last_name": "Smith",
            "license_state": "TX",
            "license_expiry_date": date(2027, 12, 31),
            "lines_of_authority": "life,health,property",
            "appointment_date": date(2020, 1, 1),
        },
        {
            "id": 2,
            "national_producer_number": "7654321",
            "first_name": "Jane",
            "last_name": "Doe",
            "license_state": "TX",
            "license_expiry_date": date(2025, 6, 30),  # expired
            "lines_of_authority": "life",
            "appointment_date": date(2024, 6, 1),
        },
    ]


def _sample_transactions() -> list[dict]:
    return [
        {
            "id": i,
            "producer_id": 1 if i <= 5 else 2,
            "policy_number": f"POL-{i:03d}",
            "line_of_business": "life",
            "commission_type": "new_business",
            "transaction_date": date(2026, 1, 15 if i <= 5 else 20),
            "premium_amount": 10000.0,
            "commission_rate": 0.15 if i <= 8 else 0.70,  # tx 9,10 exceed limits
            "commission_amount": 1500.0 if i <= 8 else 7000.0,
            "net_commission": 1500.0 if i <= 8 else 7000.0,
            "carrier_name": "ABC Insurance",
            "is_chargeback": False,
        }
        for i in range(1, 11)
    ]


def test_run_audit_full_pipeline() -> None:
    cmd = RunAuditCommand(
        audit_report_data=_sample_audit_data(),
        producers=_sample_producers(),
        transactions=_sample_transactions(),
    )
    result = cmd.run()

    assert result["status"] == "completed"
    assert result["audit_report_id"] == 1
    assert result["compliance_violations"] > 0
    assert result["findings_generated"] > 0
    assert len(result["anomaly_results"]) == 7
    assert len(result["risk_profiles"]) == 2
    assert "executive_summary" in result["regulatory_report"]
    assert "financial_impact" in result["regulatory_report"]
    assert result["audit_trail"]["total_entries"] > 0


def test_run_audit_detects_rate_violations() -> None:
    cmd = RunAuditCommand(
        audit_report_data=_sample_audit_data(),
        producers=_sample_producers(),
        transactions=_sample_transactions(),
    )
    result = cmd.run()

    rate_findings = [
        f for f in result["findings"] if f["finding_code"] == "CR-001"
    ]
    assert len(rate_findings) > 0


def test_run_audit_detects_expired_license() -> None:
    cmd = RunAuditCommand(
        audit_report_data=_sample_audit_data(),
        producers=_sample_producers(),
        transactions=_sample_transactions(),
    )
    result = cmd.run()

    license_findings = [
        f for f in result["findings"] if f["finding_code"] == "LIC-001"
    ]
    assert len(license_findings) > 0


def test_run_audit_risk_profiles_sorted() -> None:
    cmd = RunAuditCommand(
        audit_report_data=_sample_audit_data(),
        producers=_sample_producers(),
        transactions=_sample_transactions(),
    )
    result = cmd.run()

    profiles = result["risk_profiles"]
    scores = [p["composite_score"] for p in profiles]
    assert scores == sorted(scores, reverse=True)


def test_run_audit_regulatory_report_has_recommendations() -> None:
    cmd = RunAuditCommand(
        audit_report_data=_sample_audit_data(),
        producers=_sample_producers(),
        transactions=_sample_transactions(),
    )
    result = cmd.run()

    reg = result["regulatory_report"]
    assert len(reg["recommendations"]) > 0
    assert len(reg["corrective_actions"]) > 0
    assert len(reg["compliance_deadlines"]) > 0


def test_run_audit_transaction_stats() -> None:
    cmd = RunAuditCommand(
        audit_report_data=_sample_audit_data(),
        producers=_sample_producers(),
        transactions=_sample_transactions(),
    )
    result = cmd.run()

    stats = result["transaction_stats"]
    assert stats["total_transactions"] == 10
    assert stats["total_premium"] == 100000.0


def test_validate_missing_state() -> None:
    cmd = RunAuditCommand(
        audit_report_data={"id": 1},
        producers=[],
        transactions=[],
    )
    with pytest.raises(ValueError, match="State jurisdiction"):
        cmd.run()


def test_validate_missing_period() -> None:
    cmd = RunAuditCommand(
        audit_report_data={"id": 1, "state_jurisdiction": "TX"},
        producers=[],
        transactions=[],
    )
    with pytest.raises(ValueError, match="Audit period start"):
        cmd.run()


def test_run_audit_empty_transactions() -> None:
    cmd = RunAuditCommand(
        audit_report_data=_sample_audit_data(),
        producers=_sample_producers(),
        transactions=[],
    )
    result = cmd.run()
    assert result["status"] == "completed"
    assert result["compliance_violations"] == 0
    assert result["findings_generated"] == 0


def test_deduplication_of_findings() -> None:
    # Create transactions that would trigger the same violation twice
    txns = [
        {
            "id": 1,
            "producer_id": 1,
            "policy_number": "POL-001",
            "line_of_business": "life",
            "commission_type": "new_business",
            "transaction_date": date(2026, 1, 15),
            "premium_amount": 10000.0,
            "commission_rate": 0.70,
            "commission_amount": 7000.0,
            "net_commission": 7000.0,
            "carrier_name": "ABC",
            "is_chargeback": False,
        },
    ]
    cmd = RunAuditCommand(
        audit_report_data=_sample_audit_data(),
        producers=_sample_producers(),
        transactions=txns,
    )
    result = cmd.run()

    # Each unique violation should appear only once
    finding_keys = set()
    for f in result["findings"]:
        key = f"{f['finding_code']}:{f.get('transaction_id')}:{f.get('producer_id')}"
        assert key not in finding_keys, f"Duplicate finding: {key}"
        finding_keys.add(key)
