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
"""Unit tests for Insurance Commission Audit schemas."""

from __future__ import annotations

from datetime import date

import pytest
from marshmallow import ValidationError

from superset.insurance_commission_audit.schemas import (
    AuditFindingPostSchema,
    AuditFindingPutSchema,
    CommissionAuditReportPostSchema,
    CommissionAuditReportPutSchema,
    CommissionTransactionPostSchema,
    InsuranceProducerPostSchema,
    InsuranceProducerPutSchema,
)


def test_producer_post_schema_valid_individual() -> None:
    schema = InsuranceProducerPostSchema()
    data = schema.load(
        {
            "national_producer_number": "1234567",
            "license_number": "LIC-001",
            "license_state": "TX",
            "first_name": "John",
            "last_name": "Smith",
            "producer_type": "individual",
        }
    )
    assert data["national_producer_number"] == "1234567"
    assert data["license_state"] == "TX"


def test_producer_post_schema_valid_business() -> None:
    schema = InsuranceProducerPostSchema()
    data = schema.load(
        {
            "national_producer_number": "9876543",
            "license_number": "LIC-002",
            "license_state": "CA",
            "business_name": "Acme Insurance Agency",
            "producer_type": "business_entity",
        }
    )
    assert data["business_name"] == "Acme Insurance Agency"


def test_producer_post_schema_individual_missing_name() -> None:
    schema = InsuranceProducerPostSchema()
    with pytest.raises(ValidationError, match="first_name and last_name"):
        schema.load(
            {
                "national_producer_number": "1234567",
                "license_number": "LIC-001",
                "license_state": "TX",
                "producer_type": "individual",
            }
        )


def test_producer_post_schema_business_missing_name() -> None:
    schema = InsuranceProducerPostSchema()
    with pytest.raises(ValidationError, match="business_name"):
        schema.load(
            {
                "national_producer_number": "1234567",
                "license_number": "LIC-001",
                "license_state": "TX",
                "producer_type": "business_entity",
            }
        )


def test_producer_post_schema_invalid_state() -> None:
    schema = InsuranceProducerPostSchema()
    with pytest.raises(ValidationError):
        schema.load(
            {
                "national_producer_number": "1234567",
                "license_number": "LIC-001",
                "license_state": "XX",
                "first_name": "John",
                "last_name": "Smith",
            }
        )


def test_producer_put_schema_partial_update() -> None:
    schema = InsuranceProducerPutSchema()
    data = schema.load({"status": "suspended", "email": "new@example.com"})
    assert data["status"] == "suspended"
    assert data["email"] == "new@example.com"


def test_commission_transaction_post_schema_valid() -> None:
    schema = CommissionTransactionPostSchema()
    data = schema.load(
        {
            "producer_id": 1,
            "policy_number": "POL-001",
            "line_of_business": "life",
            "commission_type": "new_business",
            "transaction_date": "2026-01-15",
            "premium_amount": 10000.0,
            "commission_rate": 0.15,
            "commission_amount": 1500.0,
            "net_commission": 1500.0,
            "carrier_name": "ABC Insurance Co",
        }
    )
    assert data["policy_number"] == "POL-001"
    assert data["commission_rate"] == 0.15


def test_commission_transaction_post_schema_invalid_rate() -> None:
    schema = CommissionTransactionPostSchema()
    with pytest.raises(ValidationError):
        schema.load(
            {
                "producer_id": 1,
                "policy_number": "POL-001",
                "line_of_business": "life",
                "commission_type": "new_business",
                "transaction_date": "2026-01-15",
                "premium_amount": 10000.0,
                "commission_rate": 1.5,
                "commission_amount": 1500.0,
                "net_commission": 1500.0,
                "carrier_name": "ABC Insurance Co",
            }
        )


def test_audit_report_post_schema_valid() -> None:
    schema = CommissionAuditReportPostSchema()
    data = schema.load(
        {
            "title": "Q1 2026 Commission Audit",
            "audit_period_start": "2026-01-01",
            "audit_period_end": "2026-03-31",
            "state_jurisdiction": "NY",
            "company_name": "XYZ Insurance Corp",
        }
    )
    assert data["title"] == "Q1 2026 Commission Audit"
    assert data["state_jurisdiction"] == "NY"


def test_audit_report_post_schema_invalid_period() -> None:
    schema = CommissionAuditReportPostSchema()
    with pytest.raises(ValidationError, match="audit_period_start must be before"):
        schema.load(
            {
                "title": "Bad Period Audit",
                "audit_period_start": "2026-06-30",
                "audit_period_end": "2026-01-01",
                "state_jurisdiction": "NY",
                "company_name": "XYZ Insurance Corp",
            }
        )


def test_audit_finding_post_schema_valid() -> None:
    schema = AuditFindingPostSchema()
    data = schema.load(
        {
            "audit_report_id": 1,
            "finding_code": "CR-001",
            "title": "Excessive Commission Rate",
            "description": "Commission rate exceeds state maximum for this LOB.",
            "severity": "high",
        }
    )
    assert data["finding_code"] == "CR-001"
    assert data["severity"] == "high"


def test_audit_finding_put_schema_partial() -> None:
    schema = AuditFindingPutSchema()
    data = schema.load(
        {
            "status": "remediated",
            "remediation_notes": "Rate adjusted to comply with regulations.",
            "remediated_date": "2026-03-15",
        }
    )
    assert data["status"] == "remediated"


def test_audit_finding_post_schema_invalid_severity() -> None:
    schema = AuditFindingPostSchema()
    with pytest.raises(ValidationError):
        schema.load(
            {
                "audit_report_id": 1,
                "finding_code": "CR-001",
                "title": "Test",
                "description": "Test description",
                "severity": "ultra_critical",
            }
        )
