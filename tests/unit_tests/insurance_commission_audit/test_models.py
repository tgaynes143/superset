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
"""Unit tests for Insurance Commission Audit models."""

from __future__ import annotations

import uuid
from datetime import date

from superset.insurance_commission_audit.models import (
    AuditFinding,
    AuditStatus,
    CommissionAuditReport,
    CommissionTransaction,
    CommissionType,
    FindingSeverity,
    FindingStatus,
    InsuranceProducer,
    LineOfBusiness,
    ProducerStatus,
    ProducerType,
)


def test_insurance_producer_repr_individual() -> None:
    producer = InsuranceProducer()
    producer.first_name = "John"
    producer.last_name = "Smith"
    producer.national_producer_number = "1234567"
    producer.producer_type = ProducerType.INDIVIDUAL
    assert "Smith, John" in repr(producer)
    assert "1234567" in repr(producer)


def test_insurance_producer_repr_business() -> None:
    producer = InsuranceProducer()
    producer.business_name = "Acme Insurance Agency"
    producer.national_producer_number = "9876543"
    producer.producer_type = ProducerType.BUSINESS_ENTITY
    assert "Acme Insurance Agency" in repr(producer)


def test_insurance_producer_display_name_individual() -> None:
    producer = InsuranceProducer()
    producer.first_name = "Jane"
    producer.last_name = "Doe"
    producer.producer_type = ProducerType.INDIVIDUAL
    assert producer.display_name == "Doe, Jane"


def test_insurance_producer_display_name_business() -> None:
    producer = InsuranceProducer()
    producer.business_name = "Test Agency LLC"
    producer.producer_type = ProducerType.BUSINESS_ENTITY
    assert producer.display_name == "Test Agency LLC"


def test_commission_transaction_repr() -> None:
    tx = CommissionTransaction()
    tx.policy_number = "POL-001"
    tx.commission_amount = 1500.50
    tx.transaction_date = date(2026, 1, 15)
    result = repr(tx)
    assert "POL-001" in result
    assert "$1500.50" in result


def test_commission_audit_report_repr() -> None:
    report = CommissionAuditReport()
    report.title = "Q1 2026 Commission Audit"
    report.status = AuditStatus.IN_PROGRESS
    result = repr(report)
    assert "Q1 2026 Commission Audit" in result
    assert "in_progress" in result


def test_audit_finding_repr() -> None:
    finding = AuditFinding()
    finding.finding_code = "CR-001"
    finding.title = "Excessive Commission Rate"
    finding.severity = FindingSeverity.HIGH
    result = repr(finding)
    assert "CR-001" in result
    assert "Excessive Commission Rate" in result
    assert "high" in result


def test_producer_status_enum() -> None:
    assert ProducerStatus.ACTIVE == "active"
    assert ProducerStatus.SUSPENDED == "suspended"
    assert ProducerStatus.TERMINATED == "terminated"


def test_commission_type_enum() -> None:
    assert CommissionType.NEW_BUSINESS == "new_business"
    assert CommissionType.RENEWAL == "renewal"
    assert CommissionType.OVERRIDE == "override"
    assert CommissionType.CONTINGENT == "contingent"


def test_line_of_business_enum() -> None:
    assert LineOfBusiness.LIFE == "life"
    assert LineOfBusiness.HEALTH == "health"
    assert LineOfBusiness.PROPERTY == "property"
    assert LineOfBusiness.WORKERS_COMP == "workers_comp"


def test_audit_status_enum() -> None:
    assert AuditStatus.DRAFT == "draft"
    assert AuditStatus.IN_PROGRESS == "in_progress"
    assert AuditStatus.SUBMITTED == "submitted"
    assert AuditStatus.COMPLETED == "completed"


def test_finding_severity_enum() -> None:
    assert FindingSeverity.LOW == "low"
    assert FindingSeverity.CRITICAL == "critical"


def test_finding_status_enum() -> None:
    assert FindingStatus.OPEN == "open"
    assert FindingStatus.REMEDIATED == "remediated"
    assert FindingStatus.ESCALATED == "escalated"
