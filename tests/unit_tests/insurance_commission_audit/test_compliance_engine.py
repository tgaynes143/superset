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
"""Tests for the compliance engine."""

from __future__ import annotations

from datetime import date

from superset.insurance_commission_audit.compliance_engine import (
    ComplianceEngine,
    RateLimit,
)
from superset.insurance_commission_audit.models import FindingSeverity


def test_rate_compliance_within_limit() -> None:
    engine = ComplianceEngine()
    violations = engine.check_rate_compliance(
        transaction_id=1,
        producer_id=1,
        state="TX",
        line_of_business="life",
        commission_type="new_business",
        commission_rate=0.40,
        premium_amount=10000.0,
        commission_amount=4000.0,
    )
    assert len(violations) == 0


def test_rate_compliance_exceeds_limit() -> None:
    engine = ComplianceEngine()
    violations = engine.check_rate_compliance(
        transaction_id=1,
        producer_id=1,
        state="TX",
        line_of_business="life",
        commission_type="new_business",
        commission_rate=0.70,
        premium_amount=10000.0,
        commission_amount=7000.0,
    )
    rate_violations = [v for v in violations if v.rule_name == "RATE_EXCEEDS_STATE_LIMIT"]
    assert len(rate_violations) == 1
    assert rate_violations[0].finding_code == "CR-001"
    assert rate_violations[0].variance_amount > 0


def test_rate_compliance_state_override_ny() -> None:
    engine = ComplianceEngine()
    # NY has stricter life cap (0.50 vs default 0.55)
    violations = engine.check_rate_compliance(
        transaction_id=1,
        producer_id=1,
        state="NY",
        line_of_business="life",
        commission_type="new_business",
        commission_rate=0.52,
        premium_amount=10000.0,
        commission_amount=5200.0,
    )
    rate_violations = [v for v in violations if v.rule_name == "RATE_EXCEEDS_STATE_LIMIT"]
    assert len(rate_violations) == 1


def test_commission_amount_mismatch() -> None:
    engine = ComplianceEngine()
    violations = engine.check_rate_compliance(
        transaction_id=1,
        producer_id=1,
        state="TX",
        line_of_business="property",
        commission_type="new_business",
        commission_rate=0.15,
        premium_amount=10000.0,
        commission_amount=2000.0,  # should be 1500
    )
    mismatch = [v for v in violations if v.rule_name == "COMMISSION_AMOUNT_MISMATCH"]
    assert len(mismatch) == 1
    assert mismatch[0].finding_code == "CR-002"


def test_expired_license_check() -> None:
    engine = ComplianceEngine()
    violations = engine.check_license_compliance(
        producer_id=1,
        license_state="TX",
        license_expiry_date=date(2025, 1, 1),
        transaction_state="TX",
        transaction_date=date(2026, 3, 15),
        lines_of_authority="life,health",
        line_of_business="life",
    )
    expired = [v for v in violations if v.rule_name == "EXPIRED_LICENSE"]
    assert len(expired) == 1
    assert expired[0].severity == FindingSeverity.CRITICAL


def test_jurisdiction_mismatch() -> None:
    engine = ComplianceEngine()
    violations = engine.check_license_compliance(
        producer_id=1,
        license_state="TX",
        license_expiry_date=date(2027, 1, 1),
        transaction_state="NY",
        transaction_date=date(2026, 3, 15),
        lines_of_authority="life",
        line_of_business="life",
    )
    mismatch = [v for v in violations if v.rule_name == "JURISDICTION_MISMATCH"]
    assert len(mismatch) == 1


def test_line_of_authority_mismatch() -> None:
    engine = ComplianceEngine()
    violations = engine.check_license_compliance(
        producer_id=1,
        license_state="TX",
        license_expiry_date=date(2027, 1, 1),
        transaction_state="TX",
        transaction_date=date(2026, 3, 15),
        lines_of_authority="life,health",
        line_of_business="property",
    )
    loa = [v for v in violations if v.rule_name == "LOA_MISMATCH"]
    assert len(loa) == 1


def test_chargeback_missing_reason() -> None:
    engine = ComplianceEngine()
    violations = engine.check_chargeback_compliance(
        transaction_id=1,
        producer_id=1,
        is_chargeback=True,
        chargeback_reason=None,
        original_transaction_id=None,
        commission_amount=-500.0,
    )
    assert len(violations) == 2
    codes = {v.rule_name for v in violations}
    assert "CHARGEBACK_NO_REASON" in codes
    assert "CHARGEBACK_NO_ORIGINAL_REF" in codes


def test_non_chargeback_no_violations() -> None:
    engine = ComplianceEngine()
    violations = engine.check_chargeback_compliance(
        transaction_id=1,
        producer_id=1,
        is_chargeback=False,
        chargeback_reason=None,
        original_transaction_id=None,
        commission_amount=500.0,
    )
    assert len(violations) == 0


def test_rate_violation_severity_calculation() -> None:
    assert ComplianceEngine._rate_violation_severity(0.01, 0.20) == FindingSeverity.LOW
    assert ComplianceEngine._rate_violation_severity(0.05, 0.20) == FindingSeverity.MEDIUM
    assert ComplianceEngine._rate_violation_severity(0.10, 0.20) == FindingSeverity.HIGH
    assert ComplianceEngine._rate_violation_severity(0.30, 0.20) == FindingSeverity.CRITICAL


def test_get_rate_limit_fallback_to_default() -> None:
    engine = ComplianceEngine()
    limit = engine.get_rate_limit("WY", "life", "new_business")
    assert limit is not None
    assert limit.max_rate == 0.55


def test_get_rate_limit_state_specific() -> None:
    engine = ComplianceEngine()
    limit = engine.get_rate_limit("NY", "life", "new_business")
    assert limit is not None
    assert limit.max_rate == 0.50  # NY-specific
