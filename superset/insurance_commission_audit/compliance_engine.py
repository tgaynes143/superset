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
"""State regulatory commission rate compliance engine.

Enforces per-state, per-line-of-business maximum commission rate limits
per NAIC model regulations and individual state insurance codes.
Supports first-year vs renewal rate distinctions and special product
category overrides.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from superset.insurance_commission_audit.models import (
    CommissionType,
    FindingSeverity,
    LineOfBusiness,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RateLimit:
    """Maximum commission rate for a state/LOB/commission-type combination."""

    max_rate: float
    effective_date: date | None = None
    expiry_date: date | None = None
    regulation_citation: str = ""
    notes: str = ""


@dataclass
class ComplianceViolation:
    """A detected compliance violation from rate checking."""

    rule_name: str
    severity: str
    transaction_id: int | None
    producer_id: int | None
    description: str
    regulation_reference: str
    expected_value: str
    actual_value: str
    variance_amount: float
    finding_code: str
    metadata: dict[str, Any] = field(default_factory=dict)


# State regulatory rate limits database
# Organized as: state -> line_of_business -> commission_type -> RateLimit
# These represent composite NAIC model regulation and state-specific limits
STATE_RATE_LIMITS: dict[str, dict[str, dict[str, RateLimit]]] = {
    "__default__": {
        LineOfBusiness.LIFE: {
            CommissionType.NEW_BUSINESS: RateLimit(
                max_rate=0.55,
                regulation_citation="NAIC Model #582",
                notes="First year life commission cap",
            ),
            CommissionType.RENEWAL: RateLimit(
                max_rate=0.05,
                regulation_citation="NAIC Model #582",
                notes="Renewal life commission cap",
            ),
            CommissionType.OVERRIDE: RateLimit(
                max_rate=0.15,
                regulation_citation="NAIC Model #582",
            ),
            CommissionType.BONUS: RateLimit(
                max_rate=0.10,
                regulation_citation="NAIC Model #582",
            ),
        },
        LineOfBusiness.HEALTH: {
            CommissionType.NEW_BUSINESS: RateLimit(
                max_rate=0.20,
                regulation_citation="ACA Section 2718",
                notes="MLR-adjusted health commission cap",
            ),
            CommissionType.RENEWAL: RateLimit(
                max_rate=0.08,
                regulation_citation="ACA Section 2718",
            ),
            CommissionType.OVERRIDE: RateLimit(
                max_rate=0.05,
                regulation_citation="ACA Section 2718",
            ),
        },
        LineOfBusiness.PROPERTY: {
            CommissionType.NEW_BUSINESS: RateLimit(
                max_rate=0.25,
                regulation_citation="NAIC Model #785",
            ),
            CommissionType.RENEWAL: RateLimit(
                max_rate=0.15,
                regulation_citation="NAIC Model #785",
            ),
            CommissionType.CONTINGENT: RateLimit(
                max_rate=0.05,
                regulation_citation="NAIC Model #785",
                notes="Contingent/profit-sharing commission cap",
            ),
        },
        LineOfBusiness.CASUALTY: {
            CommissionType.NEW_BUSINESS: RateLimit(
                max_rate=0.20,
                regulation_citation="NAIC Model #785",
            ),
            CommissionType.RENEWAL: RateLimit(
                max_rate=0.12,
                regulation_citation="NAIC Model #785",
            ),
        },
        LineOfBusiness.ANNUITY: {
            CommissionType.NEW_BUSINESS: RateLimit(
                max_rate=0.08,
                regulation_citation="NAIC Model Annuity Reg #245",
                notes="Compliant with DOL fiduciary standard",
            ),
            CommissionType.RENEWAL: RateLimit(
                max_rate=0.03,
                regulation_citation="NAIC Model Annuity Reg #245",
            ),
        },
        LineOfBusiness.SURPLUS_LINES: {
            CommissionType.NEW_BUSINESS: RateLimit(
                max_rate=0.30,
                regulation_citation="NAIC Nonadmitted Insurance Model Act",
            ),
            CommissionType.RENEWAL: RateLimit(
                max_rate=0.20,
                regulation_citation="NAIC Nonadmitted Insurance Model Act",
            ),
        },
        LineOfBusiness.TITLE: {
            CommissionType.NEW_BUSINESS: RateLimit(
                max_rate=0.15,
                regulation_citation="RESPA Section 8",
            ),
        },
        LineOfBusiness.WORKERS_COMP: {
            CommissionType.NEW_BUSINESS: RateLimit(
                max_rate=0.10,
                regulation_citation="NAIC Model #780",
            ),
            CommissionType.RENEWAL: RateLimit(
                max_rate=0.07,
                regulation_citation="NAIC Model #780",
            ),
        },
    },
    # State-specific overrides (stricter than NAIC default)
    "NY": {
        LineOfBusiness.LIFE: {
            CommissionType.NEW_BUSINESS: RateLimit(
                max_rate=0.50,
                regulation_citation="NY Insurance Law Section 4228",
                notes="New York has stricter first-year caps",
            ),
            CommissionType.RENEWAL: RateLimit(
                max_rate=0.04,
                regulation_citation="NY Insurance Law Section 4228",
            ),
        },
        LineOfBusiness.ANNUITY: {
            CommissionType.NEW_BUSINESS: RateLimit(
                max_rate=0.06,
                regulation_citation="NY Reg 187",
                notes="NY Best Interest regulation",
            ),
        },
    },
    "CA": {
        LineOfBusiness.HEALTH: {
            CommissionType.NEW_BUSINESS: RateLimit(
                max_rate=0.10,
                regulation_citation="CA Insurance Code Section 10509.915",
                notes="California ACA marketplace commission limit",
            ),
        },
    },
    "TX": {
        LineOfBusiness.PROPERTY: {
            CommissionType.NEW_BUSINESS: RateLimit(
                max_rate=0.20,
                regulation_citation="TX Insurance Code Chapter 4005",
            ),
        },
    },
    "FL": {
        LineOfBusiness.PROPERTY: {
            CommissionType.NEW_BUSINESS: RateLimit(
                max_rate=0.20,
                regulation_citation="FL Statute 626.9541",
            ),
            CommissionType.CONTINGENT: RateLimit(
                max_rate=0.03,
                regulation_citation="FL Statute 626.9541",
                notes="Florida restricts contingent commissions on property",
            ),
        },
    },
}


class ComplianceEngine:
    """Validates commission transactions against state regulatory rate limits."""

    def __init__(
        self,
        custom_rate_limits: dict[str, dict[str, dict[str, RateLimit]]] | None = None,
    ) -> None:
        self._rate_limits = custom_rate_limits or STATE_RATE_LIMITS

    def get_rate_limit(
        self,
        state: str,
        line_of_business: str,
        commission_type: str,
        transaction_date: date | None = None,
    ) -> RateLimit | None:
        """Look up the applicable rate limit, falling back to defaults."""
        for lookup_state in (state, "__default__"):
            state_limits = self._rate_limits.get(lookup_state, {})
            lob_limits = state_limits.get(line_of_business, {})
            rate_limit = lob_limits.get(commission_type)
            if rate_limit:
                if transaction_date and rate_limit.effective_date:
                    if transaction_date < rate_limit.effective_date:
                        continue
                if transaction_date and rate_limit.expiry_date:
                    if transaction_date > rate_limit.expiry_date:
                        continue
                return rate_limit
        return None

    def check_rate_compliance(
        self,
        transaction_id: int,
        producer_id: int,
        state: str,
        line_of_business: str,
        commission_type: str,
        commission_rate: float,
        premium_amount: float,
        commission_amount: float,
        transaction_date: date | None = None,
    ) -> list[ComplianceViolation]:
        """Check a single transaction for rate compliance violations."""
        violations: list[ComplianceViolation] = []

        rate_limit = self.get_rate_limit(
            state, line_of_business, commission_type, transaction_date
        )

        if rate_limit and commission_rate > rate_limit.max_rate:
            excess_rate = commission_rate - rate_limit.max_rate
            excess_amount = premium_amount * excess_rate
            severity = self._rate_violation_severity(excess_rate, rate_limit.max_rate)
            violations.append(
                ComplianceViolation(
                    rule_name="RATE_EXCEEDS_STATE_LIMIT",
                    severity=severity,
                    transaction_id=transaction_id,
                    producer_id=producer_id,
                    description=(
                        f"Commission rate {commission_rate:.4f} exceeds "
                        f"maximum allowed rate {rate_limit.max_rate:.4f} for "
                        f"{line_of_business}/{commission_type} in {state}. "
                        f"Excess commission: ${excess_amount:.2f}. "
                        f"{rate_limit.notes}"
                    ),
                    regulation_reference=rate_limit.regulation_citation,
                    expected_value=f"<= {rate_limit.max_rate:.4f}",
                    actual_value=f"{commission_rate:.4f}",
                    variance_amount=excess_amount,
                    finding_code="CR-001",
                )
            )

        # Verify commission amount matches rate * premium
        expected_commission = premium_amount * commission_rate
        tolerance = max(0.01, premium_amount * 0.001)
        if abs(commission_amount - expected_commission) > tolerance:
            violations.append(
                ComplianceViolation(
                    rule_name="COMMISSION_AMOUNT_MISMATCH",
                    severity=FindingSeverity.MEDIUM,
                    transaction_id=transaction_id,
                    producer_id=producer_id,
                    description=(
                        f"Commission amount ${commission_amount:.2f} does not match "
                        f"rate ({commission_rate:.4f}) x premium (${premium_amount:.2f}) "
                        f"= ${expected_commission:.2f}. "
                        f"Difference: ${abs(commission_amount - expected_commission):.2f}"
                    ),
                    regulation_reference="Internal Audit Standard",
                    expected_value=f"${expected_commission:.2f}",
                    actual_value=f"${commission_amount:.2f}",
                    variance_amount=abs(commission_amount - expected_commission),
                    finding_code="CR-002",
                )
            )

        return violations

    def check_license_compliance(
        self,
        producer_id: int,
        license_state: str,
        license_expiry_date: date | None,
        transaction_state: str,
        transaction_date: date,
        lines_of_authority: str | None,
        line_of_business: str,
    ) -> list[ComplianceViolation]:
        """Check producer license compliance for a transaction."""
        violations: list[ComplianceViolation] = []

        # Check expired license
        if license_expiry_date and transaction_date > license_expiry_date:
            violations.append(
                ComplianceViolation(
                    rule_name="EXPIRED_LICENSE",
                    severity=FindingSeverity.CRITICAL,
                    transaction_id=None,
                    producer_id=producer_id,
                    description=(
                        f"Producer license expired on {license_expiry_date} but "
                        f"commission transaction recorded on {transaction_date}. "
                        f"Commissions paid to unlicensed producers violate state law."
                    ),
                    regulation_reference="State Insurance Licensing Statute",
                    expected_value=f"License valid through {transaction_date}",
                    actual_value=f"License expired {license_expiry_date}",
                    variance_amount=0.0,
                    finding_code="LIC-001",
                )
            )

        # Check jurisdiction mismatch
        if license_state != transaction_state:
            violations.append(
                ComplianceViolation(
                    rule_name="JURISDICTION_MISMATCH",
                    severity=FindingSeverity.HIGH,
                    transaction_id=None,
                    producer_id=producer_id,
                    description=(
                        f"Producer licensed in {license_state} but transaction "
                        f"originated in {transaction_state}. Producer may need "
                        f"non-resident license for {transaction_state}."
                    ),
                    regulation_reference="NAIC Producer Licensing Model Act",
                    expected_value=f"License for {transaction_state}",
                    actual_value=f"License for {license_state}",
                    variance_amount=0.0,
                    finding_code="LIC-002",
                )
            )

        # Check line of authority
        if lines_of_authority and line_of_business:
            authorities = [
                a.strip().lower() for a in lines_of_authority.split(",")
            ]
            if line_of_business.lower() not in authorities:
                violations.append(
                    ComplianceViolation(
                        rule_name="LOA_MISMATCH",
                        severity=FindingSeverity.HIGH,
                        transaction_id=None,
                        producer_id=producer_id,
                        description=(
                            f"Producer not authorized for {line_of_business}. "
                            f"Lines of authority: {lines_of_authority}. "
                            f"Selling outside authorized lines violates state law."
                        ),
                        regulation_reference="State Producer Licensing Act",
                        expected_value=f"Authority for {line_of_business}",
                        actual_value=f"Authorized for: {lines_of_authority}",
                        variance_amount=0.0,
                        finding_code="LIC-003",
                    )
                )

        return violations

    def check_chargeback_compliance(
        self,
        transaction_id: int,
        producer_id: int,
        is_chargeback: bool,
        chargeback_reason: str | None,
        original_transaction_id: int | None,
        commission_amount: float,
    ) -> list[ComplianceViolation]:
        """Validate chargeback transactions have proper documentation."""
        violations: list[ComplianceViolation] = []

        if not is_chargeback:
            return violations

        if not chargeback_reason:
            violations.append(
                ComplianceViolation(
                    rule_name="CHARGEBACK_NO_REASON",
                    severity=FindingSeverity.MEDIUM,
                    transaction_id=transaction_id,
                    producer_id=producer_id,
                    description=(
                        "Chargeback transaction lacks required reason documentation. "
                        "All chargebacks must include justification per audit standards."
                    ),
                    regulation_reference="Internal Audit Standard - Chargebacks",
                    expected_value="Chargeback reason documented",
                    actual_value="No reason provided",
                    variance_amount=abs(commission_amount),
                    finding_code="CB-001",
                )
            )

        if not original_transaction_id:
            violations.append(
                ComplianceViolation(
                    rule_name="CHARGEBACK_NO_ORIGINAL_REF",
                    severity=FindingSeverity.MEDIUM,
                    transaction_id=transaction_id,
                    producer_id=producer_id,
                    description=(
                        "Chargeback transaction lacks reference to original "
                        "transaction. Cannot verify chargeback validity."
                    ),
                    regulation_reference="Internal Audit Standard - Chargebacks",
                    expected_value="Original transaction reference",
                    actual_value="No reference",
                    variance_amount=abs(commission_amount),
                    finding_code="CB-002",
                )
            )

        return violations

    @staticmethod
    def _rate_violation_severity(excess_rate: float, max_rate: float) -> str:
        """Determine severity based on how far the rate exceeds the limit."""
        excess_pct = excess_rate / max_rate if max_rate > 0 else 1.0
        if excess_pct > 0.50:
            return FindingSeverity.CRITICAL
        if excess_pct > 0.20:
            return FindingSeverity.HIGH
        if excess_pct > 0.05:
            return FindingSeverity.MEDIUM
        return FindingSeverity.LOW
