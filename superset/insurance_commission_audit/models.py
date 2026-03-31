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
"""Insurance Commission Audit models for regulatory compliance."""

from __future__ import annotations

from flask_appbuilder import Model
from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy_utils import UUIDType

from superset.models.helpers import AuditMixinNullable
from superset.utils.backports import StrEnum


class ProducerStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"


class ProducerType(StrEnum):
    INDIVIDUAL = "individual"
    BUSINESS_ENTITY = "business_entity"


class CommissionType(StrEnum):
    NEW_BUSINESS = "new_business"
    RENEWAL = "renewal"
    OVERRIDE = "override"
    BONUS = "bonus"
    CONTINGENT = "contingent"
    SUPPLEMENTAL = "supplemental"


class LineOfBusiness(StrEnum):
    LIFE = "life"
    HEALTH = "health"
    PROPERTY = "property"
    CASUALTY = "casualty"
    ANNUITY = "annuity"
    SURPLUS_LINES = "surplus_lines"
    TITLE = "title"
    WORKERS_COMP = "workers_comp"


class AuditStatus(StrEnum):
    DRAFT = "draft"
    IN_PROGRESS = "in_progress"
    UNDER_REVIEW = "under_review"
    COMPLETED = "completed"
    SUBMITTED = "submitted"
    REJECTED = "rejected"


class FindingSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    REMEDIATED = "remediated"
    CLOSED = "closed"
    ESCALATED = "escalated"


class InsuranceProducer(AuditMixinNullable, Model):
    """Insurance producer (agent/broker) subject to commission audits."""

    __tablename__ = "insurance_producer"
    __table_args__ = (
        Index("ix_producer_npn", "national_producer_number"),
        Index("ix_producer_license", "license_number", "license_state"),
    )

    id = Column(Integer, primary_key=True)
    uuid = Column(UUIDType(binary=True), unique=True, nullable=False)

    national_producer_number = Column(String(20), unique=True, nullable=False)
    license_number = Column(String(50), nullable=False)
    license_state = Column(String(2), nullable=False)

    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    business_name = Column(String(255), nullable=True)
    producer_type = Column(String(50), default=ProducerType.INDIVIDUAL, nullable=False)
    status = Column(String(50), default=ProducerStatus.ACTIVE, nullable=False)

    tax_id_last_four = Column(String(4), nullable=True)
    email = Column(String(255), nullable=True)
    phone = Column(String(20), nullable=True)

    appointment_date = Column(Date, nullable=True)
    termination_date = Column(Date, nullable=True)
    license_expiry_date = Column(Date, nullable=True)

    lines_of_authority = Column(Text, nullable=True)
    appointing_company = Column(String(255), nullable=True)
    agency_affiliation = Column(String(255), nullable=True)

    commission_transactions = relationship(
        "CommissionTransaction",
        back_populates="producer",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        if self.producer_type == ProducerType.BUSINESS_ENTITY:
            return f"<InsuranceProducer {self.business_name} (NPN: {self.national_producer_number})>"
        return f"<InsuranceProducer {self.last_name}, {self.first_name} (NPN: {self.national_producer_number})>"

    @property
    def display_name(self) -> str:
        if self.producer_type == ProducerType.BUSINESS_ENTITY:
            return self.business_name or ""
        return f"{self.last_name}, {self.first_name}"


class CommissionTransaction(AuditMixinNullable, Model):
    """Individual commission payment record for audit tracking."""

    __tablename__ = "commission_transaction"
    __table_args__ = (
        Index("ix_commission_producer_id", "producer_id"),
        Index("ix_commission_policy_number", "policy_number"),
        Index("ix_commission_transaction_date", "transaction_date"),
        Index("ix_commission_line_of_business", "line_of_business"),
    )

    id = Column(Integer, primary_key=True)
    uuid = Column(UUIDType(binary=True), unique=True, nullable=False)

    producer_id = Column(
        Integer,
        ForeignKey("insurance_producer.id", ondelete="CASCADE"),
        nullable=False,
    )
    producer = relationship("InsuranceProducer", back_populates="commission_transactions")

    policy_number = Column(String(50), nullable=False)
    policy_holder_name = Column(String(255), nullable=True)
    policy_effective_date = Column(Date, nullable=True)
    policy_expiry_date = Column(Date, nullable=True)

    line_of_business = Column(String(50), nullable=False)
    commission_type = Column(String(50), nullable=False)
    transaction_date = Column(Date, nullable=False)

    premium_amount = Column(Float, nullable=False)
    commission_rate = Column(Float, nullable=False)
    commission_amount = Column(Float, nullable=False)
    override_amount = Column(Float, default=0.0)
    net_commission = Column(Float, nullable=False)

    carrier_name = Column(String(255), nullable=False)
    carrier_naic_code = Column(String(10), nullable=True)
    payment_reference = Column(String(100), nullable=True)
    statement_period_start = Column(Date, nullable=True)
    statement_period_end = Column(Date, nullable=True)

    is_chargeback = Column(Boolean, default=False)
    chargeback_reason = Column(Text, nullable=True)
    original_transaction_id = Column(Integer, nullable=True)

    notes = Column(Text, nullable=True)

    audit_findings = relationship(
        "AuditFinding",
        back_populates="commission_transaction",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return (
            f"<CommissionTransaction {self.policy_number} "
            f"${self.commission_amount:.2f} on {self.transaction_date}>"
        )


class CommissionAuditReport(AuditMixinNullable, Model):
    """Audit report for insurance commissioner review of producer commissions."""

    __tablename__ = "commission_audit_report"
    __table_args__ = (
        Index("ix_audit_report_status", "status"),
        Index("ix_audit_report_period", "audit_period_start", "audit_period_end"),
    )

    id = Column(Integer, primary_key=True)
    uuid = Column(UUIDType(binary=True), unique=True, nullable=False)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), default=AuditStatus.DRAFT, nullable=False)

    audit_period_start = Column(Date, nullable=False)
    audit_period_end = Column(Date, nullable=False)

    state_jurisdiction = Column(String(2), nullable=False)
    commissioner_name = Column(String(255), nullable=True)
    examiner_name = Column(String(255), nullable=True)
    examiner_title = Column(String(100), nullable=True)

    company_name = Column(String(255), nullable=False)
    company_naic_code = Column(String(10), nullable=True)

    total_producers_examined = Column(Integer, default=0)
    total_transactions_examined = Column(Integer, default=0)
    total_commission_volume = Column(Float, default=0.0)
    total_premium_volume = Column(Float, default=0.0)
    total_exceptions_found = Column(Integer, default=0)

    methodology_notes = Column(Text, nullable=True)
    scope_description = Column(Text, nullable=True)
    executive_summary = Column(Text, nullable=True)
    recommendations = Column(Text, nullable=True)

    submitted_date = Column(DateTime, nullable=True)
    completed_date = Column(DateTime, nullable=True)

    findings = relationship(
        "AuditFinding",
        back_populates="audit_report",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<CommissionAuditReport '{self.title}' ({self.status})>"


class AuditFinding(AuditMixinNullable, Model):
    """Individual finding/exception discovered during a commission audit."""

    __tablename__ = "audit_finding"
    __table_args__ = (
        Index("ix_finding_report_id", "audit_report_id"),
        Index("ix_finding_severity", "severity"),
        Index("ix_finding_status", "status"),
    )

    id = Column(Integer, primary_key=True)
    uuid = Column(UUIDType(binary=True), unique=True, nullable=False)

    audit_report_id = Column(
        Integer,
        ForeignKey("commission_audit_report.id", ondelete="CASCADE"),
        nullable=False,
    )
    audit_report = relationship("CommissionAuditReport", back_populates="findings")

    commission_transaction_id = Column(
        Integer,
        ForeignKey("commission_transaction.id", ondelete="SET NULL"),
        nullable=True,
    )
    commission_transaction = relationship(
        "CommissionTransaction", back_populates="audit_findings"
    )

    finding_code = Column(String(20), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    status = Column(String(50), default=FindingStatus.OPEN, nullable=False)

    regulation_reference = Column(String(255), nullable=True)
    expected_value = Column(String(255), nullable=True)
    actual_value = Column(String(255), nullable=True)
    variance_amount = Column(Float, nullable=True)

    remediation_plan = Column(Text, nullable=True)
    remediation_deadline = Column(Date, nullable=True)
    remediated_date = Column(Date, nullable=True)
    remediation_notes = Column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<AuditFinding [{self.finding_code}] {self.title} ({self.severity})>"
