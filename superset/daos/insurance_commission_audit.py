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
"""DAOs for Insurance Commission Audit models."""

from __future__ import annotations

import logging
from datetime import date

from sqlalchemy import func

from superset.daos.base import BaseDAO
from superset.extensions import db
from superset.insurance_commission_audit.models import (
    AuditFinding,
    AuditStatus,
    CommissionAuditReport,
    CommissionTransaction,
    FindingSeverity,
    InsuranceProducer,
)

logger = logging.getLogger(__name__)


class InsuranceProducerDAO(BaseDAO[InsuranceProducer]):
    @staticmethod
    def find_by_npn(npn: str) -> InsuranceProducer | None:
        return (
            db.session.query(InsuranceProducer)
            .filter(InsuranceProducer.national_producer_number == npn)
            .one_or_none()
        )

    @staticmethod
    def find_by_license(
        license_number: str, license_state: str
    ) -> InsuranceProducer | None:
        return (
            db.session.query(InsuranceProducer)
            .filter(
                InsuranceProducer.license_number == license_number,
                InsuranceProducer.license_state == license_state,
            )
            .one_or_none()
        )

    @staticmethod
    def find_by_state(state: str) -> list[InsuranceProducer]:
        return (
            db.session.query(InsuranceProducer)
            .filter(InsuranceProducer.license_state == state)
            .all()
        )


class CommissionTransactionDAO(BaseDAO[CommissionTransaction]):
    @staticmethod
    def find_by_producer(producer_id: int) -> list[CommissionTransaction]:
        return (
            db.session.query(CommissionTransaction)
            .filter(CommissionTransaction.producer_id == producer_id)
            .all()
        )

    @staticmethod
    def find_by_policy(policy_number: str) -> list[CommissionTransaction]:
        return (
            db.session.query(CommissionTransaction)
            .filter(CommissionTransaction.policy_number == policy_number)
            .all()
        )

    @staticmethod
    def find_by_date_range(
        start_date: date, end_date: date
    ) -> list[CommissionTransaction]:
        return (
            db.session.query(CommissionTransaction)
            .filter(
                CommissionTransaction.transaction_date >= start_date,
                CommissionTransaction.transaction_date <= end_date,
            )
            .all()
        )

    @staticmethod
    def get_producer_commission_summary(
        producer_id: int,
        start_date: date | None = None,
        end_date: date | None = None,
    ) -> dict:
        query = db.session.query(
            func.count(CommissionTransaction.id).label("total_transactions"),
            func.sum(CommissionTransaction.premium_amount).label("total_premium"),
            func.sum(CommissionTransaction.commission_amount).label(
                "total_commission"
            ),
            func.sum(CommissionTransaction.net_commission).label("total_net"),
            func.avg(CommissionTransaction.commission_rate).label("avg_rate"),
        ).filter(CommissionTransaction.producer_id == producer_id)

        if start_date:
            query = query.filter(
                CommissionTransaction.transaction_date >= start_date
            )
        if end_date:
            query = query.filter(
                CommissionTransaction.transaction_date <= end_date
            )

        row = query.one()
        return {
            "total_transactions": row.total_transactions or 0,
            "total_premium": float(row.total_premium or 0),
            "total_commission": float(row.total_commission or 0),
            "total_net_commission": float(row.total_net or 0),
            "average_commission_rate": float(row.avg_rate or 0),
        }


class CommissionAuditReportDAO(BaseDAO[CommissionAuditReport]):
    @staticmethod
    def find_by_state(state: str) -> list[CommissionAuditReport]:
        return (
            db.session.query(CommissionAuditReport)
            .filter(CommissionAuditReport.state_jurisdiction == state)
            .all()
        )

    @staticmethod
    def find_by_status(status: str) -> list[CommissionAuditReport]:
        return (
            db.session.query(CommissionAuditReport)
            .filter(CommissionAuditReport.status == status)
            .all()
        )

    @staticmethod
    def get_audit_statistics(audit_report_id: int) -> dict:
        finding_stats = (
            db.session.query(
                AuditFinding.severity,
                func.count(AuditFinding.id).label("count"),
            )
            .filter(AuditFinding.audit_report_id == audit_report_id)
            .group_by(AuditFinding.severity)
            .all()
        )

        total_variance = (
            db.session.query(
                func.sum(AuditFinding.variance_amount),
            )
            .filter(AuditFinding.audit_report_id == audit_report_id)
            .scalar()
        )

        severity_counts = {row.severity: row.count for row in finding_stats}
        return {
            "findings_by_severity": severity_counts,
            "total_findings": sum(severity_counts.values()),
            "total_variance_amount": float(total_variance or 0),
        }


class AuditFindingDAO(BaseDAO[AuditFinding]):
    @staticmethod
    def find_by_audit_report(audit_report_id: int) -> list[AuditFinding]:
        return (
            db.session.query(AuditFinding)
            .filter(AuditFinding.audit_report_id == audit_report_id)
            .all()
        )

    @staticmethod
    def find_by_severity(severity: str) -> list[AuditFinding]:
        return (
            db.session.query(AuditFinding)
            .filter(AuditFinding.severity == severity)
            .all()
        )

    @staticmethod
    def find_open_findings(audit_report_id: int) -> list[AuditFinding]:
        return (
            db.session.query(AuditFinding)
            .filter(
                AuditFinding.audit_report_id == audit_report_id,
                AuditFinding.status == "open",
            )
            .all()
        )
