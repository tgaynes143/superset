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
"""Filters for Insurance Commission Audit API queries."""

from __future__ import annotations

from typing import Any

from flask_babel import lazy_gettext as _
from sqlalchemy import or_
from sqlalchemy.orm.query import Query

from superset.insurance_commission_audit.models import (
    AuditFinding,
    CommissionAuditReport,
    CommissionTransaction,
    InsuranceProducer,
)
from superset.views.base import BaseFilter


class ProducerAllTextFilter(BaseFilter):
    name = _("All Text")
    arg_name = "producer_all_text"

    def apply(self, query: Query, value: Any) -> Query:
        if not value:
            return query
        ilike_value = f"%{value}%"
        return query.filter(
            or_(
                InsuranceProducer.first_name.ilike(ilike_value),
                InsuranceProducer.last_name.ilike(ilike_value),
                InsuranceProducer.business_name.ilike(ilike_value),
                InsuranceProducer.national_producer_number.ilike(ilike_value),
                InsuranceProducer.license_number.ilike(ilike_value),
                InsuranceProducer.appointing_company.ilike(ilike_value),
            )
        )


class CommissionTransactionAllTextFilter(BaseFilter):
    name = _("All Text")
    arg_name = "commission_all_text"

    def apply(self, query: Query, value: Any) -> Query:
        if not value:
            return query
        ilike_value = f"%{value}%"
        return query.filter(
            or_(
                CommissionTransaction.policy_number.ilike(ilike_value),
                CommissionTransaction.policy_holder_name.ilike(ilike_value),
                CommissionTransaction.carrier_name.ilike(ilike_value),
                CommissionTransaction.payment_reference.ilike(ilike_value),
            )
        )


class AuditReportAllTextFilter(BaseFilter):
    name = _("All Text")
    arg_name = "audit_report_all_text"

    def apply(self, query: Query, value: Any) -> Query:
        if not value:
            return query
        ilike_value = f"%{value}%"
        return query.filter(
            or_(
                CommissionAuditReport.title.ilike(ilike_value),
                CommissionAuditReport.description.ilike(ilike_value),
                CommissionAuditReport.company_name.ilike(ilike_value),
                CommissionAuditReport.examiner_name.ilike(ilike_value),
            )
        )


class AuditFindingAllTextFilter(BaseFilter):
    name = _("All Text")
    arg_name = "finding_all_text"

    def apply(self, query: Query, value: Any) -> Query:
        if not value:
            return query
        ilike_value = f"%{value}%"
        return query.filter(
            or_(
                AuditFinding.title.ilike(ilike_value),
                AuditFinding.description.ilike(ilike_value),
                AuditFinding.finding_code.ilike(ilike_value),
                AuditFinding.regulation_reference.ilike(ilike_value),
            )
        )
