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
"""Create commands for Insurance Commission Audit entities."""

from __future__ import annotations

import logging
import uuid
from functools import partial
from typing import Any

from marshmallow import ValidationError

from superset.commands.base import BaseCommand, CreateMixin
from superset.commands.insurance_commission_audit.exceptions import (
    AuditFindingCreateFailedError,
    AuditFindingInvalidError,
    CommissionAuditReportCreateFailedError,
    CommissionAuditReportInvalidError,
    CommissionTransactionCreateFailedError,
    CommissionTransactionInvalidError,
    InsuranceProducerCreateFailedError,
    InsuranceProducerInvalidError,
    InsuranceProducerNPNUniquenessError,
)
from superset.daos.insurance_commission_audit import (
    AuditFindingDAO,
    CommissionAuditReportDAO,
    CommissionTransactionDAO,
    InsuranceProducerDAO,
)
from superset.insurance_commission_audit.models import (
    AuditFinding,
    CommissionAuditReport,
    CommissionTransaction,
    InsuranceProducer,
)
from superset.utils.decorators import on_error, transaction

logger = logging.getLogger(__name__)


class CreateInsuranceProducerCommand(CreateMixin, BaseCommand):
    def __init__(self, data: dict[str, Any]) -> None:
        self._properties = data.copy()

    @transaction(on_error=partial(on_error, reraise=InsuranceProducerCreateFailedError))
    def run(self) -> InsuranceProducer:
        self.validate()
        self._properties["uuid"] = uuid.uuid4()
        return InsuranceProducerDAO.create(attributes=self._properties)

    def validate(self) -> None:
        exceptions: list[ValidationError] = []

        npn = self._properties.get("national_producer_number")
        if npn and InsuranceProducerDAO.find_by_npn(npn):
            exceptions.append(InsuranceProducerNPNUniquenessError())

        if exceptions:
            raise InsuranceProducerInvalidError(exceptions=exceptions)


class CreateCommissionTransactionCommand(CreateMixin, BaseCommand):
    def __init__(self, data: dict[str, Any]) -> None:
        self._properties = data.copy()

    @transaction(
        on_error=partial(on_error, reraise=CommissionTransactionCreateFailedError)
    )
    def run(self) -> CommissionTransaction:
        self.validate()
        self._properties["uuid"] = uuid.uuid4()
        return CommissionTransactionDAO.create(attributes=self._properties)

    def validate(self) -> None:
        exceptions: list[ValidationError] = []

        producer_id = self._properties.get("producer_id")
        if producer_id:
            producer = InsuranceProducerDAO.find_by_id(producer_id)
            if not producer:
                exceptions.append(
                    ValidationError("Referenced producer does not exist.")
                )

        if exceptions:
            raise CommissionTransactionInvalidError(exceptions=exceptions)


class CreateCommissionAuditReportCommand(CreateMixin, BaseCommand):
    def __init__(self, data: dict[str, Any]) -> None:
        self._properties = data.copy()

    @transaction(
        on_error=partial(on_error, reraise=CommissionAuditReportCreateFailedError)
    )
    def run(self) -> CommissionAuditReport:
        self.validate()
        self._properties["uuid"] = uuid.uuid4()
        return CommissionAuditReportDAO.create(attributes=self._properties)

    def validate(self) -> None:
        exceptions: list[ValidationError] = []
        if exceptions:
            raise CommissionAuditReportInvalidError(exceptions=exceptions)


class CreateAuditFindingCommand(CreateMixin, BaseCommand):
    def __init__(self, data: dict[str, Any]) -> None:
        self._properties = data.copy()

    @transaction(on_error=partial(on_error, reraise=AuditFindingCreateFailedError))
    def run(self) -> AuditFinding:
        self.validate()
        self._properties["uuid"] = uuid.uuid4()
        return AuditFindingDAO.create(attributes=self._properties)

    def validate(self) -> None:
        exceptions: list[ValidationError] = []

        report_id = self._properties.get("audit_report_id")
        if report_id:
            report = CommissionAuditReportDAO.find_by_id(report_id)
            if not report:
                exceptions.append(
                    ValidationError("Referenced audit report does not exist.")
                )

        tx_id = self._properties.get("commission_transaction_id")
        if tx_id:
            tx = CommissionTransactionDAO.find_by_id(tx_id)
            if not tx:
                exceptions.append(
                    ValidationError(
                        "Referenced commission transaction does not exist."
                    )
                )

        if exceptions:
            raise AuditFindingInvalidError(exceptions=exceptions)
