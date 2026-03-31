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
"""Update commands for Insurance Commission Audit entities."""

from __future__ import annotations

import logging
from functools import partial
from typing import Any

from superset.commands.base import BaseCommand, UpdateMixin
from superset.commands.insurance_commission_audit.exceptions import (
    AuditFindingNotFoundError,
    AuditFindingUpdateFailedError,
    CommissionAuditReportNotFoundError,
    CommissionAuditReportUpdateFailedError,
    CommissionTransactionNotFoundError,
    CommissionTransactionUpdateFailedError,
    InsuranceProducerNotFoundError,
    InsuranceProducerUpdateFailedError,
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


class UpdateInsuranceProducerCommand(UpdateMixin, BaseCommand):
    def __init__(self, model_id: int, data: dict[str, Any]) -> None:
        self._model_id = model_id
        self._properties = data.copy()
        self._model: InsuranceProducer | None = None

    @transaction(on_error=partial(on_error, reraise=InsuranceProducerUpdateFailedError))
    def run(self) -> InsuranceProducer:
        self.validate()
        assert self._model is not None
        return InsuranceProducerDAO.update(self._model, attributes=self._properties)

    def validate(self) -> None:
        self._model = InsuranceProducerDAO.find_by_id(self._model_id)
        if not self._model:
            raise InsuranceProducerNotFoundError()


class UpdateCommissionTransactionCommand(UpdateMixin, BaseCommand):
    def __init__(self, model_id: int, data: dict[str, Any]) -> None:
        self._model_id = model_id
        self._properties = data.copy()
        self._model: CommissionTransaction | None = None

    @transaction(
        on_error=partial(on_error, reraise=CommissionTransactionUpdateFailedError)
    )
    def run(self) -> CommissionTransaction:
        self.validate()
        assert self._model is not None
        return CommissionTransactionDAO.update(
            self._model, attributes=self._properties
        )

    def validate(self) -> None:
        self._model = CommissionTransactionDAO.find_by_id(self._model_id)
        if not self._model:
            raise CommissionTransactionNotFoundError()


class UpdateCommissionAuditReportCommand(UpdateMixin, BaseCommand):
    def __init__(self, model_id: int, data: dict[str, Any]) -> None:
        self._model_id = model_id
        self._properties = data.copy()
        self._model: CommissionAuditReport | None = None

    @transaction(
        on_error=partial(on_error, reraise=CommissionAuditReportUpdateFailedError)
    )
    def run(self) -> CommissionAuditReport:
        self.validate()
        assert self._model is not None
        return CommissionAuditReportDAO.update(
            self._model, attributes=self._properties
        )

    def validate(self) -> None:
        self._model = CommissionAuditReportDAO.find_by_id(self._model_id)
        if not self._model:
            raise CommissionAuditReportNotFoundError()


class UpdateAuditFindingCommand(UpdateMixin, BaseCommand):
    def __init__(self, model_id: int, data: dict[str, Any]) -> None:
        self._model_id = model_id
        self._properties = data.copy()
        self._model: AuditFinding | None = None

    @transaction(on_error=partial(on_error, reraise=AuditFindingUpdateFailedError))
    def run(self) -> AuditFinding:
        self.validate()
        assert self._model is not None
        return AuditFindingDAO.update(self._model, attributes=self._properties)

    def validate(self) -> None:
        self._model = AuditFindingDAO.find_by_id(self._model_id)
        if not self._model:
            raise AuditFindingNotFoundError()
