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
"""Delete commands for Insurance Commission Audit entities."""

from __future__ import annotations

import logging
from functools import partial

from superset.commands.base import BaseCommand
from superset.commands.insurance_commission_audit.exceptions import (
    AuditFindingDeleteFailedError,
    AuditFindingNotFoundError,
    CommissionAuditReportDeleteFailedError,
    CommissionAuditReportNotFoundError,
    CommissionTransactionDeleteFailedError,
    CommissionTransactionNotFoundError,
    InsuranceProducerDeleteFailedError,
    InsuranceProducerNotFoundError,
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


class DeleteInsuranceProducerCommand(BaseCommand):
    def __init__(self, model_ids: list[int]) -> None:
        self._model_ids = model_ids
        self._models: list[InsuranceProducer] = []

    @transaction(on_error=partial(on_error, reraise=InsuranceProducerDeleteFailedError))
    def run(self) -> None:
        self.validate()
        for model in self._models:
            InsuranceProducerDAO.delete(model)

    def validate(self) -> None:
        self._models = []
        for model_id in self._model_ids:
            model = InsuranceProducerDAO.find_by_id(model_id)
            if not model:
                raise InsuranceProducerNotFoundError()
            self._models.append(model)


class DeleteCommissionTransactionCommand(BaseCommand):
    def __init__(self, model_ids: list[int]) -> None:
        self._model_ids = model_ids
        self._models: list[CommissionTransaction] = []

    @transaction(
        on_error=partial(on_error, reraise=CommissionTransactionDeleteFailedError)
    )
    def run(self) -> None:
        self.validate()
        for model in self._models:
            CommissionTransactionDAO.delete(model)

    def validate(self) -> None:
        self._models = []
        for model_id in self._model_ids:
            model = CommissionTransactionDAO.find_by_id(model_id)
            if not model:
                raise CommissionTransactionNotFoundError()
            self._models.append(model)


class DeleteCommissionAuditReportCommand(BaseCommand):
    def __init__(self, model_ids: list[int]) -> None:
        self._model_ids = model_ids
        self._models: list[CommissionAuditReport] = []

    @transaction(
        on_error=partial(on_error, reraise=CommissionAuditReportDeleteFailedError)
    )
    def run(self) -> None:
        self.validate()
        for model in self._models:
            CommissionAuditReportDAO.delete(model)

    def validate(self) -> None:
        self._models = []
        for model_id in self._model_ids:
            model = CommissionAuditReportDAO.find_by_id(model_id)
            if not model:
                raise CommissionAuditReportNotFoundError()
            self._models.append(model)


class DeleteAuditFindingCommand(BaseCommand):
    def __init__(self, model_ids: list[int]) -> None:
        self._model_ids = model_ids
        self._models: list[AuditFinding] = []

    @transaction(on_error=partial(on_error, reraise=AuditFindingDeleteFailedError))
    def run(self) -> None:
        self.validate()
        for model in self._models:
            AuditFindingDAO.delete(model)

    def validate(self) -> None:
        self._models = []
        for model_id in self._model_ids:
            model = AuditFindingDAO.find_by_id(model_id)
            if not model:
                raise AuditFindingNotFoundError()
            self._models.append(model)
