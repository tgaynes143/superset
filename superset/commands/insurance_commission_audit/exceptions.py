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
"""Exceptions for Insurance Commission Audit commands."""

from __future__ import annotations

from flask_babel import lazy_gettext as _

from superset.commands.exceptions import (
    CommandException,
    CommandInvalidError,
    CreateFailedError,
    DeleteFailedError,
    ForbiddenError,
    ObjectNotFoundError,
    UpdateFailedError,
)


# --- Producer Exceptions ---


class InsuranceProducerNotFoundError(ObjectNotFoundError):
    def __init__(self) -> None:
        super().__init__("InsuranceProducer", _("Insurance producer not found."))


class InsuranceProducerInvalidError(CommandInvalidError):
    message = _("Insurance producer parameters are invalid.")


class InsuranceProducerCreateFailedError(CreateFailedError):
    message = _("Insurance producer could not be created.")


class InsuranceProducerUpdateFailedError(UpdateFailedError):
    message = _("Insurance producer could not be updated.")


class InsuranceProducerDeleteFailedError(DeleteFailedError):
    message = _("Insurance producer could not be deleted.")


class InsuranceProducerNPNUniquenessError(CommandException):
    message = _("A producer with this NPN already exists.")
    status = 422


# --- Commission Transaction Exceptions ---


class CommissionTransactionNotFoundError(ObjectNotFoundError):
    def __init__(self) -> None:
        super().__init__(
            "CommissionTransaction", _("Commission transaction not found.")
        )


class CommissionTransactionInvalidError(CommandInvalidError):
    message = _("Commission transaction parameters are invalid.")


class CommissionTransactionCreateFailedError(CreateFailedError):
    message = _("Commission transaction could not be created.")


class CommissionTransactionUpdateFailedError(UpdateFailedError):
    message = _("Commission transaction could not be updated.")


class CommissionTransactionDeleteFailedError(DeleteFailedError):
    message = _("Commission transaction could not be deleted.")


# --- Audit Report Exceptions ---


class CommissionAuditReportNotFoundError(ObjectNotFoundError):
    def __init__(self) -> None:
        super().__init__(
            "CommissionAuditReport", _("Commission audit report not found.")
        )


class CommissionAuditReportInvalidError(CommandInvalidError):
    message = _("Commission audit report parameters are invalid.")


class CommissionAuditReportCreateFailedError(CreateFailedError):
    message = _("Commission audit report could not be created.")


class CommissionAuditReportUpdateFailedError(UpdateFailedError):
    message = _("Commission audit report could not be updated.")


class CommissionAuditReportDeleteFailedError(DeleteFailedError):
    message = _("Commission audit report could not be deleted.")


# --- Audit Finding Exceptions ---


class AuditFindingNotFoundError(ObjectNotFoundError):
    def __init__(self) -> None:
        super().__init__("AuditFinding", _("Audit finding not found."))


class AuditFindingInvalidError(CommandInvalidError):
    message = _("Audit finding parameters are invalid.")


class AuditFindingCreateFailedError(CreateFailedError):
    message = _("Audit finding could not be created.")


class AuditFindingUpdateFailedError(UpdateFailedError):
    message = _("Audit finding could not be updated.")


class AuditFindingDeleteFailedError(DeleteFailedError):
    message = _("Audit finding could not be deleted.")
