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
"""REST API endpoints for Insurance Commission Audit."""

from __future__ import annotations

import logging
from typing import Any

from flask import request, Response
from flask_appbuilder.api import expose, permission_name, protect, rison, safe
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_babel import ngettext
from marshmallow import ValidationError

from superset.commands.insurance_commission_audit.create import (
    CreateAuditFindingCommand,
    CreateCommissionAuditReportCommand,
    CreateCommissionTransactionCommand,
    CreateInsuranceProducerCommand,
)
from superset.commands.insurance_commission_audit.delete import (
    DeleteAuditFindingCommand,
    DeleteCommissionAuditReportCommand,
    DeleteCommissionTransactionCommand,
    DeleteInsuranceProducerCommand,
)
from superset.commands.insurance_commission_audit.exceptions import (
    AuditFindingCreateFailedError,
    AuditFindingDeleteFailedError,
    AuditFindingInvalidError,
    AuditFindingNotFoundError,
    AuditFindingUpdateFailedError,
    CommissionAuditReportCreateFailedError,
    CommissionAuditReportDeleteFailedError,
    CommissionAuditReportInvalidError,
    CommissionAuditReportNotFoundError,
    CommissionAuditReportUpdateFailedError,
    CommissionTransactionCreateFailedError,
    CommissionTransactionDeleteFailedError,
    CommissionTransactionInvalidError,
    CommissionTransactionNotFoundError,
    CommissionTransactionUpdateFailedError,
    InsuranceProducerCreateFailedError,
    InsuranceProducerDeleteFailedError,
    InsuranceProducerInvalidError,
    InsuranceProducerNotFoundError,
    InsuranceProducerUpdateFailedError,
)
from superset.commands.insurance_commission_audit.update import (
    UpdateAuditFindingCommand,
    UpdateCommissionAuditReportCommand,
    UpdateCommissionTransactionCommand,
    UpdateInsuranceProducerCommand,
)
from superset.constants import MODEL_API_RW_METHOD_PERMISSION_MAP, RouteMethod
from superset.daos.insurance_commission_audit import (
    CommissionAuditReportDAO,
    CommissionTransactionDAO,
)
from superset.extensions import event_logger
from superset.insurance_commission_audit.filters import (
    AuditFindingAllTextFilter,
    AuditReportAllTextFilter,
    CommissionTransactionAllTextFilter,
    ProducerAllTextFilter,
)
from superset.insurance_commission_audit.models import (
    AuditFinding,
    CommissionAuditReport,
    CommissionTransaction,
    InsuranceProducer,
)
from superset.insurance_commission_audit.schemas import (
    audit_finding_openapi_spec,
    audit_report_openapi_spec,
    AuditFindingPostSchema,
    AuditFindingPutSchema,
    commission_transaction_openapi_spec,
    CommissionAuditReportPostSchema,
    CommissionAuditReportPutSchema,
    CommissionTransactionPostSchema,
    CommissionTransactionPutSchema,
    get_delete_ids_schema,
    InsuranceProducerPostSchema,
    InsuranceProducerPutSchema,
    producer_openapi_spec,
)
from superset.views.base_api import (
    BaseSupersetModelRestApi,
    requires_json,
    statsd_metrics,
)

logger = logging.getLogger(__name__)


class InsuranceProducerRestApi(BaseSupersetModelRestApi):
    datamodel = SQLAInterface(InsuranceProducer)

    include_route_methods = RouteMethod.REST_MODEL_VIEW_CRUD_SET | {
        RouteMethod.RELATED,
        "bulk_delete",
    }
    class_permission_name = "InsuranceProducer"
    method_permission_name = MODEL_API_RW_METHOD_PERMISSION_MAP
    resource_name = "insurance_producer"
    allow_browser_login = True

    openapi_spec_tag = "Insurance Producers"
    openapi_spec_methods = producer_openapi_spec

    list_columns = [
        "id",
        "uuid",
        "national_producer_number",
        "license_number",
        "license_state",
        "first_name",
        "last_name",
        "business_name",
        "producer_type",
        "status",
        "email",
        "appointment_date",
        "license_expiry_date",
        "appointing_company",
        "agency_affiliation",
        "changed_on_delta_humanized",
    ]

    show_columns = list_columns + [
        "tax_id_last_four",
        "phone",
        "termination_date",
        "lines_of_authority",
        "created_on",
        "changed_on",
    ]

    order_columns = [
        "id",
        "national_producer_number",
        "last_name",
        "business_name",
        "license_state",
        "status",
        "appointment_date",
        "changed_on_delta_humanized",
    ]

    search_columns = [
        "national_producer_number",
        "license_number",
        "license_state",
        "first_name",
        "last_name",
        "business_name",
        "producer_type",
        "status",
        "appointing_company",
    ]

    search_filters = {"national_producer_number": [ProducerAllTextFilter]}

    add_model_schema = InsuranceProducerPostSchema()
    edit_model_schema = InsuranceProducerPutSchema()

    @expose("/", methods=("POST",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.post",
        log_to_statsd=False,
    )
    @requires_json
    def post(self) -> Response:
        """Create a new insurance producer.
        ---
        post:
          summary: Create an insurance producer
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/InsuranceProducerPostSchema'
          responses:
            201:
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      id:
                        type: number
                      result:
                        $ref: '#/components/schemas/InsuranceProducerPostSchema'
            400:
              $ref: '#/components/responses/400'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            item = self.add_model_schema.load(request.json)
        except ValidationError as error:
            return self.response_400(message=error.messages)
        try:
            new_model = CreateInsuranceProducerCommand(item).run()
            return self.response(201, id=new_model.id, result=item)
        except InsuranceProducerInvalidError as ex:
            return self.response_422(message=ex.normalized_messages())
        except InsuranceProducerCreateFailedError as ex:
            logger.error(
                "Error creating insurance producer: %s",
                str(ex),
                exc_info=True,
            )
            return self.response_422(message=str(ex))

    @expose("/<int:pk>", methods=("PUT",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.put",
        log_to_statsd=False,
    )
    @requires_json
    def put(self, pk: int) -> Response:
        """Update an insurance producer.
        ---
        put:
          summary: Update an insurance producer
          parameters:
            - in: path
              name: pk
              schema:
                type: integer
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/InsuranceProducerPutSchema'
          responses:
            200:
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      id:
                        type: number
                      result:
                        $ref: '#/components/schemas/InsuranceProducerPutSchema'
            400:
              $ref: '#/components/responses/400'
            404:
              $ref: '#/components/responses/404'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            item = self.edit_model_schema.load(request.json)
        except ValidationError as error:
            return self.response_400(message=error.messages)
        try:
            UpdateInsuranceProducerCommand(pk, item).run()
            return self.response(200, id=pk, result=item)
        except InsuranceProducerNotFoundError:
            return self.response_404()
        except InsuranceProducerUpdateFailedError as ex:
            logger.error(
                "Error updating insurance producer %s: %s",
                pk,
                str(ex),
                exc_info=True,
            )
            return self.response_422(message=str(ex))

    @expose("/<int:pk>", methods=("DELETE",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.delete",
        log_to_statsd=False,
    )
    def delete(self, pk: int) -> Response:
        """Delete an insurance producer.
        ---
        delete:
          summary: Delete an insurance producer
          parameters:
            - in: path
              name: pk
              schema:
                type: integer
          responses:
            200:
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      message:
                        type: string
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            DeleteInsuranceProducerCommand([pk]).run()
            return self.response(200, message="OK")
        except InsuranceProducerNotFoundError:
            return self.response_404()
        except InsuranceProducerDeleteFailedError as ex:
            logger.error(
                "Error deleting insurance producer %s: %s",
                pk,
                str(ex),
                exc_info=True,
            )
            return self.response_422(message=str(ex))

    @expose("/", methods=("DELETE",))
    @protect()
    @safe
    @statsd_metrics
    @rison(get_delete_ids_schema)
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.bulk_delete",
        log_to_statsd=False,
    )
    def bulk_delete(self, **kwargs: Any) -> Response:
        """Bulk delete insurance producers.
        ---
        delete:
          summary: Bulk delete insurance producers
          parameters:
            - in: query
              name: q
              content:
                application/json:
                  schema:
                    $ref: '#/components/schemas/get_delete_ids_schema'
          responses:
            200:
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      message:
                        type: string
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        item_ids = kwargs["rison"]
        try:
            DeleteInsuranceProducerCommand(item_ids).run()
            return self.response(
                200,
                message=ngettext(
                    "Deleted %(num)d producer",
                    "Deleted %(num)d producers",
                    num=len(item_ids),
                ),
            )
        except InsuranceProducerNotFoundError:
            return self.response_404()
        except InsuranceProducerDeleteFailedError as ex:
            return self.response_422(message=str(ex))


class CommissionTransactionRestApi(BaseSupersetModelRestApi):
    datamodel = SQLAInterface(CommissionTransaction)

    include_route_methods = RouteMethod.REST_MODEL_VIEW_CRUD_SET | {
        RouteMethod.RELATED,
        "bulk_delete",
        "producer_summary",
    }
    class_permission_name = "CommissionTransaction"
    method_permission_name = MODEL_API_RW_METHOD_PERMISSION_MAP
    resource_name = "commission_transaction"
    allow_browser_login = True

    openapi_spec_tag = "Commission Transactions"
    openapi_spec_methods = commission_transaction_openapi_spec

    list_columns = [
        "id",
        "uuid",
        "producer_id",
        "policy_number",
        "policy_holder_name",
        "line_of_business",
        "commission_type",
        "transaction_date",
        "premium_amount",
        "commission_rate",
        "commission_amount",
        "net_commission",
        "carrier_name",
        "is_chargeback",
        "changed_on_delta_humanized",
    ]

    show_columns = list_columns + [
        "policy_effective_date",
        "policy_expiry_date",
        "override_amount",
        "carrier_naic_code",
        "payment_reference",
        "statement_period_start",
        "statement_period_end",
        "chargeback_reason",
        "original_transaction_id",
        "notes",
        "created_on",
        "changed_on",
    ]

    order_columns = [
        "id",
        "transaction_date",
        "commission_amount",
        "net_commission",
        "premium_amount",
        "policy_number",
        "carrier_name",
    ]

    search_columns = [
        "policy_number",
        "line_of_business",
        "commission_type",
        "carrier_name",
        "is_chargeback",
        "producer_id",
    ]

    search_filters = {"policy_number": [CommissionTransactionAllTextFilter]}

    add_model_schema = CommissionTransactionPostSchema()
    edit_model_schema = CommissionTransactionPutSchema()

    @expose("/", methods=("POST",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.post",
        log_to_statsd=False,
    )
    @requires_json
    def post(self) -> Response:
        """Create a new commission transaction.
        ---
        post:
          summary: Create a commission transaction
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/CommissionTransactionPostSchema'
          responses:
            201:
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      id:
                        type: number
                      result:
                        $ref: '#/components/schemas/CommissionTransactionPostSchema'
            400:
              $ref: '#/components/responses/400'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            item = self.add_model_schema.load(request.json)
        except ValidationError as error:
            return self.response_400(message=error.messages)
        try:
            new_model = CreateCommissionTransactionCommand(item).run()
            return self.response(201, id=new_model.id, result=item)
        except CommissionTransactionInvalidError as ex:
            return self.response_422(message=ex.normalized_messages())
        except CommissionTransactionCreateFailedError as ex:
            logger.error(
                "Error creating commission transaction: %s",
                str(ex),
                exc_info=True,
            )
            return self.response_422(message=str(ex))

    @expose("/<int:pk>", methods=("PUT",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.put",
        log_to_statsd=False,
    )
    @requires_json
    def put(self, pk: int) -> Response:
        """Update a commission transaction.
        ---
        put:
          summary: Update a commission transaction
          parameters:
            - in: path
              name: pk
              schema:
                type: integer
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/CommissionTransactionPutSchema'
          responses:
            200:
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      id:
                        type: number
                      result:
                        $ref: '#/components/schemas/CommissionTransactionPutSchema'
            400:
              $ref: '#/components/responses/400'
            404:
              $ref: '#/components/responses/404'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            item = self.edit_model_schema.load(request.json)
        except ValidationError as error:
            return self.response_400(message=error.messages)
        try:
            UpdateCommissionTransactionCommand(pk, item).run()
            return self.response(200, id=pk, result=item)
        except CommissionTransactionNotFoundError:
            return self.response_404()
        except CommissionTransactionUpdateFailedError as ex:
            logger.error(
                "Error updating commission transaction %s: %s",
                pk,
                str(ex),
                exc_info=True,
            )
            return self.response_422(message=str(ex))

    @expose("/<int:pk>", methods=("DELETE",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.delete",
        log_to_statsd=False,
    )
    def delete(self, pk: int) -> Response:
        """Delete a commission transaction.
        ---
        delete:
          summary: Delete a commission transaction
          parameters:
            - in: path
              name: pk
              schema:
                type: integer
          responses:
            200:
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      message:
                        type: string
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            DeleteCommissionTransactionCommand([pk]).run()
            return self.response(200, message="OK")
        except CommissionTransactionNotFoundError:
            return self.response_404()
        except CommissionTransactionDeleteFailedError as ex:
            logger.error(
                "Error deleting commission transaction %s: %s",
                pk,
                str(ex),
                exc_info=True,
            )
            return self.response_422(message=str(ex))

    @expose("/", methods=("DELETE",))
    @protect()
    @safe
    @statsd_metrics
    @rison(get_delete_ids_schema)
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.bulk_delete",
        log_to_statsd=False,
    )
    def bulk_delete(self, **kwargs: Any) -> Response:
        """Bulk delete commission transactions."""
        item_ids = kwargs["rison"]
        try:
            DeleteCommissionTransactionCommand(item_ids).run()
            return self.response(
                200,
                message=ngettext(
                    "Deleted %(num)d transaction",
                    "Deleted %(num)d transactions",
                    num=len(item_ids),
                ),
            )
        except CommissionTransactionNotFoundError:
            return self.response_404()
        except CommissionTransactionDeleteFailedError as ex:
            return self.response_422(message=str(ex))

    @expose("/producer_summary/<int:producer_id>", methods=("GET",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}"
        ".producer_summary",
        log_to_statsd=False,
    )
    def producer_summary(self, producer_id: int) -> Response:
        """Get commission summary for a specific producer.
        ---
        get:
          summary: Get producer commission summary
          parameters:
            - in: path
              name: producer_id
              schema:
                type: integer
          responses:
            200:
              content:
                application/json:
                  schema:
                    type: object
            500:
              $ref: '#/components/responses/500'
        """
        try:
            summary = CommissionTransactionDAO.get_producer_commission_summary(
                producer_id
            )
            return self.response(200, result=summary)
        except Exception as ex:
            logger.error(
                "Error getting producer summary: %s", str(ex), exc_info=True
            )
            return self.response_422(message=str(ex))


class CommissionAuditReportRestApi(BaseSupersetModelRestApi):
    datamodel = SQLAInterface(CommissionAuditReport)

    include_route_methods = RouteMethod.REST_MODEL_VIEW_CRUD_SET | {
        RouteMethod.RELATED,
        "bulk_delete",
        "audit_statistics",
    }
    class_permission_name = "CommissionAuditReport"
    method_permission_name = MODEL_API_RW_METHOD_PERMISSION_MAP
    resource_name = "commission_audit_report"
    allow_browser_login = True

    openapi_spec_tag = "Commission Audit Reports"
    openapi_spec_methods = audit_report_openapi_spec

    list_columns = [
        "id",
        "uuid",
        "title",
        "status",
        "audit_period_start",
        "audit_period_end",
        "state_jurisdiction",
        "company_name",
        "total_producers_examined",
        "total_transactions_examined",
        "total_commission_volume",
        "total_exceptions_found",
        "changed_on_delta_humanized",
    ]

    show_columns = list_columns + [
        "description",
        "commissioner_name",
        "examiner_name",
        "examiner_title",
        "company_naic_code",
        "total_premium_volume",
        "methodology_notes",
        "scope_description",
        "executive_summary",
        "recommendations",
        "submitted_date",
        "completed_date",
        "created_on",
        "changed_on",
    ]

    order_columns = [
        "id",
        "title",
        "status",
        "audit_period_start",
        "state_jurisdiction",
        "company_name",
        "total_exceptions_found",
        "changed_on_delta_humanized",
    ]

    search_columns = [
        "title",
        "status",
        "state_jurisdiction",
        "company_name",
        "examiner_name",
    ]

    search_filters = {"title": [AuditReportAllTextFilter]}

    add_model_schema = CommissionAuditReportPostSchema()
    edit_model_schema = CommissionAuditReportPutSchema()

    @expose("/", methods=("POST",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.post",
        log_to_statsd=False,
    )
    @requires_json
    def post(self) -> Response:
        """Create a new commission audit report.
        ---
        post:
          summary: Create a commission audit report
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/CommissionAuditReportPostSchema'
          responses:
            201:
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      id:
                        type: number
                      result:
                        $ref: '#/components/schemas/CommissionAuditReportPostSchema'
            400:
              $ref: '#/components/responses/400'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            item = self.add_model_schema.load(request.json)
        except ValidationError as error:
            return self.response_400(message=error.messages)
        try:
            new_model = CreateCommissionAuditReportCommand(item).run()
            return self.response(201, id=new_model.id, result=item)
        except CommissionAuditReportInvalidError as ex:
            return self.response_422(message=ex.normalized_messages())
        except CommissionAuditReportCreateFailedError as ex:
            logger.error(
                "Error creating audit report: %s", str(ex), exc_info=True
            )
            return self.response_422(message=str(ex))

    @expose("/<int:pk>", methods=("PUT",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.put",
        log_to_statsd=False,
    )
    @requires_json
    def put(self, pk: int) -> Response:
        """Update a commission audit report.
        ---
        put:
          summary: Update a commission audit report
          parameters:
            - in: path
              name: pk
              schema:
                type: integer
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/CommissionAuditReportPutSchema'
          responses:
            200:
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      id:
                        type: number
                      result:
                        $ref: '#/components/schemas/CommissionAuditReportPutSchema'
            400:
              $ref: '#/components/responses/400'
            404:
              $ref: '#/components/responses/404'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            item = self.edit_model_schema.load(request.json)
        except ValidationError as error:
            return self.response_400(message=error.messages)
        try:
            UpdateCommissionAuditReportCommand(pk, item).run()
            return self.response(200, id=pk, result=item)
        except CommissionAuditReportNotFoundError:
            return self.response_404()
        except CommissionAuditReportUpdateFailedError as ex:
            logger.error(
                "Error updating audit report %s: %s", pk, str(ex), exc_info=True
            )
            return self.response_422(message=str(ex))

    @expose("/<int:pk>", methods=("DELETE",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.delete",
        log_to_statsd=False,
    )
    def delete(self, pk: int) -> Response:
        """Delete a commission audit report.
        ---
        delete:
          summary: Delete a commission audit report
          parameters:
            - in: path
              name: pk
              schema:
                type: integer
          responses:
            200:
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      message:
                        type: string
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            DeleteCommissionAuditReportCommand([pk]).run()
            return self.response(200, message="OK")
        except CommissionAuditReportNotFoundError:
            return self.response_404()
        except CommissionAuditReportDeleteFailedError as ex:
            logger.error(
                "Error deleting audit report %s: %s", pk, str(ex), exc_info=True
            )
            return self.response_422(message=str(ex))

    @expose("/", methods=("DELETE",))
    @protect()
    @safe
    @statsd_metrics
    @rison(get_delete_ids_schema)
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.bulk_delete",
        log_to_statsd=False,
    )
    def bulk_delete(self, **kwargs: Any) -> Response:
        """Bulk delete commission audit reports."""
        item_ids = kwargs["rison"]
        try:
            DeleteCommissionAuditReportCommand(item_ids).run()
            return self.response(
                200,
                message=ngettext(
                    "Deleted %(num)d audit report",
                    "Deleted %(num)d audit reports",
                    num=len(item_ids),
                ),
            )
        except CommissionAuditReportNotFoundError:
            return self.response_404()
        except CommissionAuditReportDeleteFailedError as ex:
            return self.response_422(message=str(ex))

    @expose("/statistics/<int:pk>", methods=("GET",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}"
        ".audit_statistics",
        log_to_statsd=False,
    )
    def audit_statistics(self, pk: int) -> Response:
        """Get statistics for a specific audit report.
        ---
        get:
          summary: Get audit report statistics
          parameters:
            - in: path
              name: pk
              schema:
                type: integer
          responses:
            200:
              content:
                application/json:
                  schema:
                    type: object
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            stats = CommissionAuditReportDAO.get_audit_statistics(pk)
            return self.response(200, result=stats)
        except Exception as ex:
            logger.error(
                "Error getting audit statistics: %s", str(ex), exc_info=True
            )
            return self.response_422(message=str(ex))


class AuditFindingRestApi(BaseSupersetModelRestApi):
    datamodel = SQLAInterface(AuditFinding)

    include_route_methods = RouteMethod.REST_MODEL_VIEW_CRUD_SET | {
        RouteMethod.RELATED,
        "bulk_delete",
    }
    class_permission_name = "AuditFinding"
    method_permission_name = MODEL_API_RW_METHOD_PERMISSION_MAP
    resource_name = "audit_finding"
    allow_browser_login = True

    openapi_spec_tag = "Audit Findings"
    openapi_spec_methods = audit_finding_openapi_spec

    list_columns = [
        "id",
        "uuid",
        "audit_report_id",
        "commission_transaction_id",
        "finding_code",
        "title",
        "severity",
        "status",
        "variance_amount",
        "remediation_deadline",
        "changed_on_delta_humanized",
    ]

    show_columns = list_columns + [
        "description",
        "regulation_reference",
        "expected_value",
        "actual_value",
        "remediation_plan",
        "remediated_date",
        "remediation_notes",
        "created_on",
        "changed_on",
    ]

    order_columns = [
        "id",
        "finding_code",
        "severity",
        "status",
        "variance_amount",
        "remediation_deadline",
        "changed_on_delta_humanized",
    ]

    search_columns = [
        "finding_code",
        "title",
        "severity",
        "status",
        "audit_report_id",
    ]

    search_filters = {"finding_code": [AuditFindingAllTextFilter]}

    add_model_schema = AuditFindingPostSchema()
    edit_model_schema = AuditFindingPutSchema()

    @expose("/", methods=("POST",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.post",
        log_to_statsd=False,
    )
    @requires_json
    def post(self) -> Response:
        """Create a new audit finding.
        ---
        post:
          summary: Create an audit finding
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/AuditFindingPostSchema'
          responses:
            201:
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      id:
                        type: number
                      result:
                        $ref: '#/components/schemas/AuditFindingPostSchema'
            400:
              $ref: '#/components/responses/400'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            item = self.add_model_schema.load(request.json)
        except ValidationError as error:
            return self.response_400(message=error.messages)
        try:
            new_model = CreateAuditFindingCommand(item).run()
            return self.response(201, id=new_model.id, result=item)
        except AuditFindingInvalidError as ex:
            return self.response_422(message=ex.normalized_messages())
        except AuditFindingCreateFailedError as ex:
            logger.error(
                "Error creating audit finding: %s", str(ex), exc_info=True
            )
            return self.response_422(message=str(ex))

    @expose("/<int:pk>", methods=("PUT",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.put",
        log_to_statsd=False,
    )
    @requires_json
    def put(self, pk: int) -> Response:
        """Update an audit finding.
        ---
        put:
          summary: Update an audit finding
          parameters:
            - in: path
              name: pk
              schema:
                type: integer
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/AuditFindingPutSchema'
          responses:
            200:
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      id:
                        type: number
                      result:
                        $ref: '#/components/schemas/AuditFindingPutSchema'
            400:
              $ref: '#/components/responses/400'
            404:
              $ref: '#/components/responses/404'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            item = self.edit_model_schema.load(request.json)
        except ValidationError as error:
            return self.response_400(message=error.messages)
        try:
            UpdateAuditFindingCommand(pk, item).run()
            return self.response(200, id=pk, result=item)
        except AuditFindingNotFoundError:
            return self.response_404()
        except AuditFindingUpdateFailedError as ex:
            logger.error(
                "Error updating audit finding %s: %s", pk, str(ex), exc_info=True
            )
            return self.response_422(message=str(ex))

    @expose("/<int:pk>", methods=("DELETE",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.delete",
        log_to_statsd=False,
    )
    def delete(self, pk: int) -> Response:
        """Delete an audit finding.
        ---
        delete:
          summary: Delete an audit finding
          parameters:
            - in: path
              name: pk
              schema:
                type: integer
          responses:
            200:
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      message:
                        type: string
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            DeleteAuditFindingCommand([pk]).run()
            return self.response(200, message="OK")
        except AuditFindingNotFoundError:
            return self.response_404()
        except AuditFindingDeleteFailedError as ex:
            logger.error(
                "Error deleting audit finding %s: %s", pk, str(ex), exc_info=True
            )
            return self.response_422(message=str(ex))

    @expose("/", methods=("DELETE",))
    @protect()
    @safe
    @statsd_metrics
    @rison(get_delete_ids_schema)
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.bulk_delete",
        log_to_statsd=False,
    )
    def bulk_delete(self, **kwargs: Any) -> Response:
        """Bulk delete audit findings."""
        item_ids = kwargs["rison"]
        try:
            DeleteAuditFindingCommand(item_ids).run()
            return self.response(
                200,
                message=ngettext(
                    "Deleted %(num)d finding",
                    "Deleted %(num)d findings",
                    num=len(item_ids),
                ),
            )
        except AuditFindingNotFoundError:
            return self.response_404()
        except AuditFindingDeleteFailedError as ex:
            return self.response_422(message=str(ex))
