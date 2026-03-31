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
"""Marshmallow schemas for Insurance Commission Audit API validation."""

from __future__ import annotations

from marshmallow import fields, Schema, validate, validates_schema
from marshmallow.validate import Length, ValidationError

from superset.insurance_commission_audit.models import (
    AuditStatus,
    CommissionType,
    FindingSeverity,
    FindingStatus,
    LineOfBusiness,
    ProducerStatus,
    ProducerType,
)

# --- OpenAPI spec overrides ---

producer_openapi_spec = {
    "get": {"get": {"summary": "Get an insurance producer"}},
    "get_list": {
        "get": {
            "summary": "Get a list of insurance producers",
            "description": "Gets a list of insurance producers with filtering, "
            "sorting, and pagination.",
        }
    },
    "post": {"post": {"summary": "Create an insurance producer"}},
    "put": {"put": {"summary": "Update an insurance producer"}},
    "delete": {"delete": {"summary": "Delete an insurance producer"}},
}

commission_transaction_openapi_spec = {
    "get": {"get": {"summary": "Get a commission transaction"}},
    "get_list": {
        "get": {
            "summary": "Get a list of commission transactions",
            "description": "Gets a list of commission transactions with filtering, "
            "sorting, and pagination.",
        }
    },
    "post": {"post": {"summary": "Create a commission transaction"}},
    "put": {"put": {"summary": "Update a commission transaction"}},
    "delete": {"delete": {"summary": "Delete a commission transaction"}},
}

audit_report_openapi_spec = {
    "get": {"get": {"summary": "Get a commission audit report"}},
    "get_list": {
        "get": {
            "summary": "Get a list of commission audit reports",
            "description": "Gets a list of commission audit reports with filtering, "
            "sorting, and pagination.",
        }
    },
    "post": {"post": {"summary": "Create a commission audit report"}},
    "put": {"put": {"summary": "Update a commission audit report"}},
    "delete": {"delete": {"summary": "Delete a commission audit report"}},
}

audit_finding_openapi_spec = {
    "get": {"get": {"summary": "Get an audit finding"}},
    "get_list": {
        "get": {
            "summary": "Get a list of audit findings",
            "description": "Gets a list of audit findings with filtering, "
            "sorting, and pagination.",
        }
    },
    "post": {"post": {"summary": "Create an audit finding"}},
    "put": {"put": {"summary": "Update an audit finding"}},
    "delete": {"delete": {"summary": "Delete an audit finding"}},
}

get_delete_ids_schema = {"type": "array", "items": {"type": "integer"}}

US_STATES = [
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
    "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
    "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
    "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
    "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
    "DC", "PR", "VI", "GU", "AS", "MP",
]


# --- Producer Schemas ---


class InsuranceProducerPostSchema(Schema):
    national_producer_number = fields.String(
        required=True, validate=Length(min=1, max=20)
    )
    license_number = fields.String(required=True, validate=Length(min=1, max=50))
    license_state = fields.String(required=True, validate=validate.OneOf(US_STATES))
    first_name = fields.String(validate=Length(max=100), load_default=None)
    last_name = fields.String(validate=Length(max=100), load_default=None)
    business_name = fields.String(validate=Length(max=255), load_default=None)
    producer_type = fields.String(
        validate=validate.OneOf([e.value for e in ProducerType]),
        load_default=ProducerType.INDIVIDUAL,
    )
    status = fields.String(
        validate=validate.OneOf([e.value for e in ProducerStatus]),
        load_default=ProducerStatus.ACTIVE,
    )
    tax_id_last_four = fields.String(validate=Length(max=4), load_default=None)
    email = fields.Email(load_default=None)
    phone = fields.String(validate=Length(max=20), load_default=None)
    appointment_date = fields.Date(load_default=None)
    termination_date = fields.Date(load_default=None)
    license_expiry_date = fields.Date(load_default=None)
    lines_of_authority = fields.String(load_default=None)
    appointing_company = fields.String(validate=Length(max=255), load_default=None)
    agency_affiliation = fields.String(validate=Length(max=255), load_default=None)

    @validates_schema
    def validate_producer_identity(
        self, data: dict, **kwargs: dict  # noqa: ANN003
    ) -> None:
        producer_type = data.get("producer_type", ProducerType.INDIVIDUAL)
        if producer_type == ProducerType.INDIVIDUAL:
            if not data.get("first_name") or not data.get("last_name"):
                raise ValidationError(
                    "first_name and last_name are required for individual producers."
                )
        elif producer_type == ProducerType.BUSINESS_ENTITY:
            if not data.get("business_name"):
                raise ValidationError(
                    "business_name is required for business entity producers."
                )


class InsuranceProducerPutSchema(Schema):
    license_number = fields.String(validate=Length(min=1, max=50))
    license_state = fields.String(validate=validate.OneOf(US_STATES))
    first_name = fields.String(validate=Length(max=100))
    last_name = fields.String(validate=Length(max=100))
    business_name = fields.String(validate=Length(max=255))
    producer_type = fields.String(
        validate=validate.OneOf([e.value for e in ProducerType])
    )
    status = fields.String(
        validate=validate.OneOf([e.value for e in ProducerStatus])
    )
    tax_id_last_four = fields.String(validate=Length(max=4))
    email = fields.Email()
    phone = fields.String(validate=Length(max=20))
    appointment_date = fields.Date()
    termination_date = fields.Date()
    license_expiry_date = fields.Date()
    lines_of_authority = fields.String()
    appointing_company = fields.String(validate=Length(max=255))
    agency_affiliation = fields.String(validate=Length(max=255))


# --- Commission Transaction Schemas ---


class CommissionTransactionPostSchema(Schema):
    producer_id = fields.Integer(required=True)
    policy_number = fields.String(required=True, validate=Length(min=1, max=50))
    policy_holder_name = fields.String(validate=Length(max=255), load_default=None)
    policy_effective_date = fields.Date(load_default=None)
    policy_expiry_date = fields.Date(load_default=None)
    line_of_business = fields.String(
        required=True,
        validate=validate.OneOf([e.value for e in LineOfBusiness]),
    )
    commission_type = fields.String(
        required=True,
        validate=validate.OneOf([e.value for e in CommissionType]),
    )
    transaction_date = fields.Date(required=True)
    premium_amount = fields.Float(required=True, validate=validate.Range(min=0))
    commission_rate = fields.Float(
        required=True, validate=validate.Range(min=0, max=1)
    )
    commission_amount = fields.Float(required=True)
    override_amount = fields.Float(load_default=0.0)
    net_commission = fields.Float(required=True)
    carrier_name = fields.String(required=True, validate=Length(min=1, max=255))
    carrier_naic_code = fields.String(validate=Length(max=10), load_default=None)
    payment_reference = fields.String(validate=Length(max=100), load_default=None)
    statement_period_start = fields.Date(load_default=None)
    statement_period_end = fields.Date(load_default=None)
    is_chargeback = fields.Boolean(load_default=False)
    chargeback_reason = fields.String(load_default=None)
    original_transaction_id = fields.Integer(load_default=None)
    notes = fields.String(load_default=None)


class CommissionTransactionPutSchema(Schema):
    policy_number = fields.String(validate=Length(min=1, max=50))
    policy_holder_name = fields.String(validate=Length(max=255))
    policy_effective_date = fields.Date()
    policy_expiry_date = fields.Date()
    line_of_business = fields.String(
        validate=validate.OneOf([e.value for e in LineOfBusiness])
    )
    commission_type = fields.String(
        validate=validate.OneOf([e.value for e in CommissionType])
    )
    transaction_date = fields.Date()
    premium_amount = fields.Float(validate=validate.Range(min=0))
    commission_rate = fields.Float(validate=validate.Range(min=0, max=1))
    commission_amount = fields.Float()
    override_amount = fields.Float()
    net_commission = fields.Float()
    carrier_name = fields.String(validate=Length(min=1, max=255))
    carrier_naic_code = fields.String(validate=Length(max=10))
    payment_reference = fields.String(validate=Length(max=100))
    statement_period_start = fields.Date()
    statement_period_end = fields.Date()
    is_chargeback = fields.Boolean()
    chargeback_reason = fields.String()
    original_transaction_id = fields.Integer()
    notes = fields.String()


# --- Audit Report Schemas ---


class CommissionAuditReportPostSchema(Schema):
    title = fields.String(required=True, validate=Length(min=1, max=255))
    description = fields.String(load_default=None)
    audit_period_start = fields.Date(required=True)
    audit_period_end = fields.Date(required=True)
    state_jurisdiction = fields.String(
        required=True, validate=validate.OneOf(US_STATES)
    )
    commissioner_name = fields.String(validate=Length(max=255), load_default=None)
    examiner_name = fields.String(validate=Length(max=255), load_default=None)
    examiner_title = fields.String(validate=Length(max=100), load_default=None)
    company_name = fields.String(required=True, validate=Length(min=1, max=255))
    company_naic_code = fields.String(validate=Length(max=10), load_default=None)
    methodology_notes = fields.String(load_default=None)
    scope_description = fields.String(load_default=None)

    @validates_schema
    def validate_audit_period(
        self, data: dict, **kwargs: dict  # noqa: ANN003
    ) -> None:
        start = data.get("audit_period_start")
        end = data.get("audit_period_end")
        if start and end and start > end:
            raise ValidationError(
                "audit_period_start must be before audit_period_end."
            )


class CommissionAuditReportPutSchema(Schema):
    title = fields.String(validate=Length(min=1, max=255))
    description = fields.String()
    status = fields.String(
        validate=validate.OneOf([e.value for e in AuditStatus])
    )
    audit_period_start = fields.Date()
    audit_period_end = fields.Date()
    state_jurisdiction = fields.String(validate=validate.OneOf(US_STATES))
    commissioner_name = fields.String(validate=Length(max=255))
    examiner_name = fields.String(validate=Length(max=255))
    examiner_title = fields.String(validate=Length(max=100))
    company_name = fields.String(validate=Length(min=1, max=255))
    company_naic_code = fields.String(validate=Length(max=10))
    total_producers_examined = fields.Integer()
    total_transactions_examined = fields.Integer()
    total_commission_volume = fields.Float()
    total_premium_volume = fields.Float()
    total_exceptions_found = fields.Integer()
    methodology_notes = fields.String()
    scope_description = fields.String()
    executive_summary = fields.String()
    recommendations = fields.String()


# --- Audit Finding Schemas ---


class AuditFindingPostSchema(Schema):
    audit_report_id = fields.Integer(required=True)
    commission_transaction_id = fields.Integer(load_default=None)
    finding_code = fields.String(required=True, validate=Length(min=1, max=20))
    title = fields.String(required=True, validate=Length(min=1, max=255))
    description = fields.String(required=True)
    severity = fields.String(
        required=True,
        validate=validate.OneOf([e.value for e in FindingSeverity]),
    )
    regulation_reference = fields.String(validate=Length(max=255), load_default=None)
    expected_value = fields.String(validate=Length(max=255), load_default=None)
    actual_value = fields.String(validate=Length(max=255), load_default=None)
    variance_amount = fields.Float(load_default=None)
    remediation_plan = fields.String(load_default=None)
    remediation_deadline = fields.Date(load_default=None)


class AuditFindingPutSchema(Schema):
    finding_code = fields.String(validate=Length(min=1, max=20))
    title = fields.String(validate=Length(min=1, max=255))
    description = fields.String()
    severity = fields.String(
        validate=validate.OneOf([e.value for e in FindingSeverity])
    )
    status = fields.String(
        validate=validate.OneOf([e.value for e in FindingStatus])
    )
    regulation_reference = fields.String(validate=Length(max=255))
    expected_value = fields.String(validate=Length(max=255))
    actual_value = fields.String(validate=Length(max=255))
    variance_amount = fields.Float()
    remediation_plan = fields.String()
    remediation_deadline = fields.Date()
    remediated_date = fields.Date()
    remediation_notes = fields.String()
