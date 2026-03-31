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
"""add insurance commission audit tables

Revision ID: b7c8d9e0f1a2
Revises: a1b2c3d4e5f6
Create Date: 2026-03-31 12:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = "b7c8d9e0f1a2"
down_revision = "a1b2c3d4e5f6"

import sqlalchemy as sa  # noqa: E402
from alembic import op  # noqa: E402
from sqlalchemy_utils import UUIDType  # noqa: E402


def upgrade():
    # Insurance Producer table
    op.create_table(
        "insurance_producer",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("uuid", UUIDType(binary=True), unique=True, nullable=False),
        sa.Column(
            "national_producer_number", sa.String(20), unique=True, nullable=False
        ),
        sa.Column("license_number", sa.String(50), nullable=False),
        sa.Column("license_state", sa.String(2), nullable=False),
        sa.Column("first_name", sa.String(100), nullable=True),
        sa.Column("last_name", sa.String(100), nullable=True),
        sa.Column("business_name", sa.String(255), nullable=True),
        sa.Column("producer_type", sa.String(50), nullable=False, server_default="individual"),
        sa.Column("status", sa.String(50), nullable=False, server_default="active"),
        sa.Column("tax_id_last_four", sa.String(4), nullable=True),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("phone", sa.String(20), nullable=True),
        sa.Column("appointment_date", sa.Date(), nullable=True),
        sa.Column("termination_date", sa.Date(), nullable=True),
        sa.Column("license_expiry_date", sa.Date(), nullable=True),
        sa.Column("lines_of_authority", sa.Text(), nullable=True),
        sa.Column("appointing_company", sa.String(255), nullable=True),
        sa.Column("agency_affiliation", sa.String(255), nullable=True),
        sa.Column("created_on", sa.DateTime(), nullable=True),
        sa.Column("changed_on", sa.DateTime(), nullable=True),
        sa.Column("created_by_fk", sa.Integer(), nullable=True),
        sa.Column("changed_by_fk", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["created_by_fk"], ["ab_user.id"]),
        sa.ForeignKeyConstraint(["changed_by_fk"], ["ab_user.id"]),
    )
    op.create_index("ix_producer_npn", "insurance_producer", ["national_producer_number"])
    op.create_index(
        "ix_producer_license",
        "insurance_producer",
        ["license_number", "license_state"],
    )

    # Commission Transaction table
    op.create_table(
        "commission_transaction",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("uuid", UUIDType(binary=True), unique=True, nullable=False),
        sa.Column("producer_id", sa.Integer(), nullable=False),
        sa.Column("policy_number", sa.String(50), nullable=False),
        sa.Column("policy_holder_name", sa.String(255), nullable=True),
        sa.Column("policy_effective_date", sa.Date(), nullable=True),
        sa.Column("policy_expiry_date", sa.Date(), nullable=True),
        sa.Column("line_of_business", sa.String(50), nullable=False),
        sa.Column("commission_type", sa.String(50), nullable=False),
        sa.Column("transaction_date", sa.Date(), nullable=False),
        sa.Column("premium_amount", sa.Float(), nullable=False),
        sa.Column("commission_rate", sa.Float(), nullable=False),
        sa.Column("commission_amount", sa.Float(), nullable=False),
        sa.Column("override_amount", sa.Float(), server_default="0.0"),
        sa.Column("net_commission", sa.Float(), nullable=False),
        sa.Column("carrier_name", sa.String(255), nullable=False),
        sa.Column("carrier_naic_code", sa.String(10), nullable=True),
        sa.Column("payment_reference", sa.String(100), nullable=True),
        sa.Column("statement_period_start", sa.Date(), nullable=True),
        sa.Column("statement_period_end", sa.Date(), nullable=True),
        sa.Column("is_chargeback", sa.Boolean(), server_default="0"),
        sa.Column("chargeback_reason", sa.Text(), nullable=True),
        sa.Column("original_transaction_id", sa.Integer(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_on", sa.DateTime(), nullable=True),
        sa.Column("changed_on", sa.DateTime(), nullable=True),
        sa.Column("created_by_fk", sa.Integer(), nullable=True),
        sa.Column("changed_by_fk", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["producer_id"], ["insurance_producer.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["created_by_fk"], ["ab_user.id"]),
        sa.ForeignKeyConstraint(["changed_by_fk"], ["ab_user.id"]),
    )
    op.create_index(
        "ix_commission_producer_id", "commission_transaction", ["producer_id"]
    )
    op.create_index(
        "ix_commission_policy_number", "commission_transaction", ["policy_number"]
    )
    op.create_index(
        "ix_commission_transaction_date",
        "commission_transaction",
        ["transaction_date"],
    )
    op.create_index(
        "ix_commission_line_of_business",
        "commission_transaction",
        ["line_of_business"],
    )

    # Commission Audit Report table
    op.create_table(
        "commission_audit_report",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("uuid", UUIDType(binary=True), unique=True, nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="draft"),
        sa.Column("audit_period_start", sa.Date(), nullable=False),
        sa.Column("audit_period_end", sa.Date(), nullable=False),
        sa.Column("state_jurisdiction", sa.String(2), nullable=False),
        sa.Column("commissioner_name", sa.String(255), nullable=True),
        sa.Column("examiner_name", sa.String(255), nullable=True),
        sa.Column("examiner_title", sa.String(100), nullable=True),
        sa.Column("company_name", sa.String(255), nullable=False),
        sa.Column("company_naic_code", sa.String(10), nullable=True),
        sa.Column("total_producers_examined", sa.Integer(), server_default="0"),
        sa.Column("total_transactions_examined", sa.Integer(), server_default="0"),
        sa.Column("total_commission_volume", sa.Float(), server_default="0.0"),
        sa.Column("total_premium_volume", sa.Float(), server_default="0.0"),
        sa.Column("total_exceptions_found", sa.Integer(), server_default="0"),
        sa.Column("methodology_notes", sa.Text(), nullable=True),
        sa.Column("scope_description", sa.Text(), nullable=True),
        sa.Column("executive_summary", sa.Text(), nullable=True),
        sa.Column("recommendations", sa.Text(), nullable=True),
        sa.Column("submitted_date", sa.DateTime(), nullable=True),
        sa.Column("completed_date", sa.DateTime(), nullable=True),
        sa.Column("created_on", sa.DateTime(), nullable=True),
        sa.Column("changed_on", sa.DateTime(), nullable=True),
        sa.Column("created_by_fk", sa.Integer(), nullable=True),
        sa.Column("changed_by_fk", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["created_by_fk"], ["ab_user.id"]),
        sa.ForeignKeyConstraint(["changed_by_fk"], ["ab_user.id"]),
    )
    op.create_index(
        "ix_audit_report_status", "commission_audit_report", ["status"]
    )
    op.create_index(
        "ix_audit_report_period",
        "commission_audit_report",
        ["audit_period_start", "audit_period_end"],
    )

    # Audit Finding table
    op.create_table(
        "audit_finding",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("uuid", UUIDType(binary=True), unique=True, nullable=False),
        sa.Column("audit_report_id", sa.Integer(), nullable=False),
        sa.Column("commission_transaction_id", sa.Integer(), nullable=True),
        sa.Column("finding_code", sa.String(20), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default="open"),
        sa.Column("regulation_reference", sa.String(255), nullable=True),
        sa.Column("expected_value", sa.String(255), nullable=True),
        sa.Column("actual_value", sa.String(255), nullable=True),
        sa.Column("variance_amount", sa.Float(), nullable=True),
        sa.Column("remediation_plan", sa.Text(), nullable=True),
        sa.Column("remediation_deadline", sa.Date(), nullable=True),
        sa.Column("remediated_date", sa.Date(), nullable=True),
        sa.Column("remediation_notes", sa.Text(), nullable=True),
        sa.Column("created_on", sa.DateTime(), nullable=True),
        sa.Column("changed_on", sa.DateTime(), nullable=True),
        sa.Column("created_by_fk", sa.Integer(), nullable=True),
        sa.Column("changed_by_fk", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["audit_report_id"],
            ["commission_audit_report.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["commission_transaction_id"],
            ["commission_transaction.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(["created_by_fk"], ["ab_user.id"]),
        sa.ForeignKeyConstraint(["changed_by_fk"], ["ab_user.id"]),
    )
    op.create_index("ix_finding_report_id", "audit_finding", ["audit_report_id"])
    op.create_index("ix_finding_severity", "audit_finding", ["severity"])
    op.create_index("ix_finding_status", "audit_finding", ["status"])


def downgrade():
    op.drop_table("audit_finding")
    op.drop_table("commission_audit_report")
    op.drop_table("commission_transaction")
    op.drop_table("insurance_producer")
