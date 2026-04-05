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
"""Tests for the audit workflow state machine."""

from __future__ import annotations

from superset.insurance_commission_audit.models import AuditStatus
from superset.insurance_commission_audit.workflow import (
    AuditContext,
    AuditWorkflowEngine,
)


def test_draft_to_in_progress() -> None:
    engine = AuditWorkflowEngine()
    result = engine.transition(AuditStatus.DRAFT, AuditStatus.IN_PROGRESS)
    assert result.success is True


def test_invalid_transition_rejected() -> None:
    engine = AuditWorkflowEngine()
    result = engine.transition(AuditStatus.DRAFT, AuditStatus.COMPLETED)
    assert result.success is False
    assert "not defined" in result.message


def test_in_progress_to_under_review_without_methodology() -> None:
    engine = AuditWorkflowEngine()
    context = AuditContext(
        total_transactions_examined=100,
        total_producers_examined=5,
        has_methodology=False,
    )
    result = engine.transition(
        AuditStatus.IN_PROGRESS, AuditStatus.UNDER_REVIEW, context=context
    )
    assert result.success is False
    assert any("methodology" in e.lower() for e in result.validation_errors)


def test_in_progress_to_under_review_valid() -> None:
    engine = AuditWorkflowEngine()
    context = AuditContext(
        total_transactions_examined=100,
        total_producers_examined=5,
        has_methodology=True,
    )
    result = engine.transition(
        AuditStatus.IN_PROGRESS, AuditStatus.UNDER_REVIEW, context=context
    )
    assert result.success is True


def test_under_review_to_completed_requires_supervisor() -> None:
    engine = AuditWorkflowEngine()
    context = AuditContext(
        has_executive_summary=True,
        has_recommendations=True,
        all_findings_reviewed=True,
    )
    result = engine.transition(
        AuditStatus.UNDER_REVIEW,
        AuditStatus.COMPLETED,
        user_role="examiner",
        context=context,
    )
    assert result.success is False
    assert any("audit_supervisor" in e for e in result.validation_errors)


def test_under_review_to_completed_supervisor_approved() -> None:
    engine = AuditWorkflowEngine()
    context = AuditContext(
        has_executive_summary=True,
        has_recommendations=True,
        all_findings_reviewed=True,
    )
    result = engine.transition(
        AuditStatus.UNDER_REVIEW,
        AuditStatus.COMPLETED,
        user_role="audit_supervisor",
        context=context,
    )
    assert result.success is True


def test_completed_to_submitted_requires_director() -> None:
    engine = AuditWorkflowEngine()
    context = AuditContext(
        open_findings=0,
        has_executive_summary=True,
        has_recommendations=True,
        has_methodology=True,
    )
    result = engine.transition(
        AuditStatus.COMPLETED,
        AuditStatus.SUBMITTED,
        user_role="audit_supervisor",
        context=context,
    )
    assert result.success is False


def test_completed_to_submitted_director_approved() -> None:
    engine = AuditWorkflowEngine()
    context = AuditContext(
        open_findings=0,
        has_executive_summary=True,
        has_recommendations=True,
        has_methodology=True,
    )
    result = engine.transition(
        AuditStatus.COMPLETED,
        AuditStatus.SUBMITTED,
        user_role="audit_director",
        context=context,
    )
    assert result.success is True


def test_admin_bypasses_role_requirement() -> None:
    engine = AuditWorkflowEngine()
    context = AuditContext(
        has_executive_summary=True,
        has_recommendations=True,
        all_findings_reviewed=True,
    )
    result = engine.transition(
        AuditStatus.UNDER_REVIEW,
        AuditStatus.COMPLETED,
        user_role="admin",
        context=context,
    )
    assert result.success is True


def test_rejected_to_in_progress() -> None:
    engine = AuditWorkflowEngine()
    result = engine.transition(AuditStatus.REJECTED, AuditStatus.IN_PROGRESS)
    assert result.success is True


def test_get_allowed_transitions() -> None:
    engine = AuditWorkflowEngine()
    transitions = engine.get_allowed_transitions(AuditStatus.IN_PROGRESS)
    targets = {t.to_status for t in transitions}
    assert AuditStatus.UNDER_REVIEW in targets
    assert AuditStatus.DRAFT in targets


def test_workflow_graph_structure() -> None:
    engine = AuditWorkflowEngine()
    graph = engine.get_workflow_graph()
    assert "states" in graph
    assert "transitions" in graph
    assert AuditStatus.DRAFT in graph["states"]
    assert AuditStatus.SUBMITTED in graph["terminal_states"]


def test_can_transition_check() -> None:
    engine = AuditWorkflowEngine()
    can, errors = engine.can_transition(AuditStatus.DRAFT, AuditStatus.IN_PROGRESS)
    assert can is True
    assert len(errors) == 0

    can, errors = engine.can_transition(AuditStatus.DRAFT, AuditStatus.SUBMITTED)
    assert can is False


def test_submission_blocked_with_open_findings() -> None:
    engine = AuditWorkflowEngine()
    context = AuditContext(
        open_findings=3,
        has_executive_summary=True,
        has_recommendations=True,
        has_methodology=True,
    )
    result = engine.transition(
        AuditStatus.COMPLETED,
        AuditStatus.SUBMITTED,
        user_role="audit_director",
        context=context,
    )
    assert result.success is False
    assert any("open" in e.lower() for e in result.validation_errors)
