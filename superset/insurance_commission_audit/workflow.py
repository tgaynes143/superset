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
"""Audit workflow state machine with transition rules and approval gates.

Manages the lifecycle of a commission audit report through defined
states with enforced transition rules, required approvals, and
automated validation gates.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from superset.insurance_commission_audit.models import AuditStatus

logger = logging.getLogger(__name__)


class WorkflowError(Exception):
    """Raised when a workflow transition is invalid."""


@dataclass(frozen=True)
class TransitionRule:
    """Defines an allowed state transition with requirements."""

    from_status: str
    to_status: str
    requires_approval: bool = False
    required_role: str | None = None
    validation_fn_name: str | None = None
    description: str = ""


@dataclass
class TransitionResult:
    """Result of attempting a workflow transition."""

    success: bool
    from_status: str
    to_status: str
    message: str
    transitioned_at: datetime | None = None
    transitioned_by: str | None = None
    validation_errors: list[str] = field(default_factory=list)


# Define the complete audit workflow transition matrix
AUDIT_TRANSITIONS: list[TransitionRule] = [
    TransitionRule(
        from_status=AuditStatus.DRAFT,
        to_status=AuditStatus.IN_PROGRESS,
        description="Begin the audit examination process.",
    ),
    TransitionRule(
        from_status=AuditStatus.IN_PROGRESS,
        to_status=AuditStatus.UNDER_REVIEW,
        validation_fn_name="validate_audit_completeness",
        description="Submit audit for supervisory review. Requires findings.",
    ),
    TransitionRule(
        from_status=AuditStatus.IN_PROGRESS,
        to_status=AuditStatus.DRAFT,
        description="Return audit to draft for significant scope changes.",
    ),
    TransitionRule(
        from_status=AuditStatus.UNDER_REVIEW,
        to_status=AuditStatus.COMPLETED,
        requires_approval=True,
        required_role="audit_supervisor",
        validation_fn_name="validate_review_complete",
        description="Approve the audit. Requires supervisor approval and all findings addressed.",
    ),
    TransitionRule(
        from_status=AuditStatus.UNDER_REVIEW,
        to_status=AuditStatus.IN_PROGRESS,
        description="Return audit for additional work based on review.",
    ),
    TransitionRule(
        from_status=AuditStatus.COMPLETED,
        to_status=AuditStatus.SUBMITTED,
        requires_approval=True,
        required_role="audit_director",
        validation_fn_name="validate_submission_ready",
        description="Submit to insurance commissioner. Requires director sign-off.",
    ),
    TransitionRule(
        from_status=AuditStatus.SUBMITTED,
        to_status=AuditStatus.REJECTED,
        description="Commissioner rejects the audit report.",
    ),
    TransitionRule(
        from_status=AuditStatus.REJECTED,
        to_status=AuditStatus.IN_PROGRESS,
        description="Reopen rejected audit for remediation.",
    ),
]


@dataclass
class AuditContext:
    """Context data needed for workflow validation gates."""

    total_findings: int = 0
    open_findings: int = 0
    critical_findings_unresolved: int = 0
    has_executive_summary: bool = False
    has_recommendations: bool = False
    has_methodology: bool = False
    total_transactions_examined: int = 0
    total_producers_examined: int = 0
    all_findings_reviewed: bool = False
    report_signed: bool = False


class AuditWorkflowEngine:
    """State machine for audit report lifecycle management."""

    def __init__(
        self,
        transitions: list[TransitionRule] | None = None,
    ) -> None:
        self._transitions = transitions or AUDIT_TRANSITIONS
        self._transition_map: dict[tuple[str, str], TransitionRule] = {}
        for rule in self._transitions:
            self._transition_map[(rule.from_status, rule.to_status)] = rule

    def get_allowed_transitions(self, current_status: str) -> list[TransitionRule]:
        """Get all possible transitions from the current status."""
        return [
            rule
            for rule in self._transitions
            if rule.from_status == current_status
        ]

    def can_transition(
        self,
        current_status: str,
        target_status: str,
        user_role: str | None = None,
        context: AuditContext | None = None,
    ) -> tuple[bool, list[str]]:
        """Check if a transition is allowed without executing it."""
        errors: list[str] = []
        rule = self._transition_map.get((current_status, target_status))

        if not rule:
            errors.append(
                f"Transition from '{current_status}' to '{target_status}' "
                f"is not defined in the workflow."
            )
            return False, errors

        if rule.requires_approval and rule.required_role:
            if user_role != rule.required_role and user_role != "admin":
                errors.append(
                    f"Transition requires role '{rule.required_role}' "
                    f"but user has role '{user_role}'."
                )

        if rule.validation_fn_name and context:
            validator = getattr(self, rule.validation_fn_name, None)
            if validator:
                validation_errors = validator(context)
                errors.extend(validation_errors)

        return len(errors) == 0, errors

    def transition(
        self,
        current_status: str,
        target_status: str,
        user_role: str | None = None,
        user_name: str | None = None,
        context: AuditContext | None = None,
    ) -> TransitionResult:
        """Execute a workflow transition with full validation."""
        can_do, errors = self.can_transition(
            current_status, target_status, user_role, context
        )

        if not can_do:
            return TransitionResult(
                success=False,
                from_status=current_status,
                to_status=target_status,
                message=f"Transition denied: {'; '.join(errors)}",
                validation_errors=errors,
            )

        now = datetime.utcnow()
        rule = self._transition_map[(current_status, target_status)]

        return TransitionResult(
            success=True,
            from_status=current_status,
            to_status=target_status,
            message=f"Transition successful: {rule.description}",
            transitioned_at=now,
            transitioned_by=user_name,
        )

    @staticmethod
    def validate_audit_completeness(context: AuditContext) -> list[str]:
        """Validate that an audit has minimum required content before review."""
        errors: list[str] = []
        if context.total_transactions_examined == 0:
            errors.append("No transactions have been examined.")
        if context.total_producers_examined == 0:
            errors.append("No producers have been examined.")
        if not context.has_methodology:
            errors.append("Audit methodology has not been documented.")
        return errors

    @staticmethod
    def validate_review_complete(context: AuditContext) -> list[str]:
        """Validate that review requirements are met before completion."""
        errors: list[str] = []
        if context.critical_findings_unresolved > 0:
            errors.append(
                f"{context.critical_findings_unresolved} critical findings "
                f"remain unresolved."
            )
        if not context.has_executive_summary:
            errors.append("Executive summary is required before completion.")
        if not context.has_recommendations:
            errors.append("Recommendations section is required.")
        if not context.all_findings_reviewed:
            errors.append("All findings must be reviewed before completion.")
        return errors

    @staticmethod
    def validate_submission_ready(context: AuditContext) -> list[str]:
        """Validate final submission readiness for insurance commissioner."""
        errors: list[str] = []
        if context.open_findings > 0:
            errors.append(
                f"{context.open_findings} findings are still open. "
                f"All must be closed or acknowledged before submission."
            )
        if not context.has_executive_summary:
            errors.append("Executive summary required for commissioner submission.")
        if not context.has_recommendations:
            errors.append("Recommendations required for commissioner submission.")
        if not context.has_methodology:
            errors.append("Methodology documentation required.")
        return errors

    def get_workflow_graph(self) -> dict[str, Any]:
        """Return the complete workflow as a graph structure for visualization."""
        states = set()
        edges: list[dict[str, Any]] = []

        for rule in self._transitions:
            states.add(rule.from_status)
            states.add(rule.to_status)
            edges.append(
                {
                    "from": rule.from_status,
                    "to": rule.to_status,
                    "requires_approval": rule.requires_approval,
                    "required_role": rule.required_role,
                    "has_validation": rule.validation_fn_name is not None,
                    "description": rule.description,
                }
            )

        return {
            "states": sorted(states),
            "transitions": edges,
            "initial_state": AuditStatus.DRAFT,
            "terminal_states": [AuditStatus.SUBMITTED],
        }
