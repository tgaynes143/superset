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
"""Advanced REST API endpoints for audit intelligence features.

Provides endpoints for:
- Automated audit execution (compliance + anomaly + risk + report)
- Individual compliance checks
- Producer risk scoring
- Workflow state transitions
- Audit trail querying
"""

from __future__ import annotations

import logging
from typing import Any

from flask import request, Response
from flask_appbuilder.api import BaseApi, expose, protect, safe
from marshmallow import ValidationError

from superset.commands.insurance_commission_audit.run_audit import RunAuditCommand
from superset.extensions import event_logger
from superset.insurance_commission_audit.anomaly_detection import (
    AnomalyDetector,
    TransactionRecord,
)
from superset.insurance_commission_audit.audit_trail import AuditTrailManager
from superset.insurance_commission_audit.compliance_engine import ComplianceEngine
from superset.insurance_commission_audit.risk_scoring import (
    ProducerMetrics,
    RiskScoringEngine,
)
from superset.insurance_commission_audit.workflow import (
    AuditContext,
    AuditWorkflowEngine,
)
from superset.views.base_api import statsd_metrics

logger = logging.getLogger(__name__)


class CommissionAuditIntelligenceApi(BaseApi):
    """Advanced intelligence API for insurance commission auditing."""

    resource_name = "commission_audit_intelligence"
    allow_browser_login = True

    # Singleton instances for stateless engines
    _compliance_engine = ComplianceEngine()
    _anomaly_detector = AnomalyDetector()
    _risk_engine = RiskScoringEngine()
    _workflow_engine = AuditWorkflowEngine()
    _audit_trail = AuditTrailManager()

    @expose("/run_audit", methods=("POST",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.run_audit",
        log_to_statsd=False,
    )
    def run_audit(self) -> Response:
        """Execute a comprehensive automated audit.
        ---
        post:
          summary: Run a full automated commission audit
          description: >
            Executes the complete audit pipeline including compliance
            checks, anomaly detection, risk scoring, and regulatory
            report generation.
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - audit_report
                    - producers
                    - transactions
                  properties:
                    audit_report:
                      type: object
                    producers:
                      type: array
                    transactions:
                      type: array
          responses:
            200:
              description: Audit completed successfully
            400:
              $ref: '#/components/responses/400'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            payload = request.json or {}
            audit_report = payload.get("audit_report", {})
            producers = payload.get("producers", [])
            transactions = payload.get("transactions", [])

            if not audit_report:
                return self.response_400(message="audit_report is required.")
            if not transactions:
                return self.response_400(
                    message="At least one transaction is required."
                )

            command = RunAuditCommand(
                audit_report_data=audit_report,
                producers=producers,
                transactions=transactions,
            )
            result = command.run()
            return self.response(200, result=result)
        except ValueError as ex:
            return self.response_400(message=str(ex))
        except Exception as ex:
            logger.error("Error running audit: %s", str(ex), exc_info=True)
            return self.response(500, message=str(ex))

    @expose("/compliance_check", methods=("POST",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}"
        ".compliance_check",
        log_to_statsd=False,
    )
    def compliance_check(self) -> Response:
        """Run compliance checks on a set of transactions.
        ---
        post:
          summary: Run compliance checks
          description: >
            Validates transactions against state regulatory rate limits,
            license compliance, and chargeback rules.
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - state
                    - transactions
                  properties:
                    state:
                      type: string
                    transactions:
                      type: array
                    producers:
                      type: array
          responses:
            200:
              description: Compliance check completed
            400:
              $ref: '#/components/responses/400'
        """
        try:
            payload = request.json or {}
            state = payload.get("state", "")
            transactions = payload.get("transactions", [])
            producers = payload.get("producers", [])

            if not state or not transactions:
                return self.response_400(
                    message="state and transactions are required."
                )

            violations = []
            producer_map = {p["id"]: p for p in producers}

            for tx in transactions:
                rate_v = self._compliance_engine.check_rate_compliance(
                    transaction_id=tx.get("id", 0),
                    producer_id=tx.get("producer_id", 0),
                    state=state,
                    line_of_business=tx.get("line_of_business", ""),
                    commission_type=tx.get("commission_type", ""),
                    commission_rate=tx.get("commission_rate", 0),
                    premium_amount=tx.get("premium_amount", 0),
                    commission_amount=tx.get("commission_amount", 0),
                    transaction_date=tx.get("transaction_date"),
                )
                violations.extend(rate_v)

                cb_v = self._compliance_engine.check_chargeback_compliance(
                    transaction_id=tx.get("id", 0),
                    producer_id=tx.get("producer_id", 0),
                    is_chargeback=tx.get("is_chargeback", False),
                    chargeback_reason=tx.get("chargeback_reason"),
                    original_transaction_id=tx.get("original_transaction_id"),
                    commission_amount=tx.get("commission_amount", 0),
                )
                violations.extend(cb_v)

            result = {
                "total_transactions": len(transactions),
                "total_violations": len(violations),
                "violations": [
                    {
                        "rule": v.rule_name,
                        "severity": v.severity,
                        "finding_code": v.finding_code,
                        "description": v.description,
                        "transaction_id": v.transaction_id,
                        "producer_id": v.producer_id,
                        "variance_amount": v.variance_amount,
                        "regulation": v.regulation_reference,
                    }
                    for v in violations
                ],
            }
            return self.response(200, result=result)
        except Exception as ex:
            logger.error(
                "Error in compliance check: %s", str(ex), exc_info=True
            )
            return self.response(500, message=str(ex))

    @expose("/anomaly_detection", methods=("POST",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}"
        ".anomaly_detection",
        log_to_statsd=False,
    )
    def anomaly_detection(self) -> Response:
        """Run statistical anomaly detection on transactions.
        ---
        post:
          summary: Run anomaly detection
          description: >
            Analyzes transactions using Z-score outliers, Benford's Law,
            velocity analysis, duplicate detection, round-number analysis,
            and split-transaction detection.
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - transactions
                  properties:
                    transactions:
                      type: array
          responses:
            200:
              description: Anomaly detection completed
            400:
              $ref: '#/components/responses/400'
        """
        try:
            payload = request.json or {}
            raw_transactions = payload.get("transactions", [])

            if not raw_transactions:
                return self.response_400(
                    message="At least one transaction is required."
                )

            from datetime import date as date_type

            records = []
            for tx in raw_transactions:
                td = tx.get("transaction_date")
                if isinstance(td, str):
                    td = date_type.fromisoformat(td)
                elif td is None:
                    td = date_type.today()

                records.append(
                    TransactionRecord(
                        id=tx.get("id", 0),
                        producer_id=tx.get("producer_id", 0),
                        commission_amount=tx.get("commission_amount", 0),
                        commission_rate=tx.get("commission_rate", 0),
                        premium_amount=tx.get("premium_amount", 0),
                        transaction_date=td,
                        policy_number=tx.get("policy_number", ""),
                        line_of_business=tx.get("line_of_business", ""),
                        carrier_name=tx.get("carrier_name", ""),
                        is_chargeback=tx.get("is_chargeback", False),
                    )
                )

            results = self._anomaly_detector.run_all_checks(records)

            return self.response(
                200,
                result={
                    "total_transactions": len(records),
                    "checks": [
                        {
                            "check_name": r.check_name,
                            "score": r.score,
                            "description": r.description,
                            "flagged_count": len(r.flagged_transaction_ids),
                            "flagged_ids": r.flagged_transaction_ids[:100],
                            "details": r.details,
                            "violations_count": len(r.violations),
                        }
                        for r in results
                    ],
                    "total_flagged": len(
                        set(
                            tid
                            for r in results
                            for tid in r.flagged_transaction_ids
                        )
                    ),
                },
            )
        except Exception as ex:
            logger.error(
                "Error in anomaly detection: %s", str(ex), exc_info=True
            )
            return self.response(500, message=str(ex))

    @expose("/risk_score", methods=("POST",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}"
        ".risk_score",
        log_to_statsd=False,
    )
    def risk_score(self) -> Response:
        """Compute risk scores for producers.
        ---
        post:
          summary: Compute producer risk scores
          description: >
            Computes multi-factor risk scores (0-100) for producers
            based on commission rates, volume, chargebacks, license
            status, findings history, and behavioral patterns.
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - producers
                  properties:
                    producers:
                      type: array
          responses:
            200:
              description: Risk scores computed
            400:
              $ref: '#/components/responses/400'
        """
        try:
            payload = request.json or {}
            producer_metrics = payload.get("producers", [])

            if not producer_metrics:
                return self.response_400(
                    message="At least one producer metrics object is required."
                )

            metrics_list = []
            for pm in producer_metrics:
                metrics_list.append(
                    ProducerMetrics(
                        producer_id=pm.get("producer_id", 0),
                        total_transactions=pm.get("total_transactions", 0),
                        total_commission=pm.get("total_commission", 0),
                        total_premium=pm.get("total_premium", 0),
                        avg_commission_rate=pm.get("avg_commission_rate", 0),
                        max_commission_rate=pm.get("max_commission_rate", 0),
                        chargeback_count=pm.get("chargeback_count", 0),
                        chargeback_amount=pm.get("chargeback_amount", 0),
                        unique_carriers=pm.get("unique_carriers", 1),
                        dominant_carrier_pct=pm.get("dominant_carrier_pct", 1.0),
                        license_expired=pm.get("license_expired", False),
                        days_until_license_expiry=pm.get(
                            "days_until_license_expiry"
                        ),
                        open_findings_count=pm.get("open_findings_count", 0),
                        critical_findings_count=pm.get(
                            "critical_findings_count", 0
                        ),
                        high_findings_count=pm.get("high_findings_count", 0),
                        end_of_quarter_pct=pm.get("end_of_quarter_pct", 0),
                        peer_avg_commission_rate=pm.get(
                            "peer_avg_commission_rate", 0
                        ),
                        peer_avg_volume=pm.get("peer_avg_volume", 0),
                        years_of_experience=pm.get("years_of_experience", 5),
                    )
                )

            profiles = self._risk_engine.score_producers(metrics_list)

            return self.response(
                200,
                result={
                    "producers_scored": len(profiles),
                    "profiles": [
                        {
                            "producer_id": p.producer_id,
                            "composite_score": p.composite_score,
                            "risk_tier": p.risk_tier,
                            "recommendations": p.recommendations,
                            "factors": [
                                {
                                    "name": f.name,
                                    "category": f.category,
                                    "raw_score": f.raw_score,
                                    "weight": f.weight,
                                    "weighted_score": f.weighted_score,
                                    "description": f.description,
                                }
                                for f in p.factors
                            ],
                        }
                        for p in profiles
                    ],
                },
            )
        except Exception as ex:
            logger.error("Error computing risk scores: %s", str(ex), exc_info=True)
            return self.response(500, message=str(ex))

    @expose("/workflow/transitions", methods=("GET",))
    @protect()
    @safe
    @statsd_metrics
    def workflow_graph(self) -> Response:
        """Get the complete workflow transition graph.
        ---
        get:
          summary: Get audit workflow graph
          responses:
            200:
              description: Workflow graph
        """
        graph = self._workflow_engine.get_workflow_graph()
        return self.response(200, result=graph)

    @expose("/workflow/transition", methods=("POST",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}"
        ".workflow_transition",
        log_to_statsd=False,
    )
    def workflow_transition(self) -> Response:
        """Execute a workflow state transition.
        ---
        post:
          summary: Execute workflow transition
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - current_status
                    - target_status
                  properties:
                    current_status:
                      type: string
                    target_status:
                      type: string
                    user_role:
                      type: string
                    user_name:
                      type: string
                    context:
                      type: object
          responses:
            200:
              description: Transition result
            400:
              $ref: '#/components/responses/400'
        """
        try:
            payload = request.json or {}
            current = payload.get("current_status", "")
            target = payload.get("target_status", "")

            if not current or not target:
                return self.response_400(
                    message="current_status and target_status are required."
                )

            ctx_data = payload.get("context", {})
            context = AuditContext(
                total_findings=ctx_data.get("total_findings", 0),
                open_findings=ctx_data.get("open_findings", 0),
                critical_findings_unresolved=ctx_data.get(
                    "critical_findings_unresolved", 0
                ),
                has_executive_summary=ctx_data.get("has_executive_summary", False),
                has_recommendations=ctx_data.get("has_recommendations", False),
                has_methodology=ctx_data.get("has_methodology", False),
                total_transactions_examined=ctx_data.get(
                    "total_transactions_examined", 0
                ),
                total_producers_examined=ctx_data.get(
                    "total_producers_examined", 0
                ),
                all_findings_reviewed=ctx_data.get("all_findings_reviewed", False),
            )

            result = self._workflow_engine.transition(
                current_status=current,
                target_status=target,
                user_role=payload.get("user_role"),
                user_name=payload.get("user_name"),
                context=context,
            )

            return self.response(
                200,
                result={
                    "success": result.success,
                    "from_status": result.from_status,
                    "to_status": result.to_status,
                    "message": result.message,
                    "transitioned_at": (
                        result.transitioned_at.isoformat()
                        if result.transitioned_at
                        else None
                    ),
                    "transitioned_by": result.transitioned_by,
                    "validation_errors": result.validation_errors,
                },
            )
        except Exception as ex:
            logger.error(
                "Error in workflow transition: %s", str(ex), exc_info=True
            )
            return self.response(500, message=str(ex))

    @expose("/workflow/allowed_transitions/<string:status>", methods=("GET",))
    @protect()
    @safe
    @statsd_metrics
    def allowed_transitions(self, status: str) -> Response:
        """Get allowed transitions from a given status.
        ---
        get:
          summary: Get allowed transitions from a status
          parameters:
            - in: path
              name: status
              schema:
                type: string
          responses:
            200:
              description: Allowed transitions
        """
        transitions = self._workflow_engine.get_allowed_transitions(status)
        return self.response(
            200,
            result={
                "current_status": status,
                "allowed_transitions": [
                    {
                        "target_status": t.to_status,
                        "requires_approval": t.requires_approval,
                        "required_role": t.required_role,
                        "description": t.description,
                    }
                    for t in transitions
                ],
            },
        )

    @expose("/rate_limits/<string:state>", methods=("GET",))
    @protect()
    @safe
    @statsd_metrics
    def rate_limits(self, state: str) -> Response:
        """Get regulatory rate limits for a state.
        ---
        get:
          summary: Get state rate limits
          parameters:
            - in: path
              name: state
              schema:
                type: string
          responses:
            200:
              description: Rate limits
        """
        from superset.insurance_commission_audit.compliance_engine import (
            STATE_RATE_LIMITS,
        )

        state_limits = STATE_RATE_LIMITS.get(state, {})
        default_limits = STATE_RATE_LIMITS.get("__default__", {})

        result: dict[str, dict[str, dict[str, Any]]] = {}
        all_lobs = set(list(state_limits.keys()) + list(default_limits.keys()))

        for lob in all_lobs:
            result[lob] = {}
            lob_state = state_limits.get(lob, {})
            lob_default = default_limits.get(lob, {})
            all_types = set(list(lob_state.keys()) + list(lob_default.keys()))

            for ct in all_types:
                limit = lob_state.get(ct) or lob_default.get(ct)
                if limit:
                    result[lob][ct] = {
                        "max_rate": limit.max_rate,
                        "regulation_citation": limit.regulation_citation,
                        "notes": limit.notes,
                        "is_state_specific": ct in lob_state,
                    }

        return self.response(
            200,
            result={"state": state, "rate_limits": result},
        )
