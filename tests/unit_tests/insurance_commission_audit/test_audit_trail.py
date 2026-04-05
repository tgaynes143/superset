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
"""Tests for the audit trail manager."""

from __future__ import annotations

from superset.insurance_commission_audit.audit_trail import AuditTrailManager


def test_record_and_retrieve() -> None:
    trail = AuditTrailManager()
    trail.record(
        entity_type="producer",
        entity_id=1,
        action="created",
        user_name="admin",
        changes={"name": "John Smith"},
    )
    assert trail.entry_count == 1
    assert trail.entries[0].entity_type == "producer"
    assert trail.entries[0].action == "created"


def test_hash_chain_integrity() -> None:
    trail = AuditTrailManager()
    trail.record(entity_type="producer", entity_id=1, action="created")
    trail.record(entity_type="producer", entity_id=1, action="updated")
    trail.record(entity_type="transaction", entity_id=5, action="created")

    is_valid, errors = trail.verify_integrity()
    assert is_valid is True
    assert len(errors) == 0


def test_tamper_detection() -> None:
    trail = AuditTrailManager()
    trail.record(entity_type="producer", entity_id=1, action="created")
    trail.record(entity_type="producer", entity_id=1, action="updated")

    # Tamper with an entry
    trail._entries[0].changes = {"tampered": True}

    is_valid, errors = trail.verify_integrity()
    assert is_valid is False
    assert len(errors) > 0


def test_entity_history() -> None:
    trail = AuditTrailManager()
    trail.record(entity_type="producer", entity_id=1, action="created")
    trail.record(entity_type="transaction", entity_id=5, action="created")
    trail.record(entity_type="producer", entity_id=1, action="updated")

    history = trail.get_entity_history("producer", 1)
    assert len(history) == 2


def test_user_activity() -> None:
    trail = AuditTrailManager()
    trail.record(entity_type="producer", entity_id=1, action="created", user_id=10)
    trail.record(entity_type="producer", entity_id=2, action="created", user_id=20)
    trail.record(entity_type="producer", entity_id=3, action="updated", user_id=10)

    activity = trail.get_user_activity(10)
    assert len(activity) == 2


def test_record_status_change() -> None:
    trail = AuditTrailManager()
    entry = trail.record_status_change(
        entity_type="audit_report",
        entity_id=1,
        old_status="draft",
        new_status="in_progress",
        user_name="examiner",
        reason="Starting examination",
    )
    assert entry.action == "status_changed"
    assert entry.changes["status"] == "in_progress"
    assert entry.previous_values["status"] == "draft"
    assert entry.metadata["reason"] == "Starting examination"


def test_record_compliance_check() -> None:
    trail = AuditTrailManager()
    entry = trail.record_compliance_check(
        entity_type="audit_report",
        entity_id=1,
        check_type="rate_compliance",
        violations_found=5,
    )
    assert entry.action == "compliance_check"
    assert entry.metadata["violations_found"] == 5


def test_export_trail() -> None:
    trail = AuditTrailManager()
    trail.record(entity_type="producer", entity_id=1, action="created")
    trail.record(entity_type="producer", entity_id=1, action="updated")

    exported = trail.export_trail()
    assert len(exported) == 2
    assert isinstance(exported[0], dict)
    assert "entry_hash" in exported[0]


def test_summary() -> None:
    trail = AuditTrailManager()
    trail.record(entity_type="producer", entity_id=1, action="created", user_name="admin")
    trail.record(entity_type="transaction", entity_id=1, action="created", user_name="admin")
    trail.record(entity_type="producer", entity_id=1, action="updated", user_name="editor")

    summary = trail.get_summary()
    assert summary["total_entries"] == 3
    assert summary["actions"]["created"] == 2
    assert summary["actions"]["updated"] == 1
    assert summary["entities"]["producer"] == 2
    assert summary["users"]["admin"] == 2
    assert summary["integrity_valid"] is True


def test_genesis_hash() -> None:
    trail = AuditTrailManager()
    trail.record(entity_type="test", entity_id=1, action="test")
    assert trail.entries[0].previous_hash == "GENESIS"


def test_entries_by_action() -> None:
    trail = AuditTrailManager()
    trail.record(entity_type="a", entity_id=1, action="created")
    trail.record(entity_type="b", entity_id=2, action="updated")
    trail.record(entity_type="c", entity_id=3, action="created")

    created = trail.get_entries_by_action("created")
    assert len(created) == 2
