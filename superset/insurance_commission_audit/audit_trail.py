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
"""Immutable audit trail for complete change history tracking.

Records every significant action taken on audit entities with
cryptographic integrity verification through hash chains.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AuditTrailEntry:
    """A single immutable entry in the audit trail."""

    entity_type: str  # "producer", "transaction", "audit_report", "finding"
    entity_id: int
    action: str  # "created", "updated", "deleted", "status_changed", etc.
    timestamp: str
    user_id: int | None = None
    user_name: str | None = None
    changes: dict[str, Any] = field(default_factory=dict)
    previous_values: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    entry_hash: str = ""
    previous_hash: str = ""

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this entry's content for integrity verification."""
        content = {
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "action": self.action,
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "changes": self.changes,
            "previous_values": self.previous_values,
            "previous_hash": self.previous_hash,
        }
        content_str = json.dumps(content, sort_keys=True, default=str)
        return hashlib.sha256(content_str.encode()).hexdigest()


class AuditTrailManager:
    """Manages an append-only audit trail with hash chain integrity."""

    def __init__(self) -> None:
        self._entries: list[AuditTrailEntry] = []
        self._last_hash: str = "GENESIS"

    @property
    def entries(self) -> list[AuditTrailEntry]:
        return list(self._entries)

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def record(
        self,
        entity_type: str,
        entity_id: int,
        action: str,
        user_id: int | None = None,
        user_name: str | None = None,
        changes: dict[str, Any] | None = None,
        previous_values: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditTrailEntry:
        """Record a new audit trail entry with hash chain linking."""
        entry = AuditTrailEntry(
            entity_type=entity_type,
            entity_id=entity_id,
            action=action,
            timestamp=datetime.utcnow().isoformat(),
            user_id=user_id,
            user_name=user_name,
            changes=changes or {},
            previous_values=previous_values or {},
            metadata=metadata or {},
            previous_hash=self._last_hash,
        )
        entry.entry_hash = entry.compute_hash()
        self._last_hash = entry.entry_hash
        self._entries.append(entry)

        logger.info(
            "Audit trail: %s %s #%d by %s [%s]",
            action,
            entity_type,
            entity_id,
            user_name or "system",
            entry.entry_hash[:12],
        )
        return entry

    def record_creation(
        self,
        entity_type: str,
        entity_id: int,
        data: dict[str, Any],
        user_id: int | None = None,
        user_name: str | None = None,
    ) -> AuditTrailEntry:
        """Record entity creation."""
        return self.record(
            entity_type=entity_type,
            entity_id=entity_id,
            action="created",
            user_id=user_id,
            user_name=user_name,
            changes=data,
        )

    def record_update(
        self,
        entity_type: str,
        entity_id: int,
        changes: dict[str, Any],
        previous_values: dict[str, Any],
        user_id: int | None = None,
        user_name: str | None = None,
    ) -> AuditTrailEntry:
        """Record entity update with before/after values."""
        return self.record(
            entity_type=entity_type,
            entity_id=entity_id,
            action="updated",
            user_id=user_id,
            user_name=user_name,
            changes=changes,
            previous_values=previous_values,
        )

    def record_status_change(
        self,
        entity_type: str,
        entity_id: int,
        old_status: str,
        new_status: str,
        user_id: int | None = None,
        user_name: str | None = None,
        reason: str | None = None,
    ) -> AuditTrailEntry:
        """Record a workflow status change."""
        return self.record(
            entity_type=entity_type,
            entity_id=entity_id,
            action="status_changed",
            user_id=user_id,
            user_name=user_name,
            changes={"status": new_status},
            previous_values={"status": old_status},
            metadata={"reason": reason} if reason else {},
        )

    def record_compliance_check(
        self,
        entity_type: str,
        entity_id: int,
        check_type: str,
        violations_found: int,
        user_id: int | None = None,
        user_name: str | None = None,
    ) -> AuditTrailEntry:
        """Record that a compliance check was performed."""
        return self.record(
            entity_type=entity_type,
            entity_id=entity_id,
            action="compliance_check",
            user_id=user_id,
            user_name=user_name,
            metadata={
                "check_type": check_type,
                "violations_found": violations_found,
            },
        )

    def verify_integrity(self) -> tuple[bool, list[str]]:
        """Verify the hash chain integrity of the entire audit trail."""
        errors: list[str] = []

        if not self._entries:
            return True, []

        expected_prev = "GENESIS"
        for i, entry in enumerate(self._entries):
            if entry.previous_hash != expected_prev:
                errors.append(
                    f"Entry {i} ({entry.entity_type} #{entry.entity_id}): "
                    f"Previous hash mismatch. Expected '{expected_prev[:12]}...', "
                    f"got '{entry.previous_hash[:12]}...'."
                )

            recomputed = entry.compute_hash()
            if entry.entry_hash != recomputed:
                errors.append(
                    f"Entry {i} ({entry.entity_type} #{entry.entity_id}): "
                    f"Content hash mismatch. Entry may have been tampered with. "
                    f"Stored: '{entry.entry_hash[:12]}...', "
                    f"Computed: '{recomputed[:12]}...'."
                )

            expected_prev = entry.entry_hash

        return len(errors) == 0, errors

    def get_entity_history(
        self, entity_type: str, entity_id: int
    ) -> list[AuditTrailEntry]:
        """Get all audit trail entries for a specific entity."""
        return [
            e
            for e in self._entries
            if e.entity_type == entity_type and e.entity_id == entity_id
        ]

    def get_user_activity(self, user_id: int) -> list[AuditTrailEntry]:
        """Get all audit trail entries for a specific user."""
        return [e for e in self._entries if e.user_id == user_id]

    def get_entries_by_action(self, action: str) -> list[AuditTrailEntry]:
        """Get all entries of a specific action type."""
        return [e for e in self._entries if e.action == action]

    def get_entries_in_range(
        self, start: datetime, end: datetime
    ) -> list[AuditTrailEntry]:
        """Get entries within a datetime range."""
        start_iso = start.isoformat()
        end_iso = end.isoformat()
        return [
            e
            for e in self._entries
            if start_iso <= e.timestamp <= end_iso
        ]

    def export_trail(self) -> list[dict[str, Any]]:
        """Export the complete audit trail as serializable dicts."""
        return [asdict(e) for e in self._entries]

    def get_summary(self) -> dict[str, Any]:
        """Get summary statistics of the audit trail."""
        action_counts: dict[str, int] = {}
        entity_counts: dict[str, int] = {}
        user_counts: dict[str, int] = {}

        for entry in self._entries:
            action_counts[entry.action] = action_counts.get(entry.action, 0) + 1
            entity_counts[entry.entity_type] = (
                entity_counts.get(entry.entity_type, 0) + 1
            )
            if entry.user_name:
                user_counts[entry.user_name] = (
                    user_counts.get(entry.user_name, 0) + 1
                )

        is_valid, errors = self.verify_integrity()

        return {
            "total_entries": len(self._entries),
            "actions": action_counts,
            "entities": entity_counts,
            "users": user_counts,
            "integrity_valid": is_valid,
            "integrity_errors": len(errors),
            "first_entry": self._entries[0].timestamp if self._entries else None,
            "last_entry": self._entries[-1].timestamp if self._entries else None,
        }
