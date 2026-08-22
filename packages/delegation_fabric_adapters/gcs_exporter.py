"""Audit chain retention export (PLAN.md Day 7 / P1 — Cloud Storage).

Exports a task's hash-chained audit events as canonical JSONL for immutable
retention. Falls back to a logging exporter when no bucket is configured.
"""

from __future__ import annotations

import os
from typing import Any, Protocol

from delegation_fabric_core.audit.chain import canonical_json
from delegation_fabric_core.models.audit import AuditEvent


class AuditExporter(Protocol):
    async def export_chain(self, task_id: str, events: list[AuditEvent]) -> str:
        """Export events; returns a URI identifying the exported artifact."""
        ...


class LoggingAuditExporter:
    """Default local exporter — logs the export instead of writing storage."""

    def __init__(self) -> None:
        self.name = "logging"

    async def export_chain(self, task_id: str, events: list[AuditEvent]) -> str:
        return f"local://audit-exports/{task_id}.jsonl ({len(events)} events, not persisted)"


class GCSAuditExporter:
    def __init__(self, bucket_name: str, prefix: str = "audit-exports") -> None:
        self.bucket_name = bucket_name
        self.prefix = prefix
        self.name = f"gcs:{bucket_name}"

    async def export_chain(self, task_id: str, events: list[AuditEvent]) -> str:
        import asyncio

        # Refuse to archive a broken chain: retention artifacts must be trustworthy.
        from delegation_fabric_core.audit.chain import verify_audit_chain

        verification = verify_audit_chain(events)
        if not verification.valid:
            raise ValueError(
                f"Refusing export for {task_id!r}: audit chain invalid ({verification.reason})"
            )
        status_tag = "valid"

        object_name = f"{self.prefix}/{task_id}.{status_tag}.{len(events):06d}.jsonl"
        payload = "\n".join(canonical_json(e.model_dump(mode="json")) for e in events)

        def _upload() -> str:
            from google.cloud import storage  # type: ignore[attr-defined]  # lazy import

            client: Any = storage.Client()
            bucket = client.bucket(self.bucket_name)
            blob = bucket.blob(object_name)
            blob.upload_from_string(payload, content_type="application/x-ndjson")
            return f"gs://{self.bucket_name}/{object_name}"

        return await asyncio.to_thread(_upload)


def create_audit_exporter_from_env() -> AuditExporter:
    bucket = os.environ.get("DF_AUDIT_EXPORT_BUCKET")
    if bucket:
        return GCSAuditExporter(bucket)
    return LoggingAuditExporter()


__all__ = [
    "AuditExporter",
    "GCSAuditExporter",
    "LoggingAuditExporter",
    "create_audit_exporter_from_env",
]
