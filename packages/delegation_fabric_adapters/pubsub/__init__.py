"""Event publishers for Delegation Fabric (Pub/Sub and logging backends)."""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import json
import logging
import os
from typing import Any, Protocol

from delegation_fabric_core.models.event import EventEnvelope, EventType

logger = logging.getLogger(__name__)

_TOPIC_BY_EVENT_TYPE: dict[EventType, str] = {
    EventType.TASK_START: "tasks",
    EventType.TASK_RELEASE: "tasks",
    EventType.TASK_CANCEL: "tasks",
    EventType.APPROVAL_CREATED: "approvals",
    EventType.APPROVAL_REJECTED: "approvals",
}


def _topic_suffix(event_type: EventType) -> str:
    if event_type.value.startswith("external.settlement"):
        return "webhooks"
    suffix = _TOPIC_BY_EVENT_TYPE.get(event_type)
    if suffix is None:
        msg = f"No topic mapping for event type {event_type.value!r}"
        raise ValueError(msg)
    return suffix


class EventPublisher(Protocol):
    async def publish(self, envelope: EventEnvelope) -> None:
        """Publish an event envelope."""
        ...


class LoggingEventPublisher:
    """Local/no-op publisher that logs the canonical JSON envelope."""

    async def publish(self, envelope: EventEnvelope) -> None:
        logger.info("event %s", json.dumps(envelope.model_dump(mode="json")))


class PubSubEventPublisher:
    """Publishes envelopes to topic f'{topic_prefix}.{suffix}' in a GCP project.

    The google-cloud-pubsub client is imported lazily so this module can be
    imported without credentials installed.
    """

    def __init__(self, project_id: str, topic_prefix: str = "delegation_fabric") -> None:
        self.project_id = project_id
        self.topic_prefix = topic_prefix
        self._client: Any | None = None
        self._topic_paths: dict[str, str] = {}

    def _ensure_client(self) -> Any:
        if self._client is None:
            from google.cloud import pubsub_v1  # type: ignore[attr-defined]

            self._client = pubsub_v1.PublisherClient()
        return self._client

    def _topic_path(self, suffix: str) -> str:
        topic_id = f"{self.topic_prefix}.{suffix}"
        if topic_id not in self._topic_paths:
            self._topic_paths[topic_id] = self._ensure_client().topic_path(
                self.project_id, topic_id
            )
        return self._topic_paths[topic_id]

    async def publish(self, envelope: EventEnvelope) -> None:
        client = self._ensure_client()
        topic_path = self._topic_path(_topic_suffix(envelope.event_type))
        canonical_json = json.dumps(envelope.model_dump(mode="json"), separators=(",", ":"))
        data = base64.b64encode(canonical_json.encode("utf-8"))
        future = client.publish(topic_path, data=data)
        # Await delivery off the event loop; a failed publish must surface to
        # the caller rather than silently dropping a workflow event.
        try:
            await asyncio.to_thread(future.result, timeout=30.0)
        except concurrent.futures.TimeoutError as e:
            raise RuntimeError(f"Pub/Sub publish timed out for {topic_path}") from e


def create_publisher_from_env() -> EventPublisher:
    """Build an EventPublisher from DF_PUBSUB_PROJECT/GOOGLE_CLOUD_PROJECT/DF_ENV."""
    project_id = os.environ.get("DF_PUBSUB_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
    if project_id and os.environ.get("DF_ENV") != "local":
        return PubSubEventPublisher(project_id)
    return LoggingEventPublisher()


__all__ = [
    "EventPublisher",
    "LoggingEventPublisher",
    "PubSubEventPublisher",
    "create_publisher_from_env",
]
