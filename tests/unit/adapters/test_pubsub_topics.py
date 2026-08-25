"""Unit tests for Pub/Sub event routing and canonical dotted topic naming."""

from datetime import UTC, datetime
from typing import Any

import pytest
from delegation_fabric_adapters.pubsub import PubSubEventPublisher, _topic_suffix
from delegation_fabric_core.models.event import EventEnvelope, EventType

CANONICAL_TOPICS = frozenset(
    {
        "delegation_fabric.tasks",
        "delegation_fabric.approvals",
        "delegation_fabric.webhooks",
    }
)


def _envelope(event_type: EventType) -> EventEnvelope:
    return EventEnvelope(
        event_id=f"evt_{event_type.value}",
        event_type=event_type,
        source="control-plane",
        task_id="task_routingtest",
        occurred_at=datetime.now(UTC),
    )


class _CompletedFuture:
    def result(self, timeout: float | None = None) -> str:
        return "msg-id"


class _RecordingPublisherClient:
    """Minimal stand-in for pubsub_v1.PublisherClient (no GCP deps needed)."""

    def __init__(self) -> None:
        self.published: dict[str, list[bytes]] = {}

    def topic_path(self, project_id: str, topic_id: str) -> str:
        return f"projects/{project_id}/topics/{topic_id}"

    def publish(self, topic_path: str, data: bytes) -> Any:
        self.published.setdefault(topic_path, []).append(data)
        return _CompletedFuture()


@pytest.mark.parametrize("event_type", list(EventType))
def test_every_event_type_routes_to_a_canonical_topic_suffix(event_type: EventType) -> None:
    assert f"delegation_fabric.{_topic_suffix(event_type)}" in CANONICAL_TOPICS


async def test_publisher_routes_to_exactly_the_three_dotted_canonical_topics() -> None:
    client = _RecordingPublisherClient()
    publisher = PubSubEventPublisher("proj-routing-test")
    publisher._client = client

    for event_type in EventType:
        await publisher.publish(_envelope(event_type))

    expected_paths = {f"projects/proj-routing-test/topics/{t}" for t in CANONICAL_TOPICS}
    assert set(client.published) == expected_paths
