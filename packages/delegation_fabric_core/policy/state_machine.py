"""Deterministic task state machine.

Pure function transition:
transition(current: TaskState, event: TaskEvent) -> TaskState

Allowed transitions from RUNTIME_WORKFLOWS.md:
- created + initial_invocation -> running
- running + approval_required -> awaiting_approval
- running + webhook_pending -> awaiting_webhook
- running + terminal_success -> completed
- running + terminal_failure -> failed
- running + security_event -> quarantined
- awaiting_approval + approval_received -> resuming
- awaiting_webhook + webhook_received -> resuming
- resuming + runtime_restored -> running
- resuming + resume_failed -> failed
- quarantined + human_released -> resuming
- any non-terminal + cancellation -> cancelled
"""

from __future__ import annotations

from delegation_fabric_core.errors.exceptions import InvalidTransitionError
from delegation_fabric_core.models.task import TaskEvent, TaskState

# Explicit transition table: (from_state, event) -> to_state
VALID_TRANSITIONS: dict[tuple[TaskState, TaskEvent], TaskState] = {
    (TaskState.CREATED, TaskEvent.INITIAL_INVOCATION): TaskState.RUNNING,
    (TaskState.RUNNING, TaskEvent.APPROVAL_REQUIRED): TaskState.AWAITING_APPROVAL,
    (TaskState.RUNNING, TaskEvent.WEBHOOK_PENDING): TaskState.AWAITING_WEBHOOK,
    (TaskState.RUNNING, TaskEvent.TERMINAL_SUCCESS): TaskState.COMPLETED,
    (TaskState.RUNNING, TaskEvent.TERMINAL_FAILURE): TaskState.FAILED,
    (TaskState.RUNNING, TaskEvent.SECURITY_EVENT): TaskState.QUARANTINED,
    (TaskState.AWAITING_APPROVAL, TaskEvent.APPROVAL_RECEIVED): TaskState.RESUMING,
    (TaskState.AWAITING_WEBHOOK, TaskEvent.WEBHOOK_RECEIVED): TaskState.RESUMING,
    (TaskState.RESUMING, TaskEvent.RUNTIME_RESTORED): TaskState.RUNNING,
    (TaskState.RESUMING, TaskEvent.RESUME_FAILED): TaskState.FAILED,
    (TaskState.QUARANTINED, TaskEvent.HUMAN_RELEASED): TaskState.RESUMING,
}


def transition(current: TaskState, event: TaskEvent) -> TaskState:
    """Execute pure state transition. Denies closed on invalid transition."""
    # Cancellation can happen from any non-terminal state
    if event == TaskEvent.CANCELLATION:
        if not current.is_terminal():
            return TaskState.CANCELLED
        raise InvalidTransitionError(current.value, event.value)

    key = (current, event)
    if key in VALID_TRANSITIONS:
        return VALID_TRANSITIONS[key]

    raise InvalidTransitionError(current.value, event.value)
