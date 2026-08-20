"""Unit tests for task state machine transitions."""

import pytest
from delegation_fabric_core.errors.exceptions import InvalidTransitionError
from delegation_fabric_core.models.task import TaskEvent, TaskState
from delegation_fabric_core.policy.state_machine import transition


@pytest.mark.parametrize(
    "from_state,event,expected_to",
    [
        (TaskState.CREATED, TaskEvent.INITIAL_INVOCATION, TaskState.RUNNING),
        (TaskState.RUNNING, TaskEvent.APPROVAL_REQUIRED, TaskState.AWAITING_APPROVAL),
        (TaskState.RUNNING, TaskEvent.WEBHOOK_PENDING, TaskState.AWAITING_WEBHOOK),
        (TaskState.RUNNING, TaskEvent.TERMINAL_SUCCESS, TaskState.COMPLETED),
        (TaskState.RUNNING, TaskEvent.TERMINAL_FAILURE, TaskState.FAILED),
        (TaskState.RUNNING, TaskEvent.SECURITY_EVENT, TaskState.QUARANTINED),
        (TaskState.AWAITING_APPROVAL, TaskEvent.APPROVAL_RECEIVED, TaskState.RESUMING),
        (TaskState.AWAITING_WEBHOOK, TaskEvent.WEBHOOK_RECEIVED, TaskState.RESUMING),
        (TaskState.RESUMING, TaskEvent.RUNTIME_RESTORED, TaskState.RUNNING),
        (TaskState.RESUMING, TaskEvent.RESUME_FAILED, TaskState.FAILED),
        (TaskState.QUARANTINED, TaskEvent.HUMAN_RELEASED, TaskState.RESUMING),
        # Cancellation from various non-terminal states
        (TaskState.CREATED, TaskEvent.CANCELLATION, TaskState.CANCELLED),
        (TaskState.RUNNING, TaskEvent.CANCELLATION, TaskState.CANCELLED),
        (TaskState.AWAITING_APPROVAL, TaskEvent.CANCELLATION, TaskState.CANCELLED),
        (TaskState.AWAITING_WEBHOOK, TaskEvent.CANCELLATION, TaskState.CANCELLED),
        (TaskState.RESUMING, TaskEvent.CANCELLATION, TaskState.CANCELLED),
        (TaskState.QUARANTINED, TaskEvent.CANCELLATION, TaskState.CANCELLED),
    ],
)
def test_valid_state_transitions(from_state, event, expected_to):
    next_state = transition(from_state, event)
    assert next_state == expected_to


@pytest.mark.parametrize(
    "from_state,event",
    [
        # Terminal states cannot transition or cancel
        (TaskState.COMPLETED, TaskEvent.CANCELLATION),
        (TaskState.FAILED, TaskEvent.CANCELLATION),
        (TaskState.CANCELLED, TaskEvent.CANCELLATION),
        (TaskState.COMPLETED, TaskEvent.INITIAL_INVOCATION),
        # Invalid direct jumps
        (TaskState.CREATED, TaskEvent.APPROVAL_REQUIRED),
        (TaskState.AWAITING_APPROVAL, TaskEvent.TERMINAL_SUCCESS),
        (TaskState.QUARANTINED, TaskEvent.RUNTIME_RESTORED),
    ],
)
def test_invalid_state_transitions(from_state, event):
    with pytest.raises(InvalidTransitionError):
        transition(from_state, event)
