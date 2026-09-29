"""Short-lived state used by stateful detection rules."""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import Lock


@dataclass
class FailureWindow:
    events: deque[tuple[datetime, str]]
    alerted: bool = False


@dataclass
class UniqueValueWindow:
    events: deque[tuple[datetime, str, int]]
    alerted: bool = False


class DetectionState:
    """In-process sliding-window state for the first detector implementation.

    Redis-backed state should replace this when the API runs with multiple workers.
    """

    def __init__(self) -> None:
        self._windows: dict[str, FailureWindow] = {}
        self._unique_windows: dict[str, UniqueValueWindow] = {}
        self._lock = Lock()

    def add_failure(
        self, *, key: str, event_id: str, occurred_at: datetime, window_seconds: int, threshold: int
    ) -> tuple[list[str], bool]:
        cutoff = occurred_at - timedelta(seconds=window_seconds)
        with self._lock:
            state = self._windows.setdefault(key, FailureWindow(events=deque()))
            while state.events and state.events[0][0] < cutoff:
                state.events.popleft()
            was_alerted = state.alerted
            state.events.append((occurred_at, event_id))
            is_threshold_met = len(state.events) >= threshold
            state.alerted = is_threshold_met
            if not is_threshold_met:
                state.alerted = False
            return [event_id for _, event_id in state.events], is_threshold_met and not was_alerted

    def add_unique_value(
        self,
        *,
        key: str,
        event_id: str,
        value: int,
        occurred_at: datetime,
        window_seconds: int,
        threshold: int,
    ) -> tuple[list[str], list[int], bool]:
        cutoff = occurred_at - timedelta(seconds=window_seconds)
        with self._lock:
            state = self._unique_windows.setdefault(key, UniqueValueWindow(events=deque()))
            while state.events and state.events[0][0] < cutoff:
                state.events.popleft()

            was_alerted = state.alerted
            state.events.append((occurred_at, event_id, value))
            unique_values = sorted({port for _, _, port in state.events})
            is_threshold_met = len(unique_values) >= threshold
            state.alerted = is_threshold_met
            if not is_threshold_met:
                state.alerted = False

            event_ids = [event_id for _, event_id, port in state.events if port in unique_values]
            return event_ids, unique_values, is_threshold_met and not was_alerted


state = DetectionState()
