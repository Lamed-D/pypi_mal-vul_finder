import asyncio
from collections import defaultdict
from typing import Any, Dict, Set


class EventManager:
    """Simple per-session pub/sub manager for server-sent events."""

    def __init__(self) -> None:
        self._subscribers: Dict[str, Set[asyncio.Queue]] = defaultdict(set)
        self._last_event: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def subscribe(self, session_id: str) -> asyncio.Queue:
        """Register a new subscriber for a session and return its queue."""
        queue: asyncio.Queue = asyncio.Queue()
        async with self._lock:
            self._subscribers[session_id].add(queue)
            last_event = self._last_event.get(session_id)
        if last_event:
            await queue.put(last_event)
        return queue

    async def unsubscribe(self, session_id: str, queue: asyncio.Queue) -> None:
        """Remove a subscriber queue when the client disconnects."""
        async with self._lock:
            subscribers = self._subscribers.get(session_id)
            if not subscribers:
                return
            subscribers.discard(queue)
            if not subscribers:
                self._subscribers.pop(session_id, None)
                # Keep the last event for a short-lived reconnection window.

    async def publish(self, session_id: str, event: str, data: Dict[str, Any]) -> None:
        """Send an event to all subscribers of the session."""
        payload = {"event": event, "data": data}
        async with self._lock:
            self._last_event[session_id] = payload
            subscribers = list(self._subscribers.get(session_id, set()))
        if not subscribers:
            return
        for queue in subscribers:
            await queue.put(payload)

    async def clear_last_event(self, session_id: str) -> None:
        """Forget the cached event for a session."""
        async with self._lock:
            self._last_event.pop(session_id, None)
