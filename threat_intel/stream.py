"""Server-Sent Events (SSE) live streaming engine for VIGIL Threat Intelligence."""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
import uuid
from typing import Dict, Generator, Optional, Set

from threat_intel.models import StreamEvent, utc_now_iso

logger = logging.getLogger("threat_intel.stream")


class ThreatStreamBroadcaster:
    """Thread-safe event broadcaster managing SSE subscriber queues and reconnection cursors."""

    def __init__(self):
        self._lock = threading.Lock()
        self._subscribers: Dict[str, queue.Queue] = {}
        self._event_counter = 0

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def subscribe(self, client_id: Optional[str] = None) -> Tuple[str, queue.Queue]:
        """Register a new SSE client stream queue."""
        cid = client_id or str(uuid.uuid4())
        q: queue.Queue = queue.Queue(maxsize=500)
        with self._lock:
            self._subscribers[cid] = q
        logger.info("SSE client %s connected (total: %d)", cid, self.client_count)
        return cid, q

    def unsubscribe(self, client_id: str) -> None:
        """Unregister a disconnected SSE client."""
        with self._lock:
            self._subscribers.pop(client_id, None)
        logger.info("SSE client %s disconnected (remaining: %d)", client_id, self.client_count)

    def broadcast(self, event: StreamEvent) -> int:
        """Push a stream event to all currently connected subscriber queues."""
        with self._lock:
            self._event_counter += 1
            if not event.event_id:
                event.event_id = str(self._event_counter)
            subscribers = list(self._subscribers.items())

        delivered = 0
        dead_clients = set()

        for cid, q in subscribers:
            try:
                q.put_nowait(event)
                delivered += 1
            except queue.Full:
                logger.warning("Subscriber queue %s full; dropping event to protect backpressure", cid)
            except Exception:
                dead_clients.add(cid)

        if dead_clients:
            with self._lock:
                for cid in dead_clients:
                    self._subscribers.pop(cid, None)

        return delivered

    def sse_event_generator(
        self,
        client_id: str,
        q: queue.Queue,
        initial_events: Optional[list[StreamEvent]] = None,
        ping_interval_seconds: float = 15.0,
    ) -> Generator[str, None, None]:
        """Generate formatted SSE text stream with automatic ping keepalives."""
        try:
            # Yield connection acknowledged event
            connect_data = json.dumps({
                "status": "connected",
                "client_id": client_id,
                "server_time": utc_now_iso(),
            })
            yield f"event: connect\ndata: {connect_data}\n\n"

            # Replay any initial/catch-up events if requested
            if initial_events:
                for ev in initial_events:
                    yield f"id: {ev.event_id}\nevent: {ev.event_type}\ndata: {json.dumps(ev.to_dict())}\n\n"

            last_ping = time.time()
            while True:
                try:
                    # Timeout after 2.0 seconds so we can check ping interval
                    event: StreamEvent = q.get(timeout=2.0)
                    yield f"id: {event.event_id}\nevent: {event.event_type}\ndata: {json.dumps(event.to_dict())}\n\n"
                except queue.Empty:
                    # Check if keepalive ping is due
                    if time.time() - last_ping >= ping_interval_seconds:
                        yield f": ping {utc_now_iso()}\n\n"
                        last_ping = time.time()
        except GeneratorExit:
            pass
        finally:
            self.unsubscribe(client_id)

