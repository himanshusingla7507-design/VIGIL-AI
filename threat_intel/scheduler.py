"""Background worker scheduler running periodic threat intelligence ingestion."""
from __future__ import annotations

import logging
import threading
import time
from typing import Dict, List, Optional

from threat_intel.pipeline import ThreatIntelPipeline
from threat_intel.providers import get_default_providers
from threat_intel.providers.base import BaseThreatProvider

logger = logging.getLogger("threat_intel.scheduler")


class ThreatIngestionScheduler:
    """Managed background worker executing provider syncs on documented cadences."""

    def __init__(
        self,
        pipeline: ThreatIntelPipeline,
        providers: Optional[List[BaseThreatProvider]] = None,
        poll_interval_seconds: float = 10.0,
    ):
        self.pipeline = pipeline
        self.providers = providers if providers is not None else get_default_providers()
        self.poll_interval_seconds = poll_interval_seconds

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._next_runs: Dict[str, float] = {}
        self._lock = threading.Lock()

    def start(self, initial_sync: bool = True) -> None:
        """Start the background ingestion scheduler loop."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                logger.info("Scheduler already running")
                return

            self._stop_event.clear()
            # Initialize next run times
            now = time.time()
            for p in self.providers:
                # Stagger initial runs slightly or run immediately
                self._next_runs[p.provider_id] = now if initial_sync else now + p.update_cadence_seconds

            self._thread = threading.Thread(
                target=self._worker_loop,
                name="VIGIL-ThreatIngestionWorker",
                daemon=True,
            )
            self._thread.start()
            logger.info("Threat ingestion scheduler worker started with %d providers", len(self.providers))

    def stop(self, timeout: float = 5.0) -> None:
        """Signal background worker to stop gracefully."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            logger.info("Threat ingestion scheduler stopped")

    def trigger_all_sync(self, limit: int = 150) -> List[Dict[str, Any]]:
        """Trigger an immediate sync of all configured providers."""
        results = []
        for p in self.providers:
            res = self.pipeline.sync_provider(p, limit=limit)
            with self._lock:
                self._next_runs[p.provider_id] = time.time() + p.update_cadence_seconds
            results.append(res)
        return results

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            now = time.time()
            for p in self.providers:
                if self._stop_event.is_set():
                    break

                with self._lock:
                    next_run = self._next_runs.get(p.provider_id, 0)

                if now >= next_run and p.is_enabled and p.is_configured:
                    try:
                        self.pipeline.sync_provider(p)
                    except Exception as exc:
                        logger.error("Error in scheduled sync for %s: %s", p.provider_id, exc)
                    finally:
                        with self._lock:
                            self._next_runs[p.provider_id] = time.time() + p.update_cadence_seconds

            # Sleep in small increments for responsive shutdown
            self._stop_event.wait(self.poll_interval_seconds)

