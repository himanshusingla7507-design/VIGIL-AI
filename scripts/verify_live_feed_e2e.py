"""End-to-End Live Verification of VIGIL Threat Intelligence Stream."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from urllib import request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from threat_intel import (
    get_threat_broadcaster,
    get_threat_pipeline,
    get_threat_storage,
)


def run_e2e_verification():
    print("==================================================")
    print("VIGIL LIVE THREAT INTEL STREAM — E2E VERIFICATION")
    print("==================================================")

    storage = get_threat_storage()
    broadcaster = get_threat_broadcaster()
    pipeline = get_threat_pipeline()

    # 1. Connect Client A via SSE queue
    client_a_id, q_a = broadcaster.subscribe("test-client-a")
    print(f"[*] Subscribed client A (id: {client_a_id}). Active broadcaster clients: {broadcaster.client_count}")

    # 2. Connect Client B via SSE queue
    client_b_id, q_b = broadcaster.subscribe("test-client-b")
    print(f"[*] Subscribed client B (id: {client_b_id}). Active broadcaster clients: {broadcaster.client_count}")

    # 3. Inject new synthetic threat indicator into backend pipeline
    test_url = f"https://verified-threat-{int(time.time())}.login-auth.xyz/verify"
    t_start = time.time()

    print(f"[*] Injecting new threat indicator: {test_url}")
    ind = pipeline.inject_test_indicator(
        url=test_url,
        source="urlhaus",
        indicator_type="malware_url",
        threat_type="agent_tesla_dropper",
        tags=["malware", "e2e_verified"],
    )

    t_injected = time.time()
    ingestion_duration_ms = (t_injected - t_start) * 1000
    print(f"[+] Indicator persisted in SQLite with ID #{ind.id} (duration: {ingestion_duration_ms:.2f} ms)")

    # 4. Receive event from Client A queue
    event_a = q_a.get(timeout=2.0)
    t_received_a = time.time()
    latency_a_ms = (t_received_a - t_injected) * 1000

    print(f"[+] Client A received SSE event '{event_a.event_type}' (id: {event_a.event_id})")
    print(f"    - URL received: {event_a.indicator['url']}")
    print(f"    - Ingestion-to-client delivery latency: {latency_a_ms:.2f} ms")
    assert event_a.indicator["url"] == test_url, "Client A URL mismatch"

    # 5. Receive event from Client B queue
    event_b = q_b.get(timeout=2.0)
    t_received_b = time.time()
    latency_b_ms = (t_received_b - t_injected) * 1000

    print(f"[+] Client B received SSE event '{event_b.event_type}' (id: {event_b.event_id})")
    print(f"    - Ingestion-to-client delivery latency: {latency_b_ms:.2f} ms")
    assert event_b.indicator["url"] == test_url, "Client B URL mismatch"

    # 6. Verify stats update event broadcast
    stats_event_a = q_a.get(timeout=2.0)
    print(f"[+] Client A received live stats event '{stats_event_a.event_type}'")
    print(f"    - Total indicators: {stats_event_a.stats['total_indicators']}")
    print(f"    - Active stream clients: {stats_event_a.stats['active_stream_clients']}")

    # 7. Test Multi-Source Cross Attribution (Same URL from OpenPhish)
    print("[*] Testing multi-source deduplication with secondary provider (openphish)...")
    ind_updated = pipeline.inject_test_indicator(
        url=test_url,
        source="openphish",
        indicator_type="phishing_url",
        threat_type="phishing_campaign",
        tags=["phishing_cross_ref"],
    )

    # Indicator ID must remain identical
    assert ind_updated.id == ind.id, "Indicator ID changed on duplicate"
    assert set(ind_updated.sources) == {"urlhaus", "openphish"}, f"Sources mismatch: {ind_updated.sources}"
    print(f"[+] Multi-source attribution verified: ID #{ind_updated.id} sources = {ind_updated.sources}")

    # 8. Test Missed-Event Cursor Recovery
    print("[*] Testing cursor recovery (Last-Event-ID)...")
    missed_records = storage.get_indicators_since(ind.id - 1, limit=10)
    assert any(m.id == ind.id for m in missed_records), "Failed to recover indicator by cursor"
    print(f"[+] Cursor recovery verified: {len(missed_records)} records recovered for reconnecting client")

    # Cleanup test clients
    broadcaster.unsubscribe(client_a_id)
    broadcaster.unsubscribe(client_b_id)
    print(f"[*] Unsubscribed test clients. Remaining clients: {broadcaster.client_count}")
    print("==================================================")
    print("ALL LIVE STREAM VERIFICATIONS PASSED SUCCESSFULLY!")
    print("==================================================")


if __name__ == "__main__":
    run_e2e_verification()

