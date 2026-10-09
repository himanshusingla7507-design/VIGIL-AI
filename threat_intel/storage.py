"""Persistent SQLite storage and indexing for VIGIL Threat Intelligence."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from threat_intel.models import (
    RawThreatRecord,
    ThreatFeedStats,
    ThreatIndicator,
    ThreatSourceStatus,
    utc_now_iso,
)

logger = logging.getLogger("threat_intel.storage")
DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vigil_history.sqlite3")


def compute_indicator_hash(normalized_url: str) -> str:
    """Compute deterministic SHA-256 hash for deduplication."""
    return hashlib.sha256(normalized_url.strip().encode("utf-8")).hexdigest()


class ThreatStorage:
    """Thread-safe SQLite storage for threat indicators and source operational health."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self.init_db()

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_hash TEXT UNIQUE NOT NULL,
                    url TEXT NOT NULL,
                    normalized_url TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    primary_source TEXT NOT NULL,
                    sources_json TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    source_timestamp TEXT,
                    status TEXT NOT NULL,
                    threat_type TEXT,
                    tags_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    ingested_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_sources_status (
                    source_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    update_cadence_seconds INTEGER NOT NULL,
                    cadence_human TEXT NOT NULL,
                    last_fetch_attempt TEXT,
                    last_successful_fetch TEXT,
                    last_error TEXT,
                    total_indicators_fetched INTEGER NOT NULL DEFAULT 0,
                    documentation_url TEXT NOT NULL,
                    terms_note TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                )
                """
            )
            # Create performance indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_hash ON threat_indicators(indicator_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_ingested_at ON threat_indicators(ingested_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_primary_source ON threat_indicators(primary_source)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_indicator_type ON threat_indicators(indicator_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_hostname ON threat_indicators(hostname)")

    def save_source_status(self, status: ThreatSourceStatus) -> None:
        """Persist latest health and sync statistics for an intelligence source."""
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO threat_sources_status (
                    source_id, name, enabled, status, update_cadence_seconds, cadence_human,
                    last_fetch_attempt, last_successful_fetch, last_error, total_indicators_fetched,
                    documentation_url, terms_note, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_id) DO UPDATE SET
                    name = excluded.name,
                    enabled = excluded.enabled,
                    status = excluded.status,
                    update_cadence_seconds = excluded.update_cadence_seconds,
                    cadence_human = excluded.cadence_human,
                    last_fetch_attempt = excluded.last_fetch_attempt,
                    last_successful_fetch = excluded.last_successful_fetch,
                    last_error = excluded.last_error,
                    total_indicators_fetched = excluded.total_indicators_fetched,
                    documentation_url = excluded.documentation_url,
                    terms_note = excluded.terms_note,
                    metadata_json = excluded.metadata_json
                """,
                (
                    status.id,
                    status.name,
                    1 if status.enabled else 0,
                    status.status,
                    status.update_cadence_seconds,
                    status.cadence_human,
                    status.last_fetch_attempt,
                    status.last_successful_fetch,
                    status.last_error,
                    status.total_indicators_fetched,
                    status.documentation_url,
                    status.terms_note,
                    json.dumps(status.metadata),
                ),
            )

    def get_all_source_statuses(self) -> List[ThreatSourceStatus]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM threat_sources_status ORDER BY source_id ASC").fetchall()
            results = []
            for r in rows:
                results.append(
                    ThreatSourceStatus(
                        id=r["source_id"],
                        name=r["name"],
                        enabled=bool(r["enabled"]),
                        status=r["status"],
                        update_cadence_seconds=r["update_cadence_seconds"],
                        cadence_human=r["cadence_human"],
                        last_fetch_attempt=r["last_fetch_attempt"],
                        last_successful_fetch=r["last_successful_fetch"],
                        last_error=r["last_error"],
                        total_indicators_fetched=r["total_indicators_fetched"],
                        documentation_url=r["documentation_url"],
                        terms_note=r["terms_note"],
                        metadata=json.loads(r["metadata_json"] or "{}"),
                    )
                )
            return results

    def upsert_indicator(
        self,
        raw: RawThreatRecord,
        normalized_url: str,
        hostname: str,
        ingested_at: Optional[str] = None,
    ) -> Tuple[ThreatIndicator, bool]:
        """Insert new threat indicator or update multi-source provenance."""
        now_iso = ingested_at or utc_now_iso()
        ind_hash = compute_indicator_hash(normalized_url)

        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM threat_indicators WHERE indicator_hash = ?",
                (ind_hash,),
            ).fetchone()

            if row is None:
                sources = [raw.source]
                tags = list(set(raw.tags))
                meta = {
                    raw.source: raw.metadata,
                }
                cursor = conn.execute(
                    """
                    INSERT INTO threat_indicators (
                        indicator_hash, url, normalized_url, hostname, indicator_type,
                        primary_source, sources_json, first_seen_at, last_seen_at,
                        source_timestamp, status, threat_type, tags_json, metadata_json, ingested_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ind_hash,
                        raw.url,
                        normalized_url,
                        hostname,
                        raw.indicator_type,
                        raw.source,
                        json.dumps(sources),
                        now_iso,
                        now_iso,
                        raw.source_timestamp,
                        raw.status,
                        raw.threat_type,
                        json.dumps(tags),
                        json.dumps(meta),
                        now_iso,
                    ),
                )
                record_id = cursor.lastrowid
                indicator = ThreatIndicator(
                    id=record_id,
                    indicator_hash=ind_hash,
                    url=raw.url,
                    normalized_url=normalized_url,
                    hostname=hostname,
                    indicator_type=raw.indicator_type,
                    primary_source=raw.source,
                    sources=sources,
                    first_seen_at=now_iso,
                    last_seen_at=now_iso,
                    source_timestamp=raw.source_timestamp,
                    status=raw.status,
                    threat_type=raw.threat_type,
                    tags=tags,
                    metadata=meta,
                    ingested_at=now_iso,
                )
                return indicator, True
            else:
                # Existing record: update multi-source provenance and last_seen
                existing_sources: List[str] = json.loads(row["sources_json"] or "[]")
                if raw.source not in existing_sources:
                    existing_sources.append(raw.source)

                existing_tags: List[str] = json.loads(row["tags_json"] or "[]")
                for t in raw.tags:
                    if t not in existing_tags:
                        existing_tags.append(t)

                existing_meta: Dict[str, Any] = json.loads(row["metadata_json"] or "{}")
                existing_meta[raw.source] = raw.metadata

                # Keep earliest source_timestamp or update if original was None
                source_ts = row["source_timestamp"] or raw.source_timestamp

                conn.execute(
                    """
                    UPDATE threat_indicators SET
                        sources_json = ?,
                        last_seen_at = ?,
                        source_timestamp = ?,
                        status = ?,
                        tags_json = ?,
                        metadata_json = ?
                    WHERE id = ?
                    """,
                    (
                        json.dumps(existing_sources),
                        now_iso,
                        source_ts,
                        raw.status or row["status"],
                        json.dumps(existing_tags),
                        json.dumps(existing_meta),
                        row["id"],
                    ),
                )

                indicator = ThreatIndicator(
                    id=row["id"],
                    indicator_hash=ind_hash,
                    url=row["url"],
                    normalized_url=row["normalized_url"],
                    hostname=row["hostname"],
                    indicator_type=row["indicator_type"],
                    primary_source=row["primary_source"],
                    sources=existing_sources,
                    first_seen_at=row["first_seen_at"],
                    last_seen_at=now_iso,
                    source_timestamp=source_ts,
                    status=raw.status or row["status"],
                    threat_type=row["threat_type"] or raw.threat_type,
                    tags=existing_tags,
                    metadata=existing_meta,
                    ingested_at=row["ingested_at"],
                )
                return indicator, False

    def query_indicators(
        self,
        page: int = 1,
        limit: int = 50,
        source: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[ThreatIndicator], int]:
        """Query threat indicators with search and filters."""
        limit = max(1, min(limit, 200))
        page = max(1, page)
        offset = (page - 1) * limit

        clauses = []
        params: List[Any] = []

        if source and source.strip() and source.lower() != "all":
            clauses.append("(primary_source = ? OR sources_json LIKE ?)")
            params.extend([source.strip(), f'%"{source.strip()}"%'])

        if category and category.strip() and category.lower() != "all":
            clauses.append("indicator_type = ?")
            params.append(category.strip())

        if status and status.strip() and status.lower() != "all":
            clauses.append("status = ?")
            params.append(status.strip())

        if search and search.strip():
            term = f"%{search.strip()}%"
            clauses.append("(url LIKE ? OR hostname LIKE ? OR threat_type LIKE ? OR tags_json LIKE ?)")
            params.extend([term, term, term, term])

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self.get_connection() as conn:
            count_row = conn.execute(f"SELECT COUNT(*) as cnt FROM threat_indicators {where_sql}", params).fetchone()
            total_count = count_row["cnt"] if count_row else 0

            query_sql = f"""
                SELECT * FROM threat_indicators
                {where_sql}
                ORDER BY id DESC
                LIMIT ? OFFSET ?
            """
            rows = conn.execute(query_sql, params + [limit, offset]).fetchall()

            indicators = []
            for r in rows:
                indicators.append(
                    ThreatIndicator(
                        id=r["id"],
                        indicator_hash=r["indicator_hash"],
                        url=r["url"],
                        normalized_url=r["normalized_url"],
                        hostname=r["hostname"],
                        indicator_type=r["indicator_type"],
                        primary_source=r["primary_source"],
                        sources=json.loads(r["sources_json"] or "[]"),
                        first_seen_at=r["first_seen_at"],
                        last_seen_at=r["last_seen_at"],
                        source_timestamp=r["source_timestamp"],
                        status=r["status"],
                        threat_type=r["threat_type"],
                        tags=json.loads(r["tags_json"] or "[]"),
                        metadata=json.loads(r["metadata_json"] or "{}"),
                        ingested_at=r["ingested_at"],
                    )
                )

            return indicators, total_count

    def get_indicators_since(self, since_id: int, limit: int = 100) -> List[ThreatIndicator]:
        """Fetch records with id > since_id for catch-up and event replay."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM threat_indicators WHERE id > ? ORDER BY id ASC LIMIT ?",
                (since_id, max(1, min(limit, 200))),
            ).fetchall()
            results = []
            for r in rows:
                results.append(
                    ThreatIndicator(
                        id=r["id"],
                        indicator_hash=r["indicator_hash"],
                        url=r["url"],
                        normalized_url=r["normalized_url"],
                        hostname=r["hostname"],
                        indicator_type=r["indicator_type"],
                        primary_source=r["primary_source"],
                        sources=json.loads(r["sources_json"] or "[]"),
                        first_seen_at=r["first_seen_at"],
                        last_seen_at=r["last_seen_at"],
                        source_timestamp=r["source_timestamp"],
                        status=r["status"],
                        threat_type=r["threat_type"],
                        tags=json.loads(r["tags_json"] or "[]"),
                        metadata=json.loads(r["metadata_json"] or "{}"),
                        ingested_at=r["ingested_at"],
                    )
                )
            return results

    def get_feed_stats(self, active_stream_clients: int = 0) -> ThreatFeedStats:
        """Compute aggregated statistics for the global live threat feed."""
        now_dt = datetime.now(timezone.utc)
        iso_24h_ago = (now_dt - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        iso_1h_ago = (now_dt - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

        with self.get_connection() as conn:
            total_row = conn.execute("SELECT COUNT(*) as cnt, MAX(ingested_at) as latest FROM threat_indicators").fetchone()
            total_indicators = total_row["cnt"] if total_row else 0
            latest_ingested = total_row["latest"] if total_row else None

            new_24h_row = conn.execute(
                "SELECT COUNT(*) as cnt FROM threat_indicators WHERE first_seen_at >= ?",
                (iso_24h_ago,),
            ).fetchone()
            new_24h = new_24h_row["cnt"] if new_24h_row else 0

            new_1h_row = conn.execute(
                "SELECT COUNT(*) as cnt FROM threat_indicators WHERE first_seen_at >= ?",
                (iso_1h_ago,),
            ).fetchone()
            new_1h = new_1h_row["cnt"] if new_1h_row else 0

            # Group by primary source
            source_rows = conn.execute("SELECT primary_source, COUNT(*) as cnt FROM threat_indicators GROUP BY primary_source").fetchall()
            by_source = {r["primary_source"]: r["cnt"] for r in source_rows}

            # Group by category
            cat_rows = conn.execute("SELECT indicator_type, COUNT(*) as cnt FROM threat_indicators GROUP BY indicator_type").fetchall()
            by_category = {r["indicator_type"]: r["cnt"] for r in cat_rows}

            # Group by status
            status_rows = conn.execute("SELECT status, COUNT(*) as cnt FROM threat_indicators GROUP BY status").fetchall()
            by_status = {r["status"]: r["cnt"] for r in status_rows}

            # Sources health count
            src_health_rows = conn.execute("SELECT status FROM threat_sources_status WHERE enabled = 1").fetchall()
            configured_sources = len(src_health_rows)
            healthy_sources = sum(1 for r in src_health_rows if r["status"] == "healthy")

            return ThreatFeedStats(
                total_indicators=total_indicators,
                new_last_24h=new_24h,
                new_last_1h=new_1h,
                by_source=by_source,
                by_category=by_category,
                by_status=by_status,
                active_stream_clients=active_stream_clients,
                latest_ingested_at=latest_ingested,
                configured_sources=configured_sources,
                healthy_sources=healthy_sources,
            )

