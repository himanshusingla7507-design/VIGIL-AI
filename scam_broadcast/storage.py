"""Persistent SQLite storage and indexing for Cyber Scam Cases."""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

from scam_broadcast.data import VERIFIED_DOCUMENTED_CASES
from scam_broadcast.models import ScamCaseBroadcast, utc_now_iso

logger = logging.getLogger("scam_broadcast.storage")
DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vigil_history.sqlite3")


class ScamCaseStorage:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self.init_db()
        self.seed_verified_cases()

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
                CREATE TABLE IF NOT EXISTS scam_cases (
                    id TEXT PRIMARY KEY,
                    slug TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    scam_type TEXT NOT NULL,
                    category_display TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    what_happened TEXT NOT NULL,
                    attack_chain_json TEXT NOT NULL,
                    target_audience TEXT NOT NULL,
                    warning_signs_json TEXT NOT NULL,
                    technical_indicators_json TEXT NOT NULL,
                    documented_impact TEXT NOT NULL,
                    protection_steps_json TEXT NOT NULL,
                    victim_recovery_steps_json TEXT NOT NULL,
                    legal_provisions_json TEXT NOT NULL,
                    primary_source TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    last_verified_at TEXT NOT NULL,
                    is_breaking INTEGER NOT NULL DEFAULT 0,
                    audit_trail_json TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scam_slug ON scam_cases(slug)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scam_type ON scam_cases(scam_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scam_status ON scam_cases(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scam_published ON scam_cases(published_at DESC)")

    def seed_verified_cases(self) -> None:
        with self.get_connection() as conn:
            for case in VERIFIED_DOCUMENTED_CASES:
                conn.execute(
                    """
                    INSERT INTO scam_cases (
                        id, slug, title, status, severity, scam_type, category_display,
                        summary, what_happened, attack_chain_json, target_audience,
                        warning_signs_json, technical_indicators_json, documented_impact,
                        protection_steps_json, victim_recovery_steps_json, legal_provisions_json,
                        primary_source, source_url, published_at, last_verified_at,
                        is_breaking, audit_trail_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        title = excluded.title,
                        status = excluded.status,
                        severity = excluded.severity,
                        scam_type = excluded.scam_type,
                        category_display = excluded.category_display,
                        summary = excluded.summary,
                        what_happened = excluded.what_happened,
                        attack_chain_json = excluded.attack_chain_json,
                        target_audience = excluded.target_audience,
                        warning_signs_json = excluded.warning_signs_json,
                        technical_indicators_json = excluded.technical_indicators_json,
                        documented_impact = excluded.documented_impact,
                        protection_steps_json = excluded.protection_steps_json,
                        victim_recovery_steps_json = excluded.victim_recovery_steps_json,
                        legal_provisions_json = excluded.legal_provisions_json,
                        primary_source = excluded.primary_source,
                        source_url = excluded.source_url,
                        last_verified_at = excluded.last_verified_at,
                        is_breaking = excluded.is_breaking
                    """,
                    (
                        case.id,
                        case.slug,
                        case.title,
                        case.status,
                        case.severity,
                        case.scam_type,
                        case.category_display,
                        case.summary,
                        case.what_happened,
                        json.dumps(case.attack_chain),
                        case.target_audience,
                        json.dumps(case.warning_signs),
                        json.dumps(case.technical_indicators),
                        case.documented_impact,
                        json.dumps(case.protection_steps),
                        json.dumps(case.victim_recovery_steps),
                        json.dumps(case.legal_provisions),
                        case.primary_source,
                        case.source_url,
                        case.published_at,
                        case.last_verified_at,
                        1 if case.is_breaking else 0,
                        json.dumps(case.audit_trail),
                    ),
                )

    def _row_to_case(self, r: sqlite3.Row) -> ScamCaseBroadcast:
        return ScamCaseBroadcast(
            id=r["id"],
            slug=r["slug"],
            title=r["title"],
            status=r["status"],
            severity=r["severity"],
            scam_type=r["scam_type"],
            category_display=r["category_display"],
            summary=r["summary"],
            what_happened=r["what_happened"],
            attack_chain=json.loads(r["attack_chain_json"] or "[]"),
            target_audience=r["target_audience"],
            warning_signs=json.loads(r["warning_signs_json"] or "[]"),
            technical_indicators=json.loads(r["technical_indicators_json"] or "[]"),
            documented_impact=r["documented_impact"],
            protection_steps=json.loads(r["protection_steps_json"] or "[]"),
            victim_recovery_steps=json.loads(r["victim_recovery_steps_json"] or "[]"),
            legal_provisions=json.loads(r["legal_provisions_json"] or "[]"),
            primary_source=r["primary_source"],
            source_url=r["source_url"],
            published_at=r["published_at"],
            last_verified_at=r["last_verified_at"],
            is_breaking=bool(r["is_breaking"]),
            audit_trail=json.loads(r["audit_trail_json"] or "[]"),
        )

    def query_cases(
        self,
        page: int = 1,
        limit: int = 20,
        scam_type: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[ScamCaseBroadcast], int]:
        limit = max(1, min(limit, 100))
        page = max(1, page)
        offset = (page - 1) * limit

        clauses = []
        params: List[Any] = []

        if scam_type and scam_type.strip() and scam_type.upper() != "ALL":
            clauses.append("scam_type = ?")
            params.append(scam_type.strip())

        if status and status.strip() and status.upper() != "ALL":
            clauses.append("status = ?")
            params.append(status.strip())

        if severity and severity.strip() and severity.upper() != "ALL":
            clauses.append("severity = ?")
            params.append(severity.strip())

        if search and search.strip():
            term = f"%{search.strip()}%"
            clauses.append("(title LIKE ? OR summary LIKE ? OR what_happened LIKE ? OR target_audience LIKE ?)")
            params.extend([term, term, term, term])

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self.get_connection() as conn:
            cnt_row = conn.execute(f"SELECT COUNT(*) as cnt FROM scam_cases {where_sql}", params).fetchone()
            total_count = cnt_row["cnt"] if cnt_row else 0

            rows = conn.execute(
                f"""
                SELECT * FROM scam_cases
                {where_sql}
                ORDER BY is_breaking DESC, published_at DESC
                LIMIT ? OFFSET ?
                """,
                params + [limit, offset],
            ).fetchall()

            return [self._row_to_case(r) for r in rows], total_count

    def get_case(self, id_or_slug: str) -> Optional[ScamCaseBroadcast]:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM scam_cases WHERE id = ? OR slug = ?",
                (id_or_slug, id_or_slug),
            ).fetchone()
            return self._row_to_case(row) if row else None

    def get_scam_stats(self) -> Dict[str, Any]:
        with self.get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) as cnt FROM scam_cases").fetchone()["cnt"]
            type_rows = conn.execute("SELECT scam_type, COUNT(*) as cnt FROM scam_cases GROUP BY scam_type").fetchall()
            by_type = {r["scam_type"]: r["cnt"] for r in type_rows}

            status_rows = conn.execute("SELECT status, COUNT(*) as cnt FROM scam_cases GROUP BY status").fetchall()
            by_status = {r["status"]: r["cnt"] for r in status_rows}

            severity_rows = conn.execute("SELECT severity, COUNT(*) as cnt FROM scam_cases GROUP BY severity").fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in severity_rows}

            breaking_count = conn.execute("SELECT COUNT(*) as cnt FROM scam_cases WHERE is_breaking = 1").fetchone()["cnt"]

            return {
                "total_cases": total,
                "by_type": by_type,
                "by_status": by_status,
                "by_severity": by_severity,
                "breaking_count": breaking_count,
            }
