"""SQLite-backed scan history for tracking hardening progress over time."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import threading
from typing import Any


class HistoryStore:
    """Thread-safe local SQLite storage for audit reports."""

    def __init__(self, db_path: Path | None = None) -> None:
        if db_path is None:
            db_path = Path(__file__).resolve().parent.parent / "data" / "audit_history.db"
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    generated_at TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    pass_count INTEGER NOT NULL,
                    warn_count INTEGER NOT NULL,
                    fail_count INTEGER NOT NULL,
                    demo_mode INTEGER NOT NULL DEFAULT 0,
                    report_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def save_scan(self, report: dict[str, Any]) -> int:
        summary = report.get("summary") or {}
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO scans (
                    generated_at, hostname, score,
                    pass_count, warn_count, fail_count,
                    demo_mode, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(report.get("generated_at", "")),
                    str(report.get("hostname", "unknown")),
                    int(report.get("score", 0)),
                    int(summary.get("pass", 0)),
                    int(summary.get("warn", 0)),
                    int(summary.get("fail", 0)),
                    1 if report.get("demo_mode") else 0,
                    json.dumps(report, ensure_ascii=False),
                ),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def list_scans(self, limit: int = 30, demo_only: bool | None = None) -> list[dict[str, Any]]:
        query = """
            SELECT id, generated_at, hostname, score,
                   pass_count, warn_count, fail_count, demo_mode
            FROM scans
        """
        params: list[Any] = []
        if demo_only is not None:
            query += " WHERE demo_mode = ?"
            params.append(1 if demo_only else 0)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        items = [
            {
                "id": int(r["id"]),
                "generated_at": str(r["generated_at"]),
                "hostname": str(r["hostname"]),
                "score": int(r["score"]),
                "summary": {
                    "pass": int(r["pass_count"]),
                    "warn": int(r["warn_count"]),
                    "fail": int(r["fail_count"]),
                },
                "demo_mode": bool(r["demo_mode"]),
            }
            for r in rows
        ]

        # Compute score delta compared to the immediately previous scan
        for idx, item in enumerate(items):
            if idx + 1 < len(items):
                item["delta"] = item["score"] - items[idx + 1]["score"]
            else:
                item["delta"] = 0
        return items

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT report_json FROM scans WHERE id = ?",
                (scan_id,),
            ).fetchone()
        if not row:
            return None
        return json.loads(str(row["report_json"]))
