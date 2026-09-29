"""Lưu alert vào SQLite — để dashboard truy vấn lịch sử, lọc, và ack."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from mini_ids.alerts import Alert

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    last_seen   REAL NOT NULL,
    detector    TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    src         TEXT,
    dst         TEXT,
    description TEXT,
    mitre       TEXT,
    evidence    TEXT,
    count       INTEGER DEFAULT 1,
    pcap        TEXT,
    acked       INTEGER DEFAULT 0,
    alert_key   TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
"""

_COLUMNS = ("id", "ts", "last_seen", "detector", "title", "severity", "src", "dst",
            "description", "mitre", "evidence", "count", "pcap", "acked", "alert_key")


class AlertStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.execute("PRAGMA journal_mode=WAL")

    def insert(self, a: Alert) -> None:
        with self._lock:
            self._db.execute(
                f"INSERT OR REPLACE INTO alerts ({','.join(_COLUMNS)}) VALUES ({','.join('?' * len(_COLUMNS))})",
                (a.id, a.ts, a.last_seen, a.detector, a.title, a.severity, a.src, a.dst,
                 a.description, json.dumps(a.mitre), json.dumps(a.evidence, default=str),
                 a.count, a.pcap, int(a.acked), a.key))
            self._db.commit()

    def update_counts(self, alerts: list[Alert]) -> None:
        if not alerts:
            return
        with self._lock:
            self._db.executemany("UPDATE alerts SET count=?, last_seen=?, pcap=? WHERE id=?",
                                 [(a.count, a.last_seen, a.pcap, a.id) for a in alerts])
            self._db.commit()

    def ack(self, alert_id: str, acked: bool = True) -> bool:
        with self._lock:
            cur = self._db.execute("UPDATE alerts SET acked=? WHERE id=?", (int(acked), alert_id))
            self._db.commit()
            return cur.rowcount > 0

    def get(self, alert_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return self._row(row) if row else None

    def query(self, limit: int = 200, severity: str | None = None, detector: str | None = None,
              since: float | None = None, search: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM alerts WHERE 1=1"
        args: list[Any] = []
        if severity:
            sql += " AND severity=?"
            args.append(severity)
        if detector:
            sql += " AND detector=?"
            args.append(detector)
        if since:
            sql += " AND last_seen>=?"
            args.append(since)
        if search:
            sql += " AND (title LIKE ? OR src LIKE ? OR dst LIKE ? OR description LIKE ?)"
            args += [f"%{search}%"] * 4
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(int(limit))
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
        return [self._row(r) for r in rows]

    def counts(self) -> dict[str, dict[str, int]]:
        with self._lock:
            sev = self._db.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall()
            det = self._db.execute("SELECT detector, COUNT(*) FROM alerts GROUP BY detector").fetchall()
        return {"severity": {r[0]: r[1] for r in sev}, "detector": {r[0]: r[1] for r in det}}

    def clear(self) -> None:
        with self._lock:
            self._db.execute("DELETE FROM alerts")
            self._db.commit()

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["mitre"] = json.loads(d["mitre"] or "[]")
        d["evidence"] = json.loads(d["evidence"] or "{}")
        d["acked"] = bool(d["acked"])
        d["key"] = d.pop("alert_key", None)
        return d

    def close(self) -> None:
        with self._lock:
            self._db.close()
