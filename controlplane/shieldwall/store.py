"""SQLite event log. SQL remembers: history for the chat box and reports, never live blocking."""
from __future__ import annotations

import json
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_t INTEGER, ended_t INTEGER,
    kind TEXT, label TEXT, malicious INTEGER,
    peak_pps REAL, sources INTEGER,
    detect_s REAL, mitigate_s REAL,
    explanation TEXT, evidence TEXT,
    wall_time REAL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    t INTEGER, incident_id INTEGER,
    kind TEXT, detail TEXT,
    wall_time REAL
);
CREATE TABLE IF NOT EXISTS metrics (
    t INTEGER PRIMARY KEY,
    pps REAL, bps REAL, passed_pps REAL, served_pct REAL,
    zscore REAL, cusum REAL, entropy REAL, anomalous INTEGER
);
"""


class EventStore:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript(SCHEMA)

    def _exec(self, sql: str, args=()) -> sqlite3.Cursor:
        with self.lock:
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur

    def open_incident(self, t: int, kind: str, label: str, malicious: bool, evidence: list[str]) -> int:
        cur = self._exec(
            "INSERT INTO incidents (started_t, kind, label, malicious, peak_pps, sources, evidence, wall_time)"
            " VALUES (?,?,?,?,0,0,?,?)",
            (t, kind, label, int(malicious), json.dumps(evidence), time.time()))
        return cur.lastrowid

    def update_incident(self, iid: int, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k} = ?" for k in fields)
        self._exec(f"UPDATE incidents SET {cols} WHERE id = ?", (*fields.values(), iid))

    def event(self, t: int, kind: str, detail: str, incident_id: int | None = None) -> None:
        self._exec("INSERT INTO events (t, incident_id, kind, detail, wall_time) VALUES (?,?,?,?,?)",
                   (t, incident_id, kind, detail, time.time()))

    def metric(self, t: int, **m) -> None:
        self._exec("INSERT OR REPLACE INTO metrics (t, pps, bps, passed_pps, served_pct, zscore, cusum, entropy, anomalous)"
                   " VALUES (?,?,?,?,?,?,?,?,?)",
                   (t, m["pps"], m["bps"], m["passed_pps"], m["served_pct"], m["zscore"], m["cusum"],
                    m["entropy"], int(m["anomalous"])))

    def query(self, sql: str, args=()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def recent_events(self, limit: int = 30) -> list[dict]:
        return self.query("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))

    def incidents(self, limit: int = 20) -> list[dict]:
        return self.query("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
