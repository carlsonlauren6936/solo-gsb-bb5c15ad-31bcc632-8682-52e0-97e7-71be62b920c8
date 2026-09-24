"""SQLite persistence layer.

The database stores five things:

* ``analyses``       : immutable analysis versions (request metadata + full result JSON)
* ``rules``          : one row per analyzed rule, for SQL-level filtering
* ``findings``       : one row per finding / minimal conflict pair, for SQL-level filtering
* ``active_pointer`` : single-row publish pointer (revision + currently active version)
* ``active_history`` : one row per successful activation (audit trail)
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id               TEXT PRIMARY KEY,
    name             TEXT,
    ruleset_hash     TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    rule_count       INTEGER NOT NULL,
    result_json      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    analysis_id   TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    rule_index    INTEGER NOT NULL,
    rule_id       TEXT NOT NULL,
    cidr          TEXT NOT NULL,
    ip_version    INTEGER NOT NULL,
    action        TEXT NOT NULL,
    priority      INTEGER NOT NULL,
    source_tag    TEXT NOT NULL,
    role          TEXT NOT NULL,
    status        TEXT NOT NULL,
    covered       TEXT NOT NULL,
    has_conflict  INTEGER NOT NULL,
    PRIMARY KEY (analysis_id, rule_index)
);

CREATE TABLE IF NOT EXISTS findings (
    analysis_id   TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    seq           INTEGER NOT NULL,
    kind          TEXT NOT NULL,
    severity      TEXT NOT NULL,
    rule_id       TEXT,
    other_rule_id TEXT,
    behavioral    INTEGER NOT NULL,
    payload_json  TEXT NOT NULL,
    PRIMARY KEY (analysis_id, seq)
);

CREATE TABLE IF NOT EXISTS active_pointer (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    revision   INTEGER NOT NULL,
    active_id  TEXT REFERENCES analyses(id),
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS active_history (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    revision     INTEGER NOT NULL,
    previous_id  TEXT,
    active_id    TEXT NOT NULL,
    activated_at TEXT NOT NULL
);

INSERT OR IGNORE INTO active_pointer (id, revision, active_id) VALUES (1, 0, NULL);

CREATE INDEX IF NOT EXISTS idx_rules_analysis   ON rules(analysis_id);
CREATE INDEX IF NOT EXISTS idx_findings_analysis ON findings(analysis_id);
CREATE INDEX IF NOT EXISTS idx_analyses_hash    ON analyses(ruleset_hash);
"""

# In-memory cache of the configured path so tests can override it once.
_db_path: str | None = None
_path_lock = threading.Lock()


def get_db_path() -> str:
    global _db_path
    with _path_lock:
        if _db_path is None:
            configured = os.environ.get("PREFIX_DB_PATH")
            if configured:
                _db_path = configured
            else:
                # Prefer a user-writable data dir; fall back to a temp file
                # when /data exists but is not writable (common in containers
                # started without a volume).
                candidates = ["/data/prefix_policy.db"]
                import tempfile

                candidates.append(os.path.join(tempfile.gettempdir(), "prefix_policy.db"))
                chosen = candidates[-1]
                for path in candidates:
                    parent = os.path.dirname(path)
                    try:
                        os.makedirs(parent, exist_ok=True)
                        if os.access(parent, os.W_OK):
                            chosen = path
                            break
                    except OSError:
                        continue
                _db_path = chosen
        return _db_path


def set_db_path(path: str) -> None:
    """Override the database location (used by tests and at startup)."""
    global _db_path
    with _path_lock:
        _db_path = path


def _connect() -> sqlite3.Connection:
    path = get_db_path()
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)


def reset_db(path: str | None = None) -> None:
    """Drop and recreate all tables (tests only)."""
    if path is not None:
        set_db_path(path)
    with _connect() as conn:
        conn.executescript(
            "DROP TABLE IF EXISTS findings; DROP TABLE IF EXISTS rules; "
            "DROP TABLE IF EXISTS active_history; DROP TABLE IF EXISTS active_pointer; "
            "DROP TABLE IF EXISTS analyses;"
        )
        conn.executescript(_SCHEMA)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def save_analysis(
    analysis_id: str,
    name: str | None,
    result: dict[str, Any],
) -> str:
    """Persist a complete analysis. Returns the id (existing id if the same
    ruleset hash was already stored — the API makes repeated submits idempotent).
    """
    with _connect() as conn:
        existing = conn.execute(
            "SELECT id FROM analyses WHERE ruleset_hash = ?",
            (result["ruleset_hash"],),
        ).fetchone()
        if existing is not None:
            return existing["id"]

        created_at = utc_now_iso()
        conn.execute(
            """INSERT INTO analyses
               (id, name, ruleset_hash, analyzer_version, created_at, rule_count, result_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                analysis_id,
                name,
                result["ruleset_hash"],
                result["analyzer_version"],
                created_at,
                result["summary"]["rule_count"],
                json.dumps(result, ensure_ascii=False),
            ),
        )
        conn.executemany(
            """INSERT INTO rules
               (analysis_id, rule_index, rule_id, cidr, ip_version, action, priority,
                source_tag, role, status, covered, has_conflict)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    analysis_id,
                    r["index"],
                    r["rule_id"],
                    r["cidr"],
                    r["ip_version"],
                    r["action"],
                    r["priority"],
                    r["source_tag"],
                    r["role"],
                    r["status"],
                    str(r["covered"]),  # IPv6 counts exceed SQLite INTEGER range
                    1 if r["has_conflict"] else 0,
                )
                for r in result["rules"]
            ],
        )
        finding_rows = []
        seq = 0
        for f in result["findings"]:
            finding_rows.append(
                (
                    analysis_id,
                    seq,
                    f["type"],
                    f["severity"],
                    f.get("rule_id"),
                    f.get("other_rule_id"),
                    1 if f.get("behavioral") else 0,
                    json.dumps(f, ensure_ascii=False),
                )
            )
            seq += 1
        conn.executemany(
            """INSERT INTO findings
               (analysis_id, seq, kind, severity, rule_id, other_rule_id, behavioral, payload_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            finding_rows,
        )
        return analysis_id


def get_analysis(analysis_id: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT result_json, created_at, name FROM analyses WHERE id = ?",
            (analysis_id,),
        ).fetchone()
    if row is None:
        return None
    result = json.loads(row["result_json"])
    result["id"] = analysis_id
    result["name"] = row["name"]
    result["created_at"] = row["created_at"]
    return result


def list_analyses(limit: int = 50, offset: int = 0) -> tuple[int, list[dict[str, Any]]]:
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM analyses").fetchone()["c"]
        rows = conn.execute(
            """SELECT id, name, ruleset_hash, analyzer_version, created_at, rule_count
               FROM analyses ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
    return total, [dict(r) for r in rows]


def query_rules(
    analysis_id: str,
    status: str | None = None,
    action: str | None = None,
    ip_version: int | None = None,
) -> list[dict[str, Any]] | None:
    """Return stored rule rows for an analysis, optionally filtered.

    Returns ``None`` when the analysis does not exist.
    """
    with _connect() as conn:
        if conn.execute("SELECT 1 FROM analyses WHERE id = ?", (analysis_id,)).fetchone() is None:
            return None
        sql = "SELECT * FROM rules WHERE analysis_id = ?"
        params: list[Any] = [analysis_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if action:
            sql += " AND action = ?"
            params.append(action)
        if ip_version is not None:
            sql += " AND ip_version = ?"
            params.append(ip_version)
        sql += " ORDER BY rule_index"
        rows = conn.execute(sql, params).fetchall()
    result_rows = [dict(r) for r in rows]
    for row in result_rows:
        # Stored as TEXT to accommodate IPv6 address counts (>2^63).
        row["covered"] = int(row["covered"])
        row["has_conflict"] = bool(row["has_conflict"])
    return result_rows


def query_findings(
    analysis_id: str,
    severity: str | None = None,
    behavioral_only: bool = False,
) -> list[dict[str, Any]] | None:
    with _connect() as conn:
        if conn.execute("SELECT 1 FROM analyses WHERE id = ?", (analysis_id,)).fetchone() is None:
            return None
        sql = "SELECT * FROM findings WHERE analysis_id = ?"
        params: list[Any] = [analysis_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if behavioral_only:
            sql += " AND behavioral = 1"
        sql += " ORDER BY seq"
        rows = conn.execute(sql, params).fetchall()
    return [
        {
            "seq": r["seq"],
            "kind": r["kind"],
            "severity": r["severity"],
            "rule_id": r["rule_id"],
            "other_rule_id": r["other_rule_id"],
            "behavioral": bool(r["behavioral"]),
            "detail": json.loads(r["payload_json"]),
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Publish pointer: which saved version is currently "active" (live).
# ---------------------------------------------------------------------------

def _pointer_state(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        return {"revision": 0, "active_id": None, "updated_at": None}
    return {
        "revision": row["revision"],
        "active_id": row["active_id"],
        "updated_at": row["updated_at"],
    }


def get_active() -> dict[str, Any]:
    """Current publish pointer: ``revision`` + the version it points to."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT revision, active_id, updated_at FROM active_pointer WHERE id = 1"
        ).fetchone()
    return _pointer_state(row)


def activate_analysis(analysis_id: str, expected_revision: int) -> dict[str, Any]:
    """Move the publish pointer to a saved version (optimistic-concurrency CAS).

    The existence check, revision check, pointer update and history insert all
    happen in one ``BEGIN IMMEDIATE`` transaction, so concurrent activations
    serialize on the database write lock: the loser re-reads the bumped
    revision and reports a conflict instead of silently overwriting the
    winner's pointer.

    Returns ``{"outcome": "not_found" | "conflict" | "activated", ...}``; the
    API layer maps the outcome to 404 / 409 / 200.
    """
    conn = _connect()
    try:
        # Take the write lock up front so a racing activation cannot slip
        # between our revision check and the pointer update.
        conn.execute("BEGIN IMMEDIATE")
        # Defensive: the schema script seeds the row, but never assume.
        conn.execute(
            "INSERT OR IGNORE INTO active_pointer (id, revision, active_id) VALUES (1, 0, NULL)"
        )
        if conn.execute("SELECT 1 FROM analyses WHERE id = ?", (analysis_id,)).fetchone() is None:
            conn.rollback()
            return {"outcome": "not_found"}
        row = conn.execute(
            "SELECT revision, active_id, updated_at FROM active_pointer WHERE id = 1"
        ).fetchone()
        current = _pointer_state(row)
        if current["revision"] != expected_revision:
            conn.rollback()
            return {"outcome": "conflict", "current": current}
        now = utc_now_iso()
        new_revision = current["revision"] + 1
        conn.execute(
            "UPDATE active_pointer SET revision = ?, active_id = ?, updated_at = ? WHERE id = 1",
            (new_revision, analysis_id, now),
        )
        conn.execute(
            """INSERT INTO active_history (revision, previous_id, active_id, activated_at)
               VALUES (?, ?, ?, ?)""",
            (new_revision, current["active_id"], analysis_id, now),
        )
        conn.commit()
        return {
            "outcome": "activated",
            "state": {
                "revision": new_revision,
                "active_id": analysis_id,
                "previous_id": current["active_id"],
                "activated_at": now,
            },
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def list_activations(limit: int = 50, offset: int = 0) -> tuple[int, list[dict[str, Any]]]:
    """Activation history, newest first (read-only audit trail)."""
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM active_history").fetchone()["c"]
        rows = conn.execute(
            """SELECT seq, revision, previous_id, active_id, activated_at
               FROM active_history ORDER BY seq DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
    return total, [dict(r) for r in rows]
