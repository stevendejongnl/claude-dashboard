"""Shared async SQLite helpers."""
import aiosqlite
import os

DB_PATH = os.environ.get("DB_PATH", "/data/dashboard.db")

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS live_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    category TEXT NOT NULL,
    method TEXT NOT NULL,
    host TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER,
    req_size INTEGER,
    resp_size INTEGER,
    duration_ms INTEGER,
    req_body TEXT,
    resp_body TEXT,
    leak_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS leaks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL REFERENCES live_flows(id),
    ts TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    redacted_match TEXT,
    context TEXT,
    entropy REAL
);

CREATE TABLE IF NOT EXISTS telemetry_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ingested_at TEXT NOT NULL,
    raw_hash TEXT UNIQUE,
    client_ts TEXT,
    event_name TEXT NOT NULL,
    session_id TEXT,
    model TEXT,
    version TEXT,
    device_id TEXT,
    additional_meta TEXT,
    raw TEXT
);

CREATE INDEX IF NOT EXISTS idx_tel_event ON telemetry_events(event_name);
CREATE INDEX IF NOT EXISTS idx_tel_session ON telemetry_events(session_id);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    start_ts TEXT,
    end_ts TEXT,
    cost_usd REAL,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cache_creation_tokens INTEGER,
    cache_read_tokens INTEGER,
    lines_added INTEGER,
    lines_removed INTEGER,
    api_duration_ms INTEGER,
    tool_duration_ms INTEGER,
    session_duration_ms INTEGER,
    model TEXT,
    version TEXT
);
"""


async def get_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(SCHEMA_SQL)
        await db.commit()

        # Migration: add raw_hash column + unique index if not present
        try:
            await db.execute("ALTER TABLE telemetry_events ADD COLUMN raw_hash TEXT")
            await db.commit()
        except Exception:
            pass  # column already exists — normal on second+ startup

        await db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_te_raw_hash ON telemetry_events(raw_hash)"
        )
        await db.commit()
