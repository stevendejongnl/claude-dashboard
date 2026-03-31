"""
Watches /telemetry/*.json for new lines and writes to SQLite.
Runs as an asyncio background task inside FastAPI.
"""
import asyncio
import hashlib
import json
import logging
import os
from datetime import datetime, timezone

import aiosqlite
from watchfiles import awatch

TELEMETRY_DIR = os.environ.get("TELEMETRY_DIR", "/telemetry")
DB_PATH = os.environ.get("DB_PATH", "/data/dashboard.db")

log = logging.getLogger("ingestor")

# Track how many bytes we've already read from each file.
# Keys are absolute paths, values are byte offsets.
_file_offsets: dict[str, int] = {}


def _parse_event(line: str) -> dict | None:
    """Parse one NDJSON line. Returns structured dict or None on error."""
    try:
        outer = json.loads(line)
        ed = outer.get("event_data", {})

        # Double-parse additional_metadata (it's a JSON-encoded string)
        am_raw = ed.get("additional_metadata", "{}")
        try:
            am = json.loads(am_raw) if isinstance(am_raw, str) else am_raw
        except (json.JSONDecodeError, TypeError):
            am = {}

        return {
            "client_ts": ed.get("client_timestamp"),
            "event_name": ed.get("event_name", "unknown"),
            "session_id": ed.get("session_id"),
            "model": ed.get("model"),
            "version": ed.get("env", {}).get("version"),
            "device_id": ed.get("device_id"),
            "additional_meta": json.dumps(am),
            "raw": line[:32768],
        }
    except Exception as e:
        log.warning(f"Failed to parse line: {e}")
        return None


async def _ingest_file(path: str, db: aiosqlite.Connection):
    """Read and ingest any new lines in `path` since last offset."""
    offset = _file_offsets.get(path, 0)
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            new_data = f.read()
            new_offset = offset + len(new_data)
    except OSError:
        return

    lines = new_data.decode("utf-8", errors="replace").splitlines()
    ingested_at = datetime.now(timezone.utc).isoformat()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        evt = _parse_event(line)
        if evt is None:
            continue

        raw_hash = hashlib.sha256(line.encode()).hexdigest()
        await db.execute(
            """INSERT OR IGNORE INTO telemetry_events
               (ingested_at, raw_hash, client_ts, event_name, session_id, model,
                version, device_id, additional_meta, raw)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                ingested_at,
                raw_hash,
                evt["client_ts"],
                evt["event_name"],
                evt["session_id"],
                evt["model"],
                evt["version"],
                evt["device_id"],
                evt["additional_meta"],
                evt["raw"],
            ),
        )

        # If it's a session-end event, upsert sessions table
        if evt["event_name"] == "tengu_exit":
            am = json.loads(evt["additional_meta"] or "{}")
            sid = evt["session_id"]
            if sid:
                await db.execute(
                    """INSERT INTO sessions
                       (session_id, end_ts, cost_usd, input_tokens, output_tokens,
                        cache_creation_tokens, cache_read_tokens,
                        lines_added, lines_removed,
                        api_duration_ms, tool_duration_ms, session_duration_ms,
                        model, version)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(session_id) DO UPDATE SET
                         end_ts=excluded.end_ts,
                         cost_usd=excluded.cost_usd,
                         input_tokens=excluded.input_tokens,
                         output_tokens=excluded.output_tokens,
                         cache_creation_tokens=excluded.cache_creation_tokens,
                         cache_read_tokens=excluded.cache_read_tokens,
                         lines_added=excluded.lines_added,
                         lines_removed=excluded.lines_removed""",
                    (
                        sid,
                        evt["client_ts"],
                        am.get("last_session_cost"),
                        am.get("last_session_total_input_tokens"),
                        am.get("last_session_total_output_tokens"),
                        am.get("last_session_total_cache_creation_input_tokens"),
                        am.get("last_session_total_cache_read_input_tokens"),
                        am.get("last_session_lines_added"),
                        am.get("last_session_lines_removed"),
                        am.get("last_session_api_duration"),
                        am.get("last_session_tool_duration"),
                        am.get("last_session_duration"),
                        evt["model"],
                        evt["version"],
                    ),
                )

    await db.commit()
    _file_offsets[path] = new_offset


async def _initial_scan(db: aiosqlite.Connection):
    """On startup, ingest all existing lines from all files."""
    import glob

    files = sorted(glob.glob(os.path.join(TELEMETRY_DIR, "*.json")))
    for path in files:
        await _ingest_file(path, db)
    log.info(f"Initial scan complete: {len(files)} files processed")


async def run_ingestor():
    """Entry point — called as asyncio.create_task from FastAPI lifespan."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await _initial_scan(db)
        # watchfiles.awatch yields sets of (ChangeType, path) tuples
        async for changes in awatch(TELEMETRY_DIR, poll_delay_ms=500):
            for _change_type, path in changes:
                if path.endswith(".json"):
                    await _ingest_file(path, db)
