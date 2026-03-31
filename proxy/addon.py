"""
Claude Code transparency dashboard — mitmproxy addon.
Intercepts HTTPS flows and writes them to SQLite for the dashboard to consume.
"""
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone

import mitmproxy.http

log = logging.getLogger("claude-dashboard")

from scanner import scan_text

DB_PATH = os.environ.get("DB_PATH", "/data/dashboard.db")


def _init_db():
    """Initialize SQLite schema."""
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")

    con.execute(
        """
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
        )
    """
    )

    con.execute(
        """
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
        )
    """
    )

    con.commit()
    con.close()


def _categorize(host: str, path: str) -> str:
    """Categorize the flow based on host and path."""
    if "api.anthropic.com" in host:
        if "/v1/messages" in path:
            return "messages_api"
        if "metrics" in path or "claude_code" in path:
            return "metrics"
        return "anthropic_other"
    if "statsig" in host or "featuregates" in host:
        return "statsig"
    return "other"


def _safe_json(raw: bytes | None) -> str | None:
    """Decode bytes to UTF-8, try to parse as JSON for pretty storage."""
    if not raw:
        return None
    try:
        text = raw.decode("utf-8", errors="replace")
        # Verify it's valid JSON
        json.loads(text)
        return text[:65536]  # cap at 64KB
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _extract_text_from_messages(req_body: str | None) -> str:
    """
    Pull all text content out of an Anthropic messages API request body.
    The body is: {"messages": [{"role": "user", "content": [{"type": "text", "text": "..."}]}]}
    Also handles string content: {"role": "user", "content": "plain string"}
    """
    if not req_body:
        return ""
    try:
        body = json.loads(req_body)
    except json.JSONDecodeError:
        return req_body  # scan raw text as fallback

    def _extract_blocks(blocks):
        """Recursively extract text from content block lists (handles tool_result nesting)."""
        for block in blocks:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                yield block.get("text", "")
            elif block.get("type") == "tool_result":
                nested = block.get("content", [])
                if isinstance(nested, list):
                    yield from _extract_blocks(nested)
                elif isinstance(nested, str):
                    yield nested

    parts = []
    for msg in body.get("messages", []):
        content = msg.get("content", "")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            parts.extend(_extract_blocks(content))

    # Also scan system prompt if present
    sys_prompt = body.get("system", "")
    if isinstance(sys_prompt, str):
        parts.append(sys_prompt)
    elif isinstance(sys_prompt, list):
        for block in sys_prompt:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))

    return "\n".join(parts)


class ClaudeDashboardAddon:
    """mitmproxy addon for Claude Code transparency dashboard."""

    def running(self):
        """Called once after proxy is fully up."""
        _init_db()
        log.info(f"[claude-dashboard] addon active, DB={DB_PATH}")

    def request(self, flow: mitmproxy.http.HTTPFlow):
        """Tag the flow with a start time for duration calculation."""
        flow.metadata["req_start"] = time.monotonic()

    def response(self, flow: mitmproxy.http.HTTPFlow):
        """Intercept response and write to SQLite."""
        host = flow.request.pretty_host
        path = flow.request.path
        category = _categorize(host, path)

        # Only log claude-related traffic
        if category == "other":
            return

        duration_ms = None
        if "req_start" in flow.metadata:
            duration_ms = int((time.monotonic() - flow.metadata["req_start"]) * 1000)

        req_content = flow.request.get_content()
        req_body = _safe_json(req_content)          # truncated for DB storage
        req_full = req_content.decode("utf-8", errors="replace") if req_content else ""
        resp_body = (
            _safe_json(flow.response.get_content())
            if flow.response
            else None
        )
        ts = datetime.now(timezone.utc).isoformat()

        try:
            con = sqlite3.connect(DB_PATH, timeout=10)
            cursor = con.execute(
                """INSERT INTO live_flows
                   (ts, category, method, host, path, status,
                    req_size, resp_size, duration_ms, req_body, resp_body)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ts,
                    category,
                    flow.request.method,
                    host,
                    path,
                    flow.response.status_code if flow.response else None,
                    len(flow.request.get_content() or b""),
                    len(flow.response.get_content() or b"") if flow.response else 0,
                    duration_ms,
                    req_body,
                    resp_body,
                ),
            )
            flow_id = cursor.lastrowid

            # Scan messages_api requests for secrets (use full content, not DB-truncated body)
            if category == "messages_api" and req_full:
                text_to_scan = _extract_text_from_messages(req_full)
                leak_count = 0

                for finding in scan_text(text_to_scan, flow_id):
                    con.execute(
                        """INSERT INTO leaks
                           (flow_id, ts, rule_id, severity, description,
                            redacted_match, context, entropy)
                           VALUES (?,?,?,?,?,?,?,?)""",
                        (
                            finding["flow_id"],
                            ts,
                            finding["rule_id"],
                            finding["severity"],
                            finding["description"],
                            finding["redacted_match"],
                            finding["context"],
                            finding["entropy"],
                        ),
                    )
                    leak_count += 1

                if leak_count > 0:
                    con.execute(
                        "UPDATE live_flows SET leak_count=? WHERE id=?",
                        (leak_count, flow_id),
                    )

            con.commit()
            con.close()

        except sqlite3.OperationalError as e:
            log.error(f"[claude-dashboard] DB write failed: {e}")


addon_instance = ClaudeDashboardAddon()
addons = [addon_instance]
