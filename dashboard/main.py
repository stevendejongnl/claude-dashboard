"""
FastAPI application. Serves the dashboard and WebSocket endpoint.
"""
import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

import aiosqlite
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from db import DB_PATH, init_db
from ingestor import run_ingestor

log = logging.getLogger("dashboard")

# --------------------------------------------------------------------------- #
# WebSocket connection manager
# --------------------------------------------------------------------------- #


class ConnectionManager:
    def __init__(self):
        self._clients: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._clients.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self._clients:
            self._clients.remove(ws)

    async def broadcast(self, msg: dict):
        dead = []
        for ws in self._clients:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


# --------------------------------------------------------------------------- #
# Background tasks
# --------------------------------------------------------------------------- #


async def _poll_new_flows():
    """
    Every second, query for flows newer than last seen id and broadcast them.
    This is the bridge between the SQLite-writing proxy addon and WebSocket clients.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Seed from current DB state so we only broadcast NEW rows going forward.
        # Without this, every restart re-broadcasts all historical rows at 100/s.
        async with db.execute("SELECT COALESCE(MAX(id), 0) FROM live_flows") as cur:
            last_flow_id = (await cur.fetchone())[0]
        async with db.execute("SELECT COALESCE(MAX(id), 0) FROM telemetry_events") as cur:
            last_event_id = (await cur.fetchone())[0]
        async with db.execute("SELECT COALESCE(MAX(id), 0) FROM leaks") as cur:
            last_leak_id = (await cur.fetchone())[0]

        while True:
            await asyncio.sleep(1)

            # New live flows
            async with db.execute(
                "SELECT * FROM live_flows WHERE id > ? ORDER BY id LIMIT 50",
                (last_flow_id,),
            ) as cur:
                rows = await cur.fetchall()
            for row in rows:
                last_flow_id = row["id"]
                await manager.broadcast({"type": "flow", "data": dict(row)})

            # New telemetry events
            async with db.execute(
                "SELECT * FROM telemetry_events WHERE id > ? ORDER BY id LIMIT 100",
                (last_event_id,),
            ) as cur:
                rows = await cur.fetchall()
            for row in rows:
                last_event_id = row["id"]
                await manager.broadcast({"type": "event", "data": dict(row)})

            # New leaks
            async with db.execute(
                "SELECT * FROM leaks WHERE id > ? ORDER BY id LIMIT 50",
                (last_leak_id,),
            ) as cur:
                rows = await cur.fetchall()
            for row in rows:
                last_leak_id = row["id"]
                await manager.broadcast({"type": "leak", "data": dict(row)})


# --------------------------------------------------------------------------- #
# FastAPI lifespan (replaces @app.on_event)
# --------------------------------------------------------------------------- #


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    asyncio.create_task(run_ingestor(), name="ingestor")
    asyncio.create_task(_poll_new_flows(), name="poller")
    yield


app = FastAPI(lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")


# --------------------------------------------------------------------------- #
# REST endpoints (used by frontend on initial load)
# --------------------------------------------------------------------------- #


@app.get("/")
async def index():
    return FileResponse("static/index.html")


@app.get("/api/flows")
async def get_flows(limit: int = 100, offset: int = 0):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM live_flows ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


@app.get("/api/events")
async def get_events(event_name: str | None = None, limit: int = 200):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if event_name:
            async with db.execute(
                "SELECT * FROM telemetry_events WHERE event_name=? ORDER BY id DESC LIMIT ?",
                (event_name, limit),
            ) as cur:
                rows = await cur.fetchall()
        else:
            async with db.execute(
                "SELECT * FROM telemetry_events ORDER BY id DESC LIMIT ?", (limit,)
            ) as cur:
                rows = await cur.fetchall()
    return [dict(r) for r in rows]


@app.get("/api/leaks")
async def get_leaks(severity: str | None = None, limit: int = 200):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if severity:
            async with db.execute(
                "SELECT * FROM leaks WHERE severity=? ORDER BY id DESC LIMIT ?",
                (severity, limit),
            ) as cur:
                rows = await cur.fetchall()
        else:
            async with db.execute(
                "SELECT * FROM leaks ORDER BY id DESC LIMIT ?", (limit,)
            ) as cur:
                rows = await cur.fetchall()
    return [dict(r) for r in rows]


@app.get("/api/sessions")
async def get_sessions(limit: int = 50):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM sessions ORDER BY end_ts DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


@app.get("/api/stats/cost")
async def get_cost_over_time():
    """Return (date, total_cost) for the API Stats chart."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT
                substr(end_ts, 1, 10) AS day,
                SUM(cost_usd)         AS total_cost,
                SUM(input_tokens)     AS input_tokens,
                SUM(output_tokens)    AS output_tokens,
                model
            FROM sessions
            GROUP BY day, model
            ORDER BY day
        """
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


@app.get("/api/cert")
async def get_ca_cert():
    """Serve the mitmproxy CA cert for easy download."""
    cert_path = "/home/mitmuser/.mitmproxy/mitmproxy-ca-cert.pem"
    return FileResponse(
        cert_path,
        media_type="application/x-pem-file",
        filename="claude-dashboard-ca.pem",
    )


# --------------------------------------------------------------------------- #
# WebSocket endpoint
# --------------------------------------------------------------------------- #


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            # Keep the connection alive; the server pushes data via broadcast()
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
