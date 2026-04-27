"""
WebSocket connection manager.
Clients subscribe by project id.
Data events:  { pid, entity, action, data }
Presence:     { type: "presence", users: [{name, note_id}] }
"""
import json
from typing import Any
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self._rooms: dict[str, set[WebSocket]] = {}
        self._users: dict[WebSocket, dict] = {}   # ws -> {name, note_id, pid}

    async def connect(self, ws: WebSocket, pid: str, name: str):
        await ws.accept()
        self._rooms.setdefault(pid, set()).add(ws)
        self._users[ws] = {"name": name or "Anonymous", "note_id": None, "pid": pid}

    def disconnect(self, ws: WebSocket, pid: str):
        room = self._rooms.get(pid, set())
        room.discard(ws)
        if not room:
            self._rooms.pop(pid, None)
        self._users.pop(ws, None)

    def set_focus(self, ws: WebSocket, note_id: str | None):
        if ws in self._users:
            self._users[ws]["note_id"] = note_id

    def get_presence(self, pid: str) -> list:
        return [
            {"name": u["name"], "note_id": u["note_id"]}
            for u in self._users.values()
            if u["pid"] == pid
        ]

    def get_all_online(self) -> list[str]:
        return list({u["name"] for u in self._users.values()})

    async def broadcast(self, pid: str, msg: dict[str, Any], exclude: WebSocket | None = None):
        dead = set()
        for ws in list(self._rooms.get(pid, set())):
            if ws is exclude:
                continue
            try:
                await ws.send_text(json.dumps(msg))
            except Exception:
                dead.add(ws)
        for ws in dead:
            self._rooms.get(pid, set()).discard(ws)

    async def broadcast_presence(self, pid: str):
        await self.broadcast(pid, {"type": "presence", "users": self.get_presence(pid)})


manager = ConnectionManager()
