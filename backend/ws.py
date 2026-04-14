from fastapi import WebSocket
from typing import Dict

class ConnectionManager:
    def __init__(self):
        # Maps username -> WebSocket
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, ws: WebSocket, username: str):
        await ws.accept()
        self.active_connections[username] = ws
        print(f"[WS] {username} connected. Total active: {len(self.active_connections)}")

    def disconnect(self, username: str):
        if username in self.active_connections:
            del self.active_connections[username]
            print(f"[WS] {username} disconnected.")

    async def send_to_user(self, username: str, data: dict):
        if username in self.active_connections:
            await self.active_connections[username].send_json(data)
            return True
        return False

manager = ConnectionManager()
