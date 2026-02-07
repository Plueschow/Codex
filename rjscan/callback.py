from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Dict, Optional
import time
import urllib.parse


@dataclass
class CallbackEvent:
    token: str
    path: str
    timestamp: float


class CallbackRegistry:
    def __init__(self) -> None:
        self.events: Dict[str, CallbackEvent] = {}

    def record(self, token: str, path: str) -> None:
        self.events[token] = CallbackEvent(token=token, path=path, timestamp=time.time())

    def get(self, token: str) -> Optional[CallbackEvent]:
        return self.events.get(token)

    def wait_for(self, token: str, timeout: float) -> Optional[CallbackEvent]:
        end = time.time() + timeout
        while time.time() < end:
            event = self.get(token)
            if event:
                return event
            time.sleep(0.1)
        return None


class _Handler(BaseHTTPRequestHandler):
    registry: CallbackRegistry

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        token = params.get("token", [""])[0]
        if token:
            self.registry.record(token, self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args) -> None:
        return


class CallbackServer:
    def __init__(self, host: str, port: int) -> None:
        self.registry = CallbackRegistry()
        handler = type("Handler", (_Handler,), {"registry": self.registry})
        self.httpd = HTTPServer((host, port), handler)
        self.thread = Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def address(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.thread.join(timeout=2)
