"""The local GUI server: standard-library HTTP on 127.0.0.1 only, for one person at this computer.

Who may call it: whoever opened the launch URL printed in the terminal. Its token becomes an HttpOnly, SameSite=Strict
cookie that every page, API call and progress stream needs. Requests naming any other Host (DNS rebinding) and
state-changing requests from any other Origin are refused, and no CORS headers are ever sent. API keys stay in this
process: no response carries them.
"""
import dataclasses
import hmac
import json
import platform
import secrets
import shutil
import subprocess
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

from .errors import ConfigurationError
from .fleet import check_all
from .gui_tasks import FINAL, TaskError, TaskManager, dumps

STATIC = Path(__file__).with_name("static")
MAX_BODY = 5 * 1024 * 1024
_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".woff2": "font/woff2"}
_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class GuiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int = 0, tasks: Optional[TaskManager] = None, environ: Optional[Mapping[str, str]] = None) -> None:
        super().__init__(("127.0.0.1", port), Handler)
        self.token = secrets.token_urlsafe(32)
        self.environ = environ
        self.tasks = tasks or TaskManager(environ=environ)
        port = self.server_address[1]
        self.hosts = {"127.0.0.1:{}".format(port), "localhost:{}".format(port), "[::1]:{}".format(port)}
        self.url = "http://127.0.0.1:{}/?token={}".format(port, self.token)
        self.cookie = "edgeconnect_gui_{}".format(port)  # cookies ignore the port, so two GUIs on one computer need different names


class Handler(BaseHTTPRequestHandler):
    server: GuiServer
    server_version = "edgeconnect-gui"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:  # the launch token is in a URL; keep request lines out of the terminal
        pass

    def do_GET(self) -> None:
        self._route("GET")

    def do_POST(self) -> None:
        self._route("POST")

    def _route(self, method: str) -> None:
        try:
            self._guard(method)
            parts = urlsplit(self.path)
            path = parts.path
            if method == "GET" and path == "/" and "token" in parse_qs(parts.query):
                return self._login(parse_qs(parts.query)["token"][0])
            self._require_cookie()
            if method == "GET" and path.startswith("/api/"):
                return self._get_api(path)
            if method == "POST" and path.startswith("/api/"):
                return self._post_api(path)
            if method == "GET":
                return self._static(path)
            raise TaskError("not found", 404)
        except TaskError as error:
            self._json(error.status, {"error": str(error)})

    def _guard(self, method: str) -> None:
        host = self.headers.get("Host", "")
        if host not in self.server.hosts:
            raise TaskError("this server only answers to 127.0.0.1, localhost or [::1] on its own port", 421)
        if method != "GET" and self.headers.get("Origin") != "http://" + host:
            raise TaskError("cross-origin request refused", 403)

    def _require_cookie(self) -> None:
        for item in self.headers.get("Cookie", "").split(";"):
            name, _, value = item.strip().partition("=")
            if name == self.server.cookie and hmac.compare_digest(value.encode(), self.server.token.encode()):
                return
        raise TaskError("open the GUI with the link printed in the terminal", 401)

    def _login(self, token: str) -> None:
        if not hmac.compare_digest(token.encode(), self.server.token.encode()):
            raise TaskError("this link is not valid for this GUI; use the link printed in the terminal", 401)
        self.send_response(303)
        self._security_headers()
        self.send_header("Set-Cookie", "{}={}; HttpOnly; SameSite=Strict; Path=/".format(self.server.cookie, self.server.token))
        self.send_header("Location", "/")  # drops the token from the address bar
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _get_api(self, path: str) -> None:
        tasks = self.server.tasks
        if path == "/api/orchestrators":
            try:
                statuses = check_all(environ=self.server.environ)
            except ConfigurationError as error:
                raise TaskError(str(error)) from None
            return self._json(200, {"orchestrators": [dataclasses.asdict(status) for status in statuses]})
        if path == "/api/tasks":
            return self._json(200, {"tasks": [task.view() for task in tasks.list()]})
        task_id, action = _task_path(path)
        if action == "":
            return self._json(200, tasks.get(task_id).view())
        if action == "events":
            return self._events(task_id)
        raise TaskError("not found", 404)

    def _post_api(self, path: str) -> None:
        if self.headers.get_content_type() != "application/json":
            raise TaskError("send JSON (Content-Type: application/json)", 415)
        body = self._body()
        tasks = self.server.tasks
        if path == "/api/tasks":
            return self._json(201, tasks.create(body).view())
        task_id, action = _task_path(path)
        if action == "approve":
            return self._json(202, tasks.approve(task_id, body.get("answers")).view())
        if action == "cancel":
            return self._json(202, tasks.cancel(task_id).view())
        raise TaskError("not found", 404)

    def _body(self) -> Mapping[str, Any]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_BODY:
            raise TaskError("request body too large or without a length", 413)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TaskError("request body is not valid JSON") from None
        if not isinstance(body, dict):
            raise TaskError("request body must be a JSON object")
        return body

    def _events(self, task_id: str) -> None:
        """Server-sent events: every state change of the task, then the stream closes when the task is finished."""
        task = self.server.tasks.get(task_id)
        self.send_response(200)
        self._security_headers()
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        sent = 0
        while True:
            with task.changed:
                if sent == len(task.events) and task.state not in FINAL:
                    task.changed.wait(15)
                events, finished = task.events[sent:], task.state in FINAL
            try:
                for event in events:
                    self.wfile.write(b"data: " + dumps(dict(event, task=task.view())) + b"\n\n")
                if not events:
                    self.wfile.write(b": keep-alive\n\n")
                self.wfile.flush()
            except OSError:
                return  # the browser went away
            sent += len(events)
            if finished and sent == len(task.events):
                return

    def _static(self, path: str) -> None:
        name = "index.html" if path == "/" else path.lstrip("/")
        files = {item.name: item for item in STATIC.iterdir() if item.is_file()}
        if name not in files:
            raise TaskError("not found", 404)
        self._send(200, files[name].read_bytes(), _TYPES.get(files[name].suffix, "application/octet-stream"))

    def _json(self, status: int, value: Any) -> None:
        self._send(status, dumps(value), "application/json")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _security_headers(self) -> None:
        for name, value in _HEADERS.items():
            self.send_header(name, value)


def _task_path(path: str) -> Tuple[str, str]:
    """/api/tasks/<id>[/<action>] -> (id, action)."""
    parts = path.split("/")
    if len(parts) not in (4, 5) or parts[:3] != ["", "api", "tasks"] or not parts[3]:
        raise TaskError("not found", 404)
    return parts[3], parts[4] if len(parts) == 5 else ""


def open_browser(url: str) -> None:
    """On WSL, open the Windows browser (wslview, else explorer.exe); elsewhere the system browser. Failures are ignored: the URL is printed."""
    if "microsoft" in platform.release().lower():  # WSL 1 and 2 kernels both name Microsoft
        command = shutil.which("wslview") or shutil.which("explorer.exe")
        if command:
            subprocess.Popen([command, url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    webbrowser.open(url)


def serve(port: int = 0, browser: bool = True) -> int:
    server = GuiServer(port)
    print("EXPERIMENTAL edgeconnect-auto GUI. Open this link in your browser (it is your sign-in; do not share it):\n\n  {}\n\nPress Ctrl+C to stop.".format(server.url), flush=True)
    if browser:
        open_browser(server.url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("GUI stopped.", file=sys.stderr)
    finally:
        server.server_close()
    return 0
