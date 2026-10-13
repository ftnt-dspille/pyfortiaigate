"""A local stand-in for a FortiAIGate: a real HTTP/1.1 server (keep-alive,
cookies), so the tests exercise the client's actual transport instead of
mocks. Routes not scripted by a test answer 200 ``{}``."""

from __future__ import annotations

import json
import re
import threading
from collections import defaultdict, deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from pyfortiaigate import FortiAIGate
from pyfortiaigate.cli import main

Answer = tuple[Any, ...] | Callable[["Seen"], tuple[Any, ...]]

# An answer of (DROP, None) closes the connection without responding: the
# request was delivered, the response never came.
DROP = -1


@dataclass
class Seen:
    method: str
    path: str  # without the query string
    query: str
    headers: dict[str, str]
    body: Any

    @property
    def key(self) -> tuple[str, str]:
        return self.method, self.path


@dataclass
class FakeFaig:
    """``answer(method, path, *answers)`` queues answers for a route (the last
    one repeats); an answer is (status, body) or (status, body, headers).
    ``seen`` records every request in order."""

    url: str = ""
    seen: list[Seen] = field(default_factory=list)
    connections: int = 0
    session_ok: bool = True
    routes: dict[tuple[str, str], deque[Answer]] = field(default_factory=lambda: defaultdict(deque))

    def answer(self, method: str, path: str, *answers: Answer) -> None:
        self.routes[(method, path)].extend(answers)

    def calls(self, method: str | None = None, path: str | None = None) -> list[Seen]:
        return [
            s
            for s in self.seen
            if (method is None or s.method == method) and (path is None or s.path == path)
        ]

    def app_calls(self) -> list[Seen]:
        """Every request except login, CSRF and logout plumbing."""
        plumbing = {"/api/v1/login", "/api/login", "/api/csrf-token", "/api/v1/logout"}
        return [s for s in self.seen if s.path not in plumbing]

    def respond(self, seen: Seen) -> tuple[int, Any, dict[str, str]]:
        q = self.routes.get(seen.key)
        if q:
            a = q.popleft() if len(q) > 1 else q[0]
            status, body, *extra = a(seen) if callable(a) else a
            return status, body, (extra[0] if extra else {})
        if seen.path in ("/api/v1/login", "/api/login"):
            return 200, {"csrf_token": "login-token"}, {"Set-Cookie": "session_id=s1; Path=/"}
        if seen.path == "/api/csrf-token":
            return 200, {"csrf_token": f"csrf-{len(self.calls(path='/api/csrf-token'))}"}, {}
        return 200, {}, {}


def _handler(fake: FakeFaig) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            super().setup()
            fake.connections += 1

        def log_message(self, *args: Any) -> None:
            pass

        def _serve(self) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            u = urlsplit(self.path)
            seen = Seen(
                self.command,
                u.path,
                u.query,
                {k.lower(): v for k, v in self.headers.items()},
                json.loads(raw) if raw else None,
            )
            fake.seen.append(seen)
            status, body, headers = fake.respond(seen)
            if status == DROP:
                self.close_connection = True
                return
            data = (
                b""
                if body is None
                else (body if isinstance(body, bytes) else json.dumps(body).encode())
            )
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            if not any(k.lower() == "content-type" for k in headers):
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _serve

    return Handler


@pytest.fixture
def fake() -> Iterator[FakeFaig]:
    f = FakeFaig()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(f))
    server.daemon_threads = True
    f.url = f"http://127.0.0.1:{server.server_address[1]}"
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    t.start()
    yield f
    server.shutdown()
    server.server_close()


@pytest.fixture
def faig(fake: FakeFaig) -> Iterator[FortiAIGate]:
    """An admin client against the fake; retries never sleep."""
    c = FortiAIGate(fake.url, "admin", "pw")
    # Short test ids ("w1") are not UUIDs; seed them so no name lookup happens.
    c._ws_ids.update({f"w{i}": f"w{i}" for i in range(10)})
    yield c
    c._opener.close()


# Short test ids ("d1", "k2") stand in for UUIDs: they pass through as ids
# without a name lookup. Names in tests contain a dash or letters after digits.
TEST_ID = re.compile(
    r"^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[a-z]\d+)$"
)


@pytest.fixture(autouse=True)
def _short_ids(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    if "live" not in request.keywords:
        monkeypatch.setattr("pyfortiaigate.client._UUID", TEST_ID)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("pyfortiaigate.client.time.sleep", lambda s: None)


# -- the command line --------------------------------------------------------------
@pytest.fixture
def cli_env(fake: FakeFaig, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FakeFaig:
    for var in (
        "FAIG_TOKEN",
        "FAIG_KEY",
        "FAIG_WS",
        "FAIG_CA_BUNDLE",
        "FAIG_VERIFY_TLS",
        "FAIG_ENV_FILE",
        "FAIG_CLI_STYLE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))  # no real ~/.config
    monkeypatch.setenv("FAIG_URL", fake.url)
    monkeypatch.setenv("FAIG_USERNAME", "admin")
    monkeypatch.setenv("FAIG_PASSWORD", "pw")
    monkeypatch.chdir(tmp_path)  # no stray .env
    return fake


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err
