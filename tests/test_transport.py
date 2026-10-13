"""Retries, keep-alive reuse, and how HTTP answers map to results."""

from __future__ import annotations

import http.client
import io
import urllib.error
from typing import Any

import pytest

from pyfortiaigate import FaigError, FortiAIGate
from pyfortiaigate.client import _KeepAliveOpener, _Resp

from .conftest import DROP, FakeFaig


class Flaky:
    """An opener that raises each queued error once, then answers 200."""

    def __init__(self, *errors: BaseException):
        self.errors = list(errors)
        self.calls = 0

    def open(self, req: Any, timeout: float = 60) -> _Resp:
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return _Resp(200, b'{"ok": true}')

    def close(self) -> None:
        pass


def reset() -> urllib.error.URLError:
    return urllib.error.URLError(ConnectionResetError(54, "Connection reset by peer"))


@pytest.fixture
def anon() -> FortiAIGate:
    return FortiAIGate("https://faig.example.com", token="t")


def test_unanswered_request_is_retried_for_post(anon: FortiAIGate) -> None:
    anon._opener = Flaky(reset(), reset())  # type: ignore[assignment]
    assert anon.post("/api/v1/x") == {"ok": True}
    assert anon._opener.calls == 3  # type: ignore[attr-defined]


def test_retry_budget_then_the_error(anon: FortiAIGate) -> None:
    anon.retries = 2
    anon._opener = Flaky(reset(), reset(), reset())  # type: ignore[assignment]
    with pytest.raises(urllib.error.URLError):
        anon.get("/api/v1/x")
    assert anon._opener.calls == 3  # type: ignore[attr-defined]


def test_retries_log_a_warning(anon: FortiAIGate, caplog: pytest.LogCaptureFixture) -> None:
    anon._opener = Flaky(reset())  # type: ignore[assignment]
    anon.get("/api/v1/x")
    assert "retry 1/5" in caplog.text


@pytest.mark.parametrize(
    "err",
    [http.client.RemoteDisconnected("closed"), ConnectionResetError(54, "reset"), TimeoutError()],
)
def test_drop_after_send_retries_get(anon: FortiAIGate, err: BaseException) -> None:
    anon._opener = Flaky(err)  # type: ignore[assignment]
    assert anon.get("/api/v1/x") == {"ok": True}


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_drop_after_send_never_resends_a_mutation(anon: FortiAIGate, method: str) -> None:
    anon._opener = Flaky(http.client.RemoteDisconnected("closed"))  # type: ignore[assignment]
    with pytest.raises(http.client.RemoteDisconnected):
        anon.request(method, "/api/v1/x", {})
    assert anon._opener.calls == 1  # type: ignore[attr-defined]


def test_http_errors_are_not_retried(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/x", (503, {"message": "busy"}))
    with pytest.raises(FaigError, match="busy") as e:
        faig.get("/api/v1/x")
    assert e.value.status == 503
    assert e.value.method == "GET"
    assert e.value.path == "/api/v1/x"
    assert len(fake.calls("GET", "/api/v1/x")) == 1


def test_one_connection_is_reused(faig: FortiAIGate, fake: FakeFaig) -> None:
    for _ in range(5):
        faig.post("/api/v1/x")
    assert len(fake.seen) == 11  # login + 5 x (csrf + post)
    assert fake.connections == 1


def test_idle_connection_is_reopened(
    faig: FortiAIGate, fake: FakeFaig, monkeypatch: pytest.MonkeyPatch
) -> None:
    faig.me()
    monkeypatch.setattr(_KeepAliveOpener, "IDLE", -1.0)
    faig.me()
    assert fake.connections == 2


def test_server_close_is_honoured(faig: FortiAIGate, fake: FakeFaig) -> None:
    faig.me()
    faig._opener._conn.close()  # type: ignore[union-attr]  # server-side drop looks like this
    faig.me()  # unanswered on the dead socket -> URLError -> retried on a new connection
    assert fake.connections == 2


def test_connect_failure_is_an_unanswered_error() -> None:
    c = FortiAIGate("http://127.0.0.1:9", token="t", retries=0)  # discard port: refused
    with pytest.raises(urllib.error.URLError):
        c.post("/api/v1/x")


def test_empty_body_is_none(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("DELETE", "/api/v1/x", (204, None))
    assert faig.delete("/api/v1/x") is None


def test_mutations_without_a_body_send_an_empty_object(faig: FortiAIGate, fake: FakeFaig) -> None:
    faig.post("/api/v1/x")
    faig.delete("/api/v1/y")
    assert fake.calls("POST", "/api/v1/x")[0].body == {}
    assert fake.calls("DELETE", "/api/v1/y")[0].body is None


def test_paths_relative_to_api_and_query_params(faig: FortiAIGate, fake: FakeFaig) -> None:
    faig.get("v1/admin/users", {"limit": 5, "skip": None})
    faig.get("/api/v1/x?a=1", {"b": 2})
    assert fake.app_calls()[0].path == "/api/v1/admin/users"
    assert fake.app_calls()[0].query == "limit=5"
    assert fake.app_calls()[1].query == "a=1&b=2"


def test_error_message_prefers_the_json_error_field() -> None:
    assert "boom" in str(FaigError("GET", "/x", 500, '{"detail": "boom"}'))
    assert "plain text" in str(FaigError("GET", "/x", 500, "plain text"))
    assert '["a"]' in str(FaigError("GET", "/x", 500, '["a"]'))


def test_http_error_body_is_returned_for_status_mapping() -> None:
    err = urllib.error.HTTPError("u", 409, "conflict", http.client.HTTPMessage(), io.BytesIO(b"x"))
    c = FortiAIGate("https://faig.example.com", token="t")
    c._opener = Flaky(err)  # type: ignore[assignment]
    assert c._raw("GET", "https://faig.example.com/api/v1/x") == (409, "x")


def test_https_connection_is_built_with_the_context(monkeypatch: pytest.MonkeyPatch) -> None:
    made: dict[str, Any] = {}

    class Conn:
        def __init__(self, host: str, port: int, context: Any = None, timeout: float = 0) -> None:
            made.update(host=host, port=port, context=context)

        def connect(self) -> None:
            raise OSError("no network in tests")

        def close(self) -> None:
            pass

    monkeypatch.setattr("pyfortiaigate.client.http.client.HTTPSConnection", Conn)
    c = FortiAIGate("faig.example.com", token="t", retries=0)
    with pytest.raises(urllib.error.URLError):
        c.me()
    assert made == {"host": "faig.example.com", "port": 443, "context": c._ctx}


def test_real_drop_after_send_retries_get(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/x", (DROP, None), (200, {"ok": 1}))
    assert faig.get("/api/v1/x") == {"ok": 1}
    assert len(fake.calls("GET", "/api/v1/x")) == 2


def test_real_drop_after_send_does_not_resend_post(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", "/api/v1/x", (DROP, None), (200, {}))
    with pytest.raises(http.client.RemoteDisconnected):
        faig.post("/api/v1/x")
    assert len(fake.calls("POST", "/api/v1/x")) == 1
    assert faig.me() == {}  # the dropped connection was discarded; the next call reconnects


def test_connection_close_from_the_server_is_honoured(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/user", (200, {}, {"Connection": "close"}))
    faig.me()
    assert faig._opener._conn is None
    faig.me()
    assert fake.connections == 2
