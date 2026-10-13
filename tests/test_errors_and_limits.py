"""Typed errors, 429 waiting and streamed chat completions."""

from __future__ import annotations

import email.utils
import json
from typing import Any

import pytest

from pyfortiaigate import (
    AuthError,
    Conflict,
    FaigError,
    FortiAIGate,
    ModelNotAvailable,
    NotFound,
    RateLimited,
    ServerError,
    ValidationError,
    blocked,
    collect_stream,
    error_for,
)
from pyfortiaigate.client import _retry_after

from .conftest import FakeFaig

CHAT = "/ai/openai/v1/chat/completions"
MSG = [{"role": "user", "content": "hi"}]


@pytest.mark.parametrize(
    ("status", "cls"),
    [
        (400, ValidationError),
        (401, AuthError),
        (403, AuthError),
        (404, NotFound),
        (409, Conflict),
        (422, ValidationError),
        (429, RateLimited),
        (500, ServerError),
        (503, ServerError),
        (418, FaigError),
    ],
)
def test_error_class_by_status(status: int, cls: type[FaigError]) -> None:
    e = error_for("GET", "/x", status, "{}")
    assert type(e) is cls
    assert isinstance(e, FaigError)
    assert e.status == status


def test_error_fields_from_a_conflict_body() -> None:
    body = '{"error": "A detector named \\"x\\" already exists", "field": "name"}'
    e = error_for("POST", "/d", 409, body)
    assert e.field == "name"
    assert e.code is None
    assert e.data["field"] == "name"
    assert "already exists" in str(e)


def test_error_with_a_non_json_body() -> None:
    e = error_for("GET", "/x", 502, "<html>bad gateway</html>")
    assert e.data is None
    assert e.field is None
    assert "bad gateway" in str(e)


def test_model_not_available_from_the_gateway(faig: FortiAIGate, fake: FakeFaig) -> None:
    body = {
        "error": {
            "message": "model nope is not available to this API key",
            "type": "not_found_error",
            "code": "model_not_found",
        }
    }
    fake.answer("POST", CHAT, (404, body))
    with pytest.raises(ModelNotAvailable, match="model nope is not available") as info:
        faig.chat_completion("faig_x", "nope", MSG)
    assert info.value.code == "model_not_found"
    assert isinstance(info.value, NotFound)


def test_other_gateway_404_is_plain_not_found(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", CHAT, (404, {"error": {"message": "no route", "code": "other"}}))
    with pytest.raises(NotFound) as info:
        faig.chat_completion("faig_x", "m", MSG)
    assert type(info.value) is NotFound


def test_management_404_is_not_found(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/users/u1", (404, {"error": "no such user"}))
    with pytest.raises(NotFound, match="no such user"):
        faig.user("u1")


# -- 429 ---------------------------------------------------------------------------
LIMITED = (429, {"error": {"message": "rate limit exceeded", "code": "rate_limit_exceeded"}})


def test_429_raises_at_once_by_default(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", CHAT, LIMITED)
    with pytest.raises(RateLimited, match="rate limit exceeded"):
        faig.chat_completion("faig_x", "m", MSG)
    assert len(fake.calls("POST", CHAT)) == 1


def test_429_waits_and_retries_within_the_budget(
    fake: FakeFaig, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr("pyfortiaigate.client.time.sleep", sleeps.append)
    c = FortiAIGate(fake.url, token="t", rate_limit_wait=10)
    fake.answer("POST", CHAT, LIMITED, LIMITED, (200, {"choices": []}))
    assert c.chat_completion("faig_x", "m", MSG) == {"choices": []}
    assert sleeps == [1.0, 2.0]  # no Retry-After: exponential backoff
    c.close()


def test_429_honours_retry_after_and_gives_up_past_the_budget(
    fake: FakeFaig, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr("pyfortiaigate.client.time.sleep", sleeps.append)
    c = FortiAIGate(fake.url, token="t", rate_limit_wait=5)
    fake.answer("GET", "/api/v1/user", (*LIMITED, {"Retry-After": "3"}))
    with pytest.raises(RateLimited):
        c.me()
    assert sleeps == [3.0, 2.0]  # 3s as asked, then the 2s left in the budget
    assert len(fake.calls("GET", "/api/v1/user")) == 3
    c.close()


def test_retry_after_parsing() -> None:
    assert _retry_after(None) is None
    assert _retry_after({}) is None
    assert _retry_after({"Retry-After": "7"}) == 7.0
    assert _retry_after({"Retry-After": "-4"}) == 0.0
    assert _retry_after({"Retry-After": "soon"}) is None
    past = email.utils.formatdate(0, usegmt=True)
    assert _retry_after({"Retry-After": past}) == 0.0
    future = email.utils.formatdate(4102444800, usegmt=True)  # 2100
    assert (_retry_after({"Retry-After": future}) or 0) > 1000


# -- streaming ---------------------------------------------------------------------------
def _sse(*events: Any) -> bytes:
    out = b": keep-alive\n\n"
    for e in events:
        out += b"data: " + (e if isinstance(e, bytes) else json.dumps(e).encode()) + b"\n\n"
    return out


def _chunk(content: str | None = None, finish: str | None = None, **delta: Any) -> dict[str, Any]:
    d = dict(delta)
    if content is not None:
        d["content"] = content
    return {
        "id": "c1",
        "model": "m",
        "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": d, "finish_reason": finish}],
    }


STREAM_HEADERS = {"Content-Type": "text/event-stream; charset=utf-8"}


def test_stream_yields_chunks_and_collects(faig: FortiAIGate, fake: FakeFaig) -> None:
    body = _sse(
        _chunk("", role="assistant"), _chunk("Hel"), _chunk("lo"), _chunk(None, "stop"), b"[DONE]"
    )
    fake.answer("POST", CHAT, (200, body, STREAM_HEADERS))
    chunks = list(faig.chat_completion_stream("faig_x", "m", MSG, max_tokens=5, temperature=0))
    assert len(chunks) == 4
    sent = fake.calls("POST", CHAT)[0]
    assert sent.body["stream"] is True
    assert sent.body["max_tokens"] == 5
    assert sent.body["temperature"] == 0.0
    assert sent.headers["authorization"] == "Bearer faig_x"
    out = collect_stream(chunks)
    assert out["choices"][0]["message"] == {"role": "assistant", "content": "Hello"}
    assert out["choices"][0]["finish_reason"] == "stop"
    assert out["id"] == "c1"
    assert not blocked(out)


def test_stream_block_is_a_content_filter_chunk(faig: FortiAIGate, fake: FakeFaig) -> None:
    body = _sse(
        _chunk("This request was blocked by FortiAIGate.", role="assistant"),
        _chunk(None, "content_filter"),
        b"[DONE]",
    )
    fake.answer("POST", CHAT, (200, body, STREAM_HEADERS))
    assert blocked(collect_stream(faig.chat_completion_stream("faig_x", "m", MSG)))


def test_stream_ends_without_done(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", CHAT, (200, _sse(_chunk("x"), b""), STREAM_HEADERS))
    assert len(list(faig.chat_completion_stream("faig_x", "m", MSG))) == 1


def test_stream_answered_without_streaming(faig: FortiAIGate, fake: FakeFaig) -> None:
    whole = {"object": "chat.completion", "choices": [{"message": {"content": "hi"}}]}
    fake.answer("POST", CHAT, (200, whole))
    chunks = list(faig.chat_completion_stream("faig_x", "m", MSG))
    assert chunks == [whole]
    assert collect_stream(chunks) == whole


def test_stream_error_status_raises(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", CHAT, (404, {"error": {"message": "nope", "code": "model_not_found"}}))
    with pytest.raises(ModelNotAvailable):
        list(faig.chat_completion_stream("faig_x", "m", MSG))


def test_stream_needs_messages(faig: FortiAIGate) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        list(faig.chat_completion_stream("faig_x", "m", []))


def test_stream_over_https_uses_the_client_tls_context(
    faig: FortiAIGate, monkeypatch: pytest.MonkeyPatch
) -> None:
    made: dict[str, Any] = {}

    class Conn:
        def __init__(self, host: str, port: int, context: Any = None, timeout: float = 0):
            made.update(host=host, port=port, context=context)

        def request(self, *a: Any, **kw: Any) -> None:
            raise ConnectionRefusedError("no")

        def close(self) -> None:
            made["closed"] = True

    monkeypatch.setattr("pyfortiaigate.client.http.client.HTTPSConnection", Conn)
    faig.gateway_url = "https://gw.example.com"
    with pytest.raises(ConnectionRefusedError):
        list(faig.chat_completion_stream("faig_x", "m", MSG))
    assert made == {"host": "gw.example.com", "port": 443, "context": faig._ctx, "closed": True}


def test_collect_stream_orders_choices_and_keeps_usage() -> None:
    chunks = [
        {"object": "chat.completion.chunk", "choices": [{"index": 1, "delta": {"content": "b"}}]},
        {"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": "a"}}]},
        {"object": "chat.completion.chunk", "choices": [], "usage": {"total_tokens": 3}},
    ]
    out = collect_stream(chunks)
    assert [c["message"]["content"] for c in out["choices"]] == ["a", "b"]
    assert out["usage"] == {"total_tokens": 3}
