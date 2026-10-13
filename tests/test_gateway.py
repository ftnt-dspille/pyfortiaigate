"""The OpenAI-compatible gateway: key checks and chat completions."""

from __future__ import annotations

import pytest

from pyfortiaigate import FaigError, FortiAIGate, blocked

from .conftest import FakeFaig

COMPLETION = {
    "model": "gpt",
    "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
}


def test_check_key_valid(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/ai/openai/v1/models", (200, {"data": [{"id": "a"}, {"id": "b"}]}))
    assert faig.check_key("faig_x") == {"valid": True, "model_count": 2, "http_status": 200}
    call = fake.calls("GET", "/ai/openai/v1/models")[0]
    assert call.headers["authorization"] == "Bearer faig_x"
    assert fake.calls("POST", "/api/v1/login") == []  # the gateway never needs a session


@pytest.mark.parametrize("status", [401, 403])
def test_check_key_rejected(faig: FortiAIGate, fake: FakeFaig, status: int) -> None:
    fake.answer("GET", "/ai/openai/v1/models", (status, {}))
    assert faig.check_key("faig_x") == {"valid": False, "model_count": 0, "http_status": status}


def test_check_key_unexpected_status_raises(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/ai/openai/v1/models", (502, {"error": "upstream"}))
    with pytest.raises(FaigError, match="upstream"):
        faig.check_key("faig_x")


def test_chat_completion(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", "/ai/openai/v1/chat/completions", (200, COMPLETION))
    msgs = [{"role": "user", "content": "hello"}]
    out = faig.chat_completion("faig_x", "gpt", msgs, max_tokens=16, temperature=0, user="u1")
    assert out == COMPLETION
    assert not blocked(out)
    assert fake.calls("POST", "/ai/openai/v1/chat/completions")[0].body == {
        "model": "gpt",
        "messages": msgs,
        "stream": False,
        "user": "u1",
        "max_tokens": 16,
        "temperature": 0.0,
    }


def test_chat_completion_blocked_is_not_an_error(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer(
        "POST",
        "/ai/openai/v1/chat/completions",
        (200, {"choices": [{"message": {"content": ""}, "finish_reason": "content_filter"}]}),
    )
    assert blocked(faig.chat_completion("faig_x", "gpt", [{"role": "user", "content": "ssn"}]))


def test_chat_completion_error(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", "/ai/openai/v1/chat/completions", (401, {"error": "bad key"}))
    with pytest.raises(FaigError, match="bad key"):
        faig.chat_completion("faig_x", "gpt", [{"role": "user", "content": "x"}])


def test_chat_completion_needs_messages(faig: FortiAIGate) -> None:
    with pytest.raises(ValueError, match="messages"):
        faig.chat_completion("faig_x", "gpt", [])


def test_separate_gateway_url(fake: FakeFaig) -> None:
    c = FortiAIGate("https://mgmt.example.com", token="t", gateway_url=fake.url)
    fake.answer("GET", "/ai/openai/v1/models", (200, []))
    assert c.check_key("faig_x")["valid"]
    assert c.gateway_url == fake.url
