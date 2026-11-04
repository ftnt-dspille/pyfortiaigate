"""Troubleshooting logs: per-attempt debug lines, 5xx bodies and the enable switch."""

from __future__ import annotations

import logging

import pytest

from pyfortiaigate import FortiAIGate, ServerError, enable_logging

from .conftest import FakeFaig

CHAT = "/ai/openai/v1/chat/completions"
MSG = [{"role": "user", "content": "hi"}]
BROKEN = (500, {"error": {"message": "The provider returned an internal server error."}})


def test_each_attempt_is_logged_with_status_and_duration(
    fake: FakeFaig, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="pyfortiaigate")
    c = FortiAIGate(fake.url, token="t")
    fake.answer("POST", CHAT, (200, {"choices": []}))
    c.chat_completion("faig_secretvalue", "m", MSG)
    line = next(r.getMessage() for r in caplog.records if "-> HTTP 200" in r.getMessage())
    assert CHAT in line
    assert " ms" in line
    c.close()


def test_a_final_5xx_logs_its_body_and_never_the_key(
    fake: FakeFaig, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("pyfortiaigate.client.time.sleep", lambda _s: None)
    caplog.set_level(logging.DEBUG, logger="pyfortiaigate")
    c = FortiAIGate(fake.url, token="tok_should_not_appear")
    fake.answer("POST", CHAT, BROKEN)
    with pytest.raises(ServerError):
        c.chat_completion("faig_secretvalue", "m", MSG)
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert text.count("retry ") == 3
    assert "internal server error" in text
    final = [
        r for r in caplog.records if r.levelno == logging.WARNING and "retry" not in r.getMessage()
    ]
    assert final, "the 5xx that was finally raised is logged at WARNING"
    assert "faig_secretvalue" not in text
    assert "tok_should_not_appear" not in text
    c.close()


def test_enable_logging_writes_a_file_and_replaces_its_own_handler(
    tmp_path: pytest.TempPathFactory,
) -> None:
    lg = logging.getLogger("pyfortiaigate")
    before = list(lg.handlers)
    level = lg.level
    try:
        path = tmp_path / "faig.log"  # type: ignore[operator]
        enable_logging("debug", str(path))
        enable_logging("info", str(path))
        added = [h for h in lg.handlers if h not in before]
        assert len(added) == 1
        lg.info("hello %s", "world")
        added[0].flush()
        assert "INFO pyfortiaigate: hello world" in path.read_text()
        assert lg.level == logging.INFO
    finally:
        for h in [h for h in lg.handlers if h not in before]:
            lg.removeHandler(h)
            h.close()
        lg.setLevel(level)


def test_an_unknown_level_falls_back_to_debug() -> None:
    lg = logging.getLogger("pyfortiaigate")
    before, level = list(lg.handlers), lg.level
    try:
        enable_logging("loud")
        assert lg.level == logging.DEBUG
    finally:
        for h in [h for h in lg.handlers if h not in before]:
            lg.removeHandler(h)
            h.close()
        lg.setLevel(level)


@pytest.mark.parametrize(
    "leak",
    [
        "faig_abcdef123456",
        "Bearer abc.def.ghi",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig",
        '"password": "hunter2hunter2"',
        "api_key=sk-live-123456",
    ],
)
def test_a_logged_error_body_scrubs_keys_and_tokens(
    fake: FakeFaig,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    leak: str,
) -> None:
    monkeypatch.setattr("pyfortiaigate.client.time.sleep", lambda _s: None)
    caplog.set_level(logging.DEBUG, logger="pyfortiaigate")
    c = FortiAIGate(fake.url, token="t", server_retries=0)
    fake.answer("POST", CHAT, (500, {"error": {"message": f"upstream said {leak} ok"}}))
    with pytest.raises(ServerError):
        c.chat_completion("faig_x", "m", MSG)
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "[redacted]" in text
    assert leak.split()[-1].strip('"') not in text.replace("[redacted]", "")
    assert "upstream said" in text
    c.close()
