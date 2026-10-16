"""Names, ensure_*, typed errors, rate limits, streaming, waiting for traffic,
the audit iterator and the CLI, against a real FortiAIGate. Opt-in, like
test_live_write: writes stay in FAIG_WRITE_WORKSPACE under a ``pytest-`` name
and are deleted afterwards (leftovers from a crashed run are swept first).

Creates and deletes: a regex detector, a guardrail, a policy and a virtual
key; sends a handful of short chat completions through the workspace's first
OpenAI model (or FAIG_TEST_MODEL)."""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import logging
import os
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from pyfortiaigate import (
    Conflict,
    FortiAIGate,
    ModelNotAvailable,
    NotFound,
    RateLimited,
    blocked,
    collect_stream,
    regex_detector_body,
)
from pyfortiaigate.cli import main

from .test_live_write import PREFIX, sweep

WORKSPACE = os.environ.get("FAIG_WRITE_WORKSPACE", "")
RUN = PREFIX + uuid.uuid4().hex[:8] + "-n"
SECRET_TEXT = "the launch code is ZEBRA-7731"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not (os.environ.get("FAIG_LIVE") and WORKSPACE),
        reason="set FAIG_LIVE=1 and FAIG_WRITE_WORKSPACE=<name> to run",
    ),
]


@pytest.fixture(scope="module")
def faig() -> Iterator[FortiAIGate]:
    with FortiAIGate.from_env() as c:
        yield c


@pytest.fixture(scope="module")
def ws(faig: FortiAIGate) -> Iterator[str]:
    sweep(faig, faig.resolve_workspace(WORKSPACE))
    yield WORKSPACE  # by NAME: every call below resolves it
    sweep(faig, faig.resolve_workspace(WORKSPACE))


@pytest.fixture(scope="module")
def state() -> dict[str, Any]:
    return {}


def need(state: dict[str, Any], *keys: str) -> None:
    missing = [k for k in keys if k not in state]
    if missing:
        pytest.skip(f"an earlier step failed: no {', '.join(missing)}")


def _detector(pattern: str = r"ZEBRA-\d{4}") -> dict[str, Any]:
    return regex_detector_body(f"{RUN}-det", [("launch-code", pattern, "block")])


def test_ensure_detector_is_idempotent(faig: FortiAIGate, ws: str, state: dict[str, Any]) -> None:
    first = faig.ensure_detector(ws, _detector())
    assert first.action == "created"
    assert first.record["approvalStatus"] == "active"
    again = faig.ensure_detector(ws, _detector())
    assert again.action == "unchanged", "a re-run should change nothing"
    assert again.id == first.id
    changed = faig.ensure_detector(ws, _detector(r"ZEBRA-\d{3,4}"))
    assert changed.action == "updated"
    assert changed.record["approvalStatus"] == "active"
    assert faig.ensure_detector(ws, _detector(r"ZEBRA-\d{3,4}")).action == "unchanged"
    state["det"] = first.id


def test_duplicate_name_is_a_conflict(faig: FortiAIGate, ws: str, state: dict[str, Any]) -> None:
    need(state, "det")
    with pytest.raises(Conflict) as info:
        faig.create_detector(ws, _detector())
    assert info.value.field == "name"


def test_detector_by_name(faig: FortiAIGate, ws: str, state: dict[str, Any]) -> None:
    need(state, "det")
    assert faig.resolve_detector(f"{RUN}-det", ws) == state["det"]
    hit = faig.test_detector(ws, f"{RUN}-det", SECRET_TEXT)
    miss = faig.test_detector(ws, f"{RUN}-det", "nothing here")
    assert hit != miss


def test_ensure_guardrail_by_detector_name(
    faig: FortiAIGate, ws: str, state: dict[str, Any]
) -> None:
    need(state, "det")
    g = faig.ensure_guardrail(ws, f"{RUN}-gr", [f"{RUN}-det"])
    assert g.action == "created"
    assert g.record["status"] == "active"
    assert g.record["detectorIds"] == [state["det"]]
    assert faig.ensure_guardrail(ws, f"{RUN}-gr", [state["det"]]).action == "unchanged"
    scan = faig.test_guardrail(SECRET_TEXT, guardrail_id=f"{RUN}-gr", ws_id=ws)
    assert scan["finalDisposition"] == "block", scan
    state["gr"] = g.id


def test_ensure_policy_by_guardrail_name(faig: FortiAIGate, ws: str, state: dict[str, Any]) -> None:
    need(state, "gr")
    args = (ws, f"{RUN}-pol", [f"{RUN}-gr"], [f"{RUN}-gr"])
    p = faig.ensure_policy(*args, provider_ids=["openai"])
    assert p.action == "created"
    assert p.record["status"] == "active"
    assert faig.ensure_policy(*args, provider_ids=["openai"]).action == "unchanged"
    state["pol"] = p.id


def test_ensure_virtual_key(faig: FortiAIGate, ws: str, state: dict[str, Any]) -> None:
    need(state, "pol")
    k = faig.ensure_virtual_key(
        ws, f"{RUN}-key", policy_ids=[f"{RUN}-pol"], provider_ids=["openai"]
    )
    assert k.action == "created"
    assert k.secret
    state["secret"], state["key"] = k.secret, k.id
    again = faig.ensure_virtual_key(
        ws, f"{RUN}-key", policy_ids=[f"{RUN}-pol"], provider_ids=["openai"]
    )
    assert (again.action, again.secret, again.id) == ("unchanged", None, k.id)
    assert faig.virtual_key(k.secret)["keyName"] == f"{RUN}-key"  # by secret
    assert faig.virtual_key(f"{RUN}-key", ws)["id"] == k.id  # by name


def _model(faig: FortiAIGate, secret: str) -> str:
    if os.environ.get("FAIG_TEST_MODEL"):
        return os.environ["FAIG_TEST_MODEL"]
    models = [m for m in faig.available_models(secret) if "gpt" in m]
    if not models:
        pytest.skip("no OpenAI model on the key; set FAIG_TEST_MODEL")
    return models[0]


def test_unknown_model_is_model_not_available(faig: FortiAIGate, state: dict[str, Any]) -> None:
    need(state, "secret")
    msgs = [{"role": "user", "content": "hi"}]
    with pytest.raises(ModelNotAvailable) as info:
        faig.chat_completion(state["secret"], "pytest-no-such-model", msgs)
    assert info.value.code == "model_not_found"
    assert isinstance(info.value, NotFound)


def test_streaming_passes_and_blocks(faig: FortiAIGate, state: dict[str, Any]) -> None:
    need(state, "secret")
    model = _model(faig, state["secret"])
    state["sent"] = dt.datetime.now(dt.timezone.utc)
    ok_chunks = list(
        faig.chat_completion_stream(
            state["secret"], model, [{"role": "user", "content": "Count 1 to 3."}], max_tokens=20
        )
    )
    assert len(ok_chunks) > 1, "expected several chunks"
    ok = collect_stream(ok_chunks)
    assert not blocked(ok)
    assert ok["choices"][0]["message"]["content"]
    bad = collect_stream(
        faig.chat_completion_stream(
            state["secret"], model, [{"role": "user", "content": SECRET_TEXT}], max_tokens=20
        )
    )
    assert blocked(bad), bad


def test_wait_for_traffic(faig: FortiAIGate, ws: str, state: dict[str, Any]) -> None:
    need(state, "sent")
    rows = faig.wait_for_traffic(
        state["sent"], filters={"virtual_key": f"{RUN}-key"}, count=2, timeout=90
    )
    assert {r["keyAlias"] for r in rows} == {f"{RUN}-key"}
    assert any(r["verdictLabel"] == "Block" for r in rows), rows


def test_rate_limit(
    faig: FortiAIGate, state: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    need(state, "secret", "key")
    faig.update_virtual_key(state["key"], rpm=1)
    model = _model(faig, state["secret"])
    msgs = [{"role": "user", "content": "Say ok."}]
    with contextlib.suppress(RateLimited):  # the minute's one request may already be used
        faig.chat_completion(state["secret"], model, msgs, max_tokens=5)
    with pytest.raises(RateLimited) as info:
        faig.chat_completion(state["secret"], model, msgs, max_tokens=5)
    assert info.value.code == "rate_limit_exceeded"
    # With a budget the client retries the 429s before giving up. (The test
    # suite turns sleeps off, so count the retries rather than the time.)
    caplog.set_level(logging.WARNING, logger="pyfortiaigate")
    with FortiAIGate.from_env(rate_limit_wait=3) as waiting, pytest.raises(RateLimited):
        waiting.chat_completion(state["secret"], model, msgs, max_tokens=5)
    assert len([r for r in caplog.records if "HTTP 429; waiting" in r.getMessage()]) == 2


def test_iter_audit_logs_sees_our_creates(faig: FortiAIGate, state: dict[str, Any]) -> None:
    need(state, "det")
    rows = list(faig.iter_audit_logs(range="24h", filters={"action": "Create"}, max_items=200))
    assert rows
    assert {r["action"].lower() for r in rows} == {"create"}
    assert any(RUN in r.get("message", "") for r in rows), "our creates are not in the audit log"


def test_approve_by_name(faig: FortiAIGate, ws: str) -> None:
    body = regex_detector_body(f"{RUN}-queued", [("x", r"QQQ-\d+", "block")])
    faig.create_detector(ws, body)
    faig.submit(ws, "detectors", f"{RUN}-queued")
    faig.approve("detectors", f"{RUN}-queued", ws)
    live = faig.detector_by_name(ws, f"{RUN}-queued")
    assert live
    assert live["approvalStatus"] == "active"


def test_cli_reads(ws: str, state: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
    need(state, "gr")
    assert main(["guardrails", "--ws", ws]) == 0
    assert f"{RUN}-gr" in capsys.readouterr().out
    assert main(["--json", "logs", "--key", f"{RUN}-key", "--range", "24h"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows
    assert {r["keyAlias"] for r in rows} == {f"{RUN}-key"}
    assert main(["scan", "--ws", ws, "--guardrail", f"{RUN}-gr", SECRET_TEXT]) == 0
    assert capsys.readouterr().out.startswith("Verdict: BLOCK")
