"""Write-path checks against a real FortiAIGate, inside ONE workspace. Opt-in:

    FAIG_LIVE=1 FAIG_WRITE_WORKSPACE=<workspace name> ... pytest tests/live -v

Everything is created with a ``pytest-`` name prefix in that workspace and
deleted afterwards, even when a step fails; leftovers from a crashed run are
swept first. Existing objects are never touched. The steps share state and run
in file order: a failed step skips the ones that depend on it.

Creates and deletes: a regex detector, a second detector (rejected), a
guardrail, a policy and a virtual key. The gateway calls send two short chat
completions through the workspace's first OpenAI model (or FAIG_TEST_MODEL)."""

from __future__ import annotations

import contextlib
import os
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from pyfortiaigate import (
    FaigError,
    FortiAIGate,
    approve_new,
    blocked,
    key_id_from_secret,
    key_update_body,
    regex_detector_body,
    secret_from_response,
)

WORKSPACE = os.environ.get("FAIG_WRITE_WORKSPACE", "")
PREFIX = "pytest-"
RUN = PREFIX + uuid.uuid4().hex[:8]
SECRET_TEXT = "the launch code is ZEBRA-7731"  # what the test detector blocks
PATTERN = r"ZEBRA-\d{4}"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not (os.environ.get("FAIG_LIVE") and WORKSPACE),
        reason="set FAIG_LIVE=1 and FAIG_WRITE_WORKSPACE=<name> to run",
    ),
]


def sweep(c: FortiAIGate, ws: str) -> None:
    """Delete every pytest- object in the workspace, dependents first."""
    for k in c.virtual_keys(ws):
        if str(k.get("keyName", "")).startswith(PREFIX):
            with contextlib.suppress(FaigError):
                c.delete_virtual_key(k["id"])
    for p in c.policies(ws):
        if str(p.get("name", "")).startswith(PREFIX):
            with contextlib.suppress(FaigError):
                c.delete_policy(p["id"], ws)
    for g in c.guardrails(ws):
        if str(g.get("name", "")).startswith(PREFIX):
            with contextlib.suppress(FaigError):
                c.delete_guardrail(g["id"], ws)
    for d in c.detectors(ws):
        if str(d.get("name", "")).startswith(PREFIX):
            with contextlib.suppress(FaigError):
                c.delete_detector(d.get("uuid") or d["id"])


@pytest.fixture(scope="module")
def faig() -> Iterator[FortiAIGate]:
    with FortiAIGate.from_env() as c:
        yield c


@pytest.fixture(scope="module")
def ws(faig: FortiAIGate) -> Iterator[str]:
    w = faig.workspace_by_name(WORKSPACE)
    assert w, f"no workspace named {WORKSPACE!r}"
    sweep(faig, w["id"])
    yield w["id"]
    sweep(faig, w["id"])
    assert not [
        x
        for x in faig.detectors(w["id"]) + faig.guardrails(w["id"]) + faig.policies(w["id"])
        if str(x.get("name", "")).startswith(PREFIX)
    ], "cleanup left pytest- objects behind"


@pytest.fixture(scope="module")
def state() -> dict[str, Any]:
    return {}


def need(state: dict[str, Any], *keys: str) -> None:
    missing = [k for k in keys if k not in state]
    if missing:
        pytest.skip(f"an earlier step failed: no {', '.join(missing)}")


def test_create_and_approve_regex_detector(
    faig: FortiAIGate, ws: str, state: dict[str, Any]
) -> None:
    body = regex_detector_body(f"{RUN}-det", [("launch-code", PATTERN, "block")])
    det = faig.create_detector(ws, body)
    state["det"] = det.get("uuid") or det["id"]
    assert (det.get("approvalStatus") or det.get("status")) == "draft"
    approve_new(faig, ws, "detectors", det)
    live = faig.detector_by_name(ws, f"{RUN}-det")
    assert live
    assert live["approvalStatus"] == "active"


def test_update_detector_applies_without_reapproval(
    faig: FortiAIGate, ws: str, state: dict[str, Any]
) -> None:
    need(state, "det")
    body = regex_detector_body(
        f"{RUN}-det", [("launch-code", PATTERN, "block")], description="updated by pytest"
    )
    faig.update_detector(ws, state["det"], body)
    live = faig.detector_by_name(ws, f"{RUN}-det")
    assert live
    assert live["description"] == "updated by pytest"
    assert live["approvalStatus"] == "active"


def test_detector_matches_its_pattern(faig: FortiAIGate, ws: str, state: dict[str, Any]) -> None:
    need(state, "det")
    hit = faig.test_detector(ws, state["det"], SECRET_TEXT)
    miss = faig.test_detector(ws, state["det"], "nothing secret here")
    state["detector_test_shape"] = hit
    assert hit != miss, f"same verdict for a hit and a miss: {hit}"


def test_reject_a_submitted_detector(faig: FortiAIGate, ws: str, state: dict[str, Any]) -> None:
    det = faig.create_detector(
        ws, regex_detector_body(f"{RUN}-reject", [("x", r"QQQ-\d+", "block")])
    )
    oid = det.get("uuid") or det["id"]
    faig.submit(ws, "detectors", oid)
    queued = [q for q in faig.review_queue() if str(q.get("id") or q.get("uuid")) == oid]
    assert queued, "submitted detector is not in the review queue"
    faig.reject("detectors", oid, "rejected by pytest")
    live = faig.detector_by_name(ws, f"{RUN}-reject")
    assert live
    assert live["approvalStatus"] != "active"


def test_create_and_approve_guardrail(faig: FortiAIGate, ws: str, state: dict[str, Any]) -> None:
    need(state, "det")
    g = faig.create_guardrail(ws, f"{RUN}-gr", [state["det"]])
    state["gr"] = g["id"]
    approve_new(faig, ws, "guardrails", g)
    live = faig.guardrail_by_name(ws, f"{RUN}-gr")
    assert live
    assert live["status"] == "active"
    assert live["detectorIds"] == [state["det"]]


def test_update_guardrail(faig: FortiAIGate, ws: str, state: dict[str, Any]) -> None:
    need(state, "gr", "det")
    faig.update_guardrail(ws, state["gr"], f"{RUN}-gr", [state["det"]], "updated by pytest")
    live = faig.guardrail(state["gr"])
    assert live["description"] == "updated by pytest"


def test_guardrail_scan(faig: FortiAIGate, state: dict[str, Any]) -> None:
    need(state, "gr")
    hit = faig.test_guardrail(SECRET_TEXT, guardrail_id=state["gr"])
    miss = faig.test_guardrail("nothing secret here", guardrail_id=state["gr"])
    assert hit["finalDisposition"] != miss["finalDisposition"], (hit, miss)


def test_create_and_approve_policy(faig: FortiAIGate, ws: str, state: dict[str, Any]) -> None:
    need(state, "gr")
    p = faig.create_policy(ws, f"{RUN}-pol", [state["gr"]], [state["gr"]], provider_ids=["openai"])
    state["pol"] = p["id"]
    approve_new(faig, ws, "policies", p)
    live = faig.policy_by_name(ws, f"{RUN}-pol")
    assert live
    assert live["status"] == "active"


def test_create_virtual_key(faig: FortiAIGate, ws: str, state: dict[str, Any]) -> None:
    need(state, "pol")
    key = faig.create_virtual_key(
        ws, f"{RUN}-key", policy_ids=[state["pol"]], provider_ids=["openai"]
    )
    secret = secret_from_response(key)
    assert secret, f"no one-time secret in {sorted(key)}"
    state["secret"] = secret
    state["key"] = key_id_from_secret(secret)
    rec = faig.virtual_key(state["key"])
    assert rec["keyName"] == f"{RUN}-key"
    # A read returns policyIds as {"id", "assignedByOrg"} objects.
    assert state["pol"] in key_update_body(rec)["policyIds"]


def test_check_key(faig: FortiAIGate, state: dict[str, Any]) -> None:
    need(state, "secret")
    out = faig.check_key(state["secret"])
    assert out["valid"], out
    assert out["model_count"] > 0


def _model(faig: FortiAIGate, ws: str) -> str:
    if os.environ.get("FAIG_TEST_MODEL"):
        return os.environ["FAIG_TEST_MODEL"]
    w = next(x for x in faig.workspaces() if x["id"] == ws)
    for access in w.get("providerAccess") or []:
        if access.get("providerId") == "openai":
            for m in access.get("models") or []:
                if m.get("enabled"):
                    return str(m["publicName"])
    pytest.skip("no enabled OpenAI model in the workspace; set FAIG_TEST_MODEL")


def test_chat_completion_passes_and_blocks(
    faig: FortiAIGate, ws: str, state: dict[str, Any]
) -> None:
    need(state, "secret")
    model = _model(faig, ws)
    ok = faig.chat_completion(
        state["secret"],
        model,
        [{"role": "user", "content": "Reply with the word ok."}],
        max_tokens=16,
    )
    assert not blocked(ok), ok
    assert ok["choices"][0]["message"]["content"]
    bad = faig.chat_completion(
        state["secret"], model, [{"role": "user", "content": SECRET_TEXT}], max_tokens=16
    )
    assert blocked(bad), bad


def test_update_virtual_key(faig: FortiAIGate, state: dict[str, Any]) -> None:
    need(state, "key")
    faig.update_virtual_key(state["key"], rpm=7)
    assert str(faig.virtual_key(state["key"]).get("rpm")) == "7"


def test_rotate_virtual_key(faig: FortiAIGate, state: dict[str, Any]) -> None:
    need(state, "key", "secret")
    new = secret_from_response(faig.rotate_virtual_key(state["key"]))
    assert new
    assert new != state["secret"]
    assert faig.check_key(new)["valid"]
    assert not faig.check_key(state["secret"])["valid"], "old secret still works after rotate"
    state["secret"] = new


def test_revoke_virtual_key(faig: FortiAIGate, state: dict[str, Any]) -> None:
    need(state, "key", "secret")
    faig.revoke_virtual_key(state["key"])
    assert faig.virtual_key(state["key"])["status"] != "active"
    assert not faig.check_key(state["secret"])["valid"]


def test_delete_virtual_key(faig: FortiAIGate, ws: str, state: dict[str, Any]) -> None:
    need(state, "key")
    faig.delete_virtual_key(state["key"])
    assert state["key"] not in {k["id"] for k in faig.virtual_keys(ws)}
