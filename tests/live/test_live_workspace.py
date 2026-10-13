"""Workspace-path writes, the Playground, Natural Language detectors, what a key
can call, and finding a key's own traffic in the logs. Confined to
FAIG_WRITE_WORKSPACE, pytest- names, everything deleted afterwards (shared
sweep with test_live_write). Sends two short chat completions."""

from __future__ import annotations

import contextlib
import os
import time
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from pyfortiaigate import (
    FaigError,
    FortiAIGate,
    ai_detector_body,
    approve_new,
    key_id_from_secret,
    regex_detector_body,
    secret_from_response,
)

from .test_live_write import PREFIX, sweep

WORKSPACE = os.environ.get("FAIG_WRITE_WORKSPACE", "")
RUN = PREFIX + "ws-" + uuid.uuid4().hex[:8]

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not (os.environ.get("FAIG_LIVE") and WORKSPACE),
        reason="set FAIG_LIVE=1 and FAIG_WRITE_WORKSPACE=<name> to run",
    ),
]

DARK_SIDE = [
    (
        "sith-recruiting",
        ["Urging someone to join the dark side of the Force or to turn to the Sith"],
        ["Neutral discussion of the Star Wars films' plots"],
    )
]


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
    left = [
        x
        for x in faig.detectors(w["id"]) + faig.guardrails(w["id"]) + faig.policies(w["id"])
        if str(x.get("name", "")).startswith(PREFIX)
    ] + [k for k in faig.virtual_keys(w["id"]) if str(k.get("keyName", "")).startswith(PREFIX)]
    assert not left, "cleanup left pytest- objects behind"


@pytest.fixture(scope="module")
def state() -> dict[str, Any]:
    return {}


def need(state: dict[str, Any], *keys: str) -> None:
    missing = [k for k in keys if k not in state]
    if missing:
        pytest.skip(f"an earlier step failed: no {', '.join(missing)}")


def test_playground_scans_an_unsaved_regex_body(faig: FortiAIGate, ws: str) -> None:
    body = regex_detector_body(f"{RUN}-pg", [("code", r"ZEBRA-\d{4}", "block")])
    hit = faig.playground("the code is ZEBRA-1234", body, ws)
    miss = faig.playground("nothing here", body, ws)
    assert hit != miss, (hit, miss)
    assert faig.detector_by_name(ws, f"{RUN}-pg") is None, "the Playground saved a detector"


def test_playground_as_org_admin(faig: FortiAIGate) -> None:
    body = regex_detector_body(f"{RUN}-pg-admin", [("code", r"ZEBRA-\d{4}", "block")])
    hit = faig.playground("the code is ZEBRA-1234", body)
    miss = faig.playground("nothing here", body)
    assert hit != miss, (hit, miss)


def test_playground_natural_language_detector(faig: FortiAIGate, ws: str) -> None:
    body = ai_detector_body(f"{RUN}-nl", DARK_SIDE)
    hit = faig.playground("Join the dark side, my apprentice, and rule with the Sith.", body, ws)
    miss = faig.playground("What is the boiling point of water at sea level?", body, ws)
    assert hit != miss, (hit, miss)


def test_create_submit_withdraw_delete_nl_detector(
    faig: FortiAIGate, ws: str, state: dict[str, Any]
) -> None:
    det = faig.create_detector(ws, ai_detector_body(f"{RUN}-nl", DARK_SIDE))
    oid = det.get("uuid") or det["id"]
    state["nl"] = oid
    live = faig.detector_by_name(ws, f"{RUN}-nl")
    assert live
    assert live["detectorType"] == "ai"
    assert live["aiRules"][0]["violateIf"] == DARK_SIDE[0][1]
    faig.submit(ws, "detectors", oid)
    assert faig.detector_by_name(ws, f"{RUN}-nl")["approvalStatus"] == "pending"  # type: ignore[index]
    faig.withdraw(ws, "detectors", oid)
    after = faig.detector_by_name(ws, f"{RUN}-nl")
    assert after
    assert after["approvalStatus"] != "pending"
    faig.delete_detector(oid, ws)
    assert faig.detector_by_name(ws, f"{RUN}-nl") is None


def test_guardrail_and_policy_then_update_policy(
    faig: FortiAIGate, ws: str, state: dict[str, Any]
) -> None:
    det = faig.create_detector(
        ws, regex_detector_body(f"{RUN}-det", [("code", r"ZEBRA-\d{4}", "block")])
    )
    approve_new(faig, ws, "detectors", det)
    g = faig.create_guardrail(ws, f"{RUN}-gr", [det.get("uuid") or det["id"]])
    approve_new(faig, ws, "guardrails", g)
    p = faig.create_policy(ws, f"{RUN}-pol", [g["id"]], [g["id"]], provider_ids=["openai"])
    approve_new(faig, ws, "policies", p)
    state["pol"], state["gr"] = p["id"], g["id"]
    state["det"] = det.get("uuid") or det["id"]
    faig.update_policy(
        ws, p["id"], f"{RUN}-pol", [g["id"]], [], provider_ids=["openai"], description="edited"
    )
    live = faig.policy_by_name(ws, f"{RUN}-pol")
    assert live
    # As org admin, an edit to an ACTIVE policy applies at once: no review.
    assert live["status"] == "active"
    assert live["description"] == "edited"
    assert live["outputGuardrailIds"] == []
    assert not live.get("hasPendingChange")
    faig.update_policy(ws, p["id"], f"{RUN}-pol", [g["id"]], [g["id"]], provider_ids=["openai"])


@pytest.mark.parametrize("kind", ["guardrails", "policies"])
def test_withdraw_a_pending_submission(
    faig: FortiAIGate, ws: str, state: dict[str, Any], kind: str
) -> None:
    need(state, "det", "gr")
    if kind == "guardrails":
        obj = faig.create_guardrail(ws, f"{RUN}-wd-gr", [state["det"]])
        find = lambda: faig.guardrail_by_name(ws, f"{RUN}-wd-gr")  # noqa: E731
    else:
        obj = faig.create_policy(
            ws, f"{RUN}-wd-pol", [state["gr"]], [state["gr"]], provider_ids=["openai"]
        )
        find = lambda: faig.policy_by_name(ws, f"{RUN}-wd-pol")  # noqa: E731
    faig.submit(ws, kind, obj["id"])
    assert find()["status"] == "pending"  # type: ignore[index]
    queued = {str(q.get("id")) for q in faig.review_queue()}
    assert obj["id"] in queued
    faig.withdraw(ws, kind, obj["id"])
    after = find()
    assert after
    assert after["status"] == "draft"
    assert obj["id"] not in {str(q.get("id")) for q in faig.review_queue()}
    if kind == "guardrails":
        faig.delete_guardrail(obj["id"], ws)
    else:
        faig.delete_policy(obj["id"], ws)
    assert find() is None


def _model(faig: FortiAIGate, ws: str) -> str:
    if os.environ.get("FAIG_TEST_MODEL"):
        return os.environ["FAIG_TEST_MODEL"]
    w = next(x for x in faig.workspaces() if x["id"] == ws)
    for access in w.get("providerAccess") or []:
        if access.get("providerId") == "openai":
            for m in access.get("models") or []:
                if m.get("enabled"):
                    return str(m["publicName"])
    pytest.skip("no enabled OpenAI model; set FAIG_TEST_MODEL")


def test_workspace_key_lifecycle_and_models(
    faig: FortiAIGate, ws: str, state: dict[str, Any]
) -> None:
    need(state, "pol")
    key = faig.create_virtual_key(
        ws, f"{RUN}-key", policy_ids=[state["pol"]], provider_ids=["openai"]
    )
    secret = secret_from_response(key)
    assert secret
    kid = key_id_from_secret(secret)
    state["key"], state["secret"] = kid, secret
    assert faig.virtual_key(kid, ws)["keyName"] == f"{RUN}-key"
    faig.update_virtual_key(kid, rpm=9, ws_id=ws)
    assert str(faig.virtual_key(kid, ws).get("rpm")) == "9"

    models = faig.available_models(secret)
    model = _model(faig, ws)
    assert model in models, f"{model} not callable with this key: {models}"
    assert faig.can_use_model(secret, model)
    assert not faig.can_use_model(secret, "no-such-model-pytest")
    with pytest.raises(FaigError) as e:
        faig.chat_completion(secret, "no-such-model-pytest", [{"role": "user", "content": "hi"}])
    assert e.value.status == 404, "an unavailable model should 404"

    out = faig.chat_completion(
        secret, model, [{"role": "user", "content": "Reply with the word ok."}], max_tokens=8
    )
    assert out["choices"]
    state["model"] = model


def test_the_keys_own_traffic_shows_up_with_cost(
    faig: FortiAIGate, ws: str, state: dict[str, Any]
) -> None:
    need(state, "key", "model")
    rows: list[dict[str, Any]] = []
    for _ in range(12):  # logs land asynchronously
        rows = list(
            faig.traffic_logs(
                range="24h", filters={"virtual_key": f"{RUN}-key"}, workspace_id=ws, max_items=5
            )
        )
        if rows:
            break
        time.sleep(5)
    assert rows, "the key's chat never appeared in the traffic logs"
    assert all(r["keyAlias"] == f"{RUN}-key" for r in rows)
    detail = faig.traffic_log(rows[0]["uuid"], ws)
    assert detail["model"] == state["model"]
    assert detail.get("cost") is not None


def test_workspace_key_rotate_revoke_delete(
    faig: FortiAIGate, ws: str, state: dict[str, Any]
) -> None:
    need(state, "key", "secret")
    new = secret_from_response(faig.rotate_virtual_key(state["key"], ws_id=ws))
    assert new
    assert new != state["secret"]
    faig.revoke_virtual_key(state["key"], "pytest done", ws_id=ws)
    assert faig.virtual_key(state["key"], ws)["status"] != "active"
    faig.delete_virtual_key(state["key"], ws_id=ws)
    with contextlib.suppress(FaigError):
        assert state["key"] not in {k["id"] for k in faig.virtual_keys(ws)}
