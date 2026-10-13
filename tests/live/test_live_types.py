"""Every typed response, checked against a real FortiAIGate: each key the
appliance returns must be declared in the method's return type, so the
documented fields (docs/reference/types.md) are complete. A failure names the
undeclared field paths: add them to the TypedDict in client.py and rerun
``python scripts/gen_docs.py``.

Read-only, except the write-path section, which (like test_live_write) works
only inside FAIG_WRITE_WORKSPACE under a ``pytest-`` name and cleans up."""

from __future__ import annotations

import os
import typing
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest

import pyfortiaigate as P
from pyfortiaigate import FortiAIGate, collect_stream, regex_detector_body

from ..shapes import assert_declared
from .test_live_write import PREFIX, sweep

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not os.environ.get("FAIG_LIVE"), reason="set FAIG_LIVE=1 to run"),
]

WORKSPACE = os.environ.get("FAIG_WRITE_WORKSPACE", "")


@pytest.fixture(scope="module")
def faig() -> Iterator[FortiAIGate]:
    with FortiAIGate.from_env() as c:
        yield c


def returns(method: str) -> Any:
    """The declared return type of a client method."""
    return typing.get_type_hints(getattr(FortiAIGate, method), vars(P.client))["return"]


def first(xs: list[Any]) -> Any:
    if not xs:
        pytest.skip("nothing on the appliance to read")
    return xs[0]


READS: list[tuple[str, Callable[[FortiAIGate], Any]]] = [
    ("me", lambda c: c.me()),
    ("users", lambda c: c.users()),
    ("user", lambda c: c.user(first(c.users())["id"])),
    ("workspaces", lambda c: c.workspaces()),
    ("my_workspaces", lambda c: c.my_workspaces()),
    ("workspace", lambda c: c.workspace(first(c.workspaces())["id"])),
    ("workspace_members", lambda c: c.workspace_members(first(c.workspaces())["id"])),
    ("workspace_budget", lambda c: c.workspace_budget(first(c.workspaces())["id"])),
    ("detectors", lambda c: c.detectors()),
    ("builtin_detectors", lambda c: c.builtin_detectors()),
    ("guardrails", lambda c: c.guardrails()),
    ("guardrail", lambda c: c.guardrail(first(c.guardrails())["id"])),
    ("policies", lambda c: c.policies()),
    ("policy", lambda c: c.policy(first(c.policies())["id"])),
    ("virtual_keys", lambda c: c.virtual_keys()),
    ("virtual_key", lambda c: c.virtual_key(first(c.virtual_keys())["id"])),
    ("review_queue", lambda c: c.review_queue()),
    ("ai_providers", lambda c: c.ai_providers()),
    ("models", lambda c: c.models()),
    ("model_groups", lambda c: c.model_groups()),
    ("grantable_providers", lambda c: c.grantable_providers()),
    ("dlp_labels", lambda c: c.dlp_labels()),
    ("licenses", lambda c: c.licenses()),
    ("usage_summary", lambda c: c.usage_summary()),
    ("usage_trend", lambda c: c.usage_trend(interval="weekly")),
    ("usage_rankings", lambda c: c.usage_rankings(by="key", end="both")),
    ("cost_summary", lambda c: c.cost_summary()),
    ("cost_trend", lambda c: c.cost_trend()),
    ("cost_rankings", lambda c: c.cost_rankings(by="user", limit=10)),
    ("analytics", lambda c: c.analytics(limit=5)),
    ("traffic_logs_page", lambda c: c.traffic_logs_page(range="7d")),
    (
        "traffic_log",
        lambda c: c.traffic_log(first(list(c.traffic_logs(range="7d", max_items=1)))["uuid"]),
    ),
    ("traffic_log_filter_options", lambda c: c.traffic_log_filter_options(range="7d")),
    ("audit_logs_page", lambda c: c.audit_logs_page(range="7d")),
    ("audit_log_filter_options", lambda c: c.audit_log_filter_options(range="7d")),
]


@pytest.mark.parametrize(("method", "call"), READS, ids=[r[0] for r in READS])
def test_read_matches_its_type(
    faig: FortiAIGate, method: str, call: Callable[[FortiAIGate], Any]
) -> None:
    assert_declared(call(faig), returns(method))


@pytest.mark.parametrize("by", ["key", "user", "workspace", "model"])
def test_rankings_and_breakdowns_match(faig: FortiAIGate, by: str) -> None:
    for kind in ("usage", "cost"):
        ranking = getattr(faig, f"{kind}_rankings")(by=by, limit=10)
        assert_declared(ranking, returns(f"{kind}_rankings"))
        live = [r for r in P.rank_items(ranking) if not r.get("deleted")]
        if live:
            assert_declared(
                getattr(faig, f"{kind}_breakdown")(by, live[0]["id"]), returns(f"{kind}_breakdown")
            )


def test_workspace_paths_match(faig: FortiAIGate) -> None:
    for w in faig.workspaces():
        ws = w["id"]
        assert_declared(faig.model_groups(ws), returns("model_groups"))
        assert_declared(faig.grantable_providers(ws), returns("grantable_providers"))
        assert_declared(faig.attachable_policies(ws), returns("attachable_policies"))
        assert_declared(faig.analytics(limit=3, ws_id=ws), returns("analytics"))


# -- write paths (FAIG_WRITE_WORKSPACE only) ---------------------------------------------
@pytest.mark.skipif(not WORKSPACE, reason="set FAIG_WRITE_WORKSPACE=<name> for the write paths")
def test_write_responses_match(faig: FortiAIGate) -> None:
    run = PREFIX + uuid.uuid4().hex[:8] + "-t"
    ws = faig.resolve_workspace(WORKSPACE)
    sweep(faig, ws)
    try:
        body = regex_detector_body(f"{run}-det", [("code", r"ZEBRA-\d{4}", "block")])
        det = faig.create_detector(ws, body)
        assert_declared(det, returns("create_detector"))
        assert_declared(faig.submit(ws, "detectors", det["uuid"]), returns("submit"))
        assert_declared(faig.approve("detectors", det["uuid"]), returns("approve"))
        assert_declared(faig.update_detector(ws, det["uuid"], body), returns("update_detector"))
        assert_declared(faig.test_detector(ws, det["uuid"], "ZEBRA-1234"), returns("test_detector"))
        assert_declared(faig.playground("ZEBRA-1234", body, ws), returns("playground"))
        gr = faig.ensure_guardrail(ws, f"{run}-gr", [det["uuid"]])
        assert_declared(gr.record, P.Guardrail)
        assert_declared(
            faig.test_guardrail("ZEBRA-1234", guardrail_id=gr.id, ws_id=ws),
            returns("test_guardrail"),
        )
        pol = faig.ensure_policy(ws, f"{run}-pol", [gr.id], [gr.id], provider_ids=["openai"])
        assert_declared(pol.record, P.Policy)
        key = faig.create_virtual_key(
            ws, f"{run}-key", policy_ids=[pol.id], provider_ids=["openai"]
        )
        assert_declared(key, returns("create_virtual_key"))
        assert_declared(faig.update_virtual_key(key["id"], rpm=50), returns("update_virtual_key"))
        rotated = faig.rotate_virtual_key(key["id"])
        assert_declared(rotated, returns("rotate_virtual_key"))
        secret = rotated["secretKey"]
        assert_declared(faig.check_key(secret), returns("check_key"))
        model = next((m for m in faig.available_models(secret) if "gpt" in m), None)
        if model:
            msgs = [{"role": "user", "content": "Say ok."}]
            assert_declared(
                faig.chat_completion(secret, model, msgs, max_tokens=5), returns("chat_completion")
            )
            chunks = list(faig.chat_completion_stream(secret, model, msgs, max_tokens=5))
            for chunk in chunks:
                assert_declared(chunk, P.ChatCompletionChunk)
            assert_declared(collect_stream(chunks), P.ChatCompletion)
        assert_declared(faig.revoke_virtual_key(key["id"]), returns("revoke_virtual_key"))
    finally:
        sweep(faig, ws)
