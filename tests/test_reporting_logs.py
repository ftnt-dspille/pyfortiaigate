"""Usage/cost reporting, traffic and ICAP logs, workspace writes, the Playground,
natural-language detectors and model checks."""

from __future__ import annotations

import datetime as dt
import json
from collections.abc import Callable
from typing import Any

import pytest

from pyfortiaigate import FaigError, FortiAIGate, ai_detector_body

from .conftest import FakeFaig, Seen

WIN = {"from": "2026-09-01", "to": "2026-09-30"}
FRM, TO = dt.date(2026, 9, 1), "2026-09-30"


def q(seen: Seen) -> dict[str, list[str]]:
    from urllib.parse import parse_qs

    return parse_qs(seen.query)


def one(fake: FakeFaig) -> Seen:
    calls = fake.app_calls()
    assert len(calls) == 1, [c.key for c in calls]
    return calls[0]


# -- reporting ------------------------------------------------------------------------
REPORTS: list[tuple[Callable[[FortiAIGate], Any], str, dict[str, str]]] = [
    (lambda c: c.usage_summary(FRM, TO), "/api/v1/admin/usage/summary", WIN),
    (lambda c: c.usage_summary(FRM, TO, "w1"), "/api/v1/workspaces/w1/usage/summary", WIN),
    (
        lambda c: c.usage_trend(FRM, TO, "weekly"),
        "/api/v1/admin/usage/trend",
        {**WIN, "interval": "weekly"},
    ),
    (
        lambda c: c.usage_rankings(FRM, TO, by="model", limit=3, end="bottom", order_by="requests"),
        "/api/v1/admin/usage/rankings",
        {**WIN, "by": "model", "limit": "3", "end": "bottom", "orderBy": "requests"},
    ),
    (
        lambda c: c.usage_breakdown("key", "k1", FRM, TO, workspace_id="w1"),
        "/api/v1/workspaces/w1/usage/breakdown",
        {**WIN, "by": "key", "id": "k1"},
    ),
    (lambda c: c.cost_summary(FRM, TO), "/api/v1/admin/cost/summary", WIN),
    (
        lambda c: c.cost_trend(FRM, TO, "monthly", workspace_id="w1"),
        "/api/v1/workspaces/w1/cost/trend",
        {**WIN, "interval": "monthly"},
    ),
    (
        lambda c: c.cost_rankings(FRM, TO, by="user", order_by="per1kTokens", interval="daily"),
        "/api/v1/admin/cost/rankings",
        {**WIN, "by": "user", "limit": "5", "orderBy": "per1kTokens", "interval": "daily"},
    ),
    (
        lambda c: c.cost_breakdown("workspace", "w9", FRM, TO),
        "/api/v1/admin/cost/breakdown",
        {**WIN, "by": "workspace", "id": "w9"},
    ),
    (lambda c: c.analytics(FRM, TO, limit=4), "/api/v1/admin/analytics", {**WIN, "limit": "4"}),
    (
        lambda c: c.workspace_analytics("w1", FRM, TO),
        "/api/v1/workspaces/w1/analytics",
        {**WIN, "limit": "10"},
    ),
]


@pytest.mark.parametrize(("call", "path", "query"), REPORTS, ids=[r[1] for r in REPORTS])
def test_report_query(
    faig: FortiAIGate, fake: FakeFaig, call: Any, path: str, query: dict[str, str]
) -> None:
    call(faig)
    s = one(fake)
    assert s.key == ("GET", path)
    assert {k: v[0] for k, v in q(s).items()} == query


def test_default_window_is_the_last_30_days(faig: FortiAIGate, fake: FakeFaig) -> None:
    faig.cost_summary()
    got = {k: v[0] for k, v in q(one(fake)).items()}
    today = dt.date.today()
    assert got == {"to": today.isoformat(), "from": (today - dt.timedelta(days=29)).isoformat()}


def test_window_from_only_an_end_date(faig: FortiAIGate, fake: FakeFaig) -> None:
    faig.usage_summary(to="2026-03-30")
    assert q(one(fake))["from"] == ["2026-03-01"]


@pytest.mark.parametrize(
    ("call", "msg"),
    [
        (lambda c: c.usage_trend(interval="minutely"), "interval"),
        (lambda c: c.usage_rankings(by="provider"), "by"),
        (lambda c: c.usage_rankings(end="middle"), "end"),
        (lambda c: c.usage_rankings(order_by="chargebackSpend"), "order_by"),
        (lambda c: c.cost_rankings(order_by="tokens"), "order_by"),
        (lambda c: c.cost_rankings(interval="yearly"), "interval"),
        (lambda c: c.cost_breakdown("team", "x"), "by"),
    ],
)
def test_report_values_are_checked_before_sending(
    faig: FortiAIGate, fake: FakeFaig, call: Any, msg: str
) -> None:
    with pytest.raises(ValueError, match=msg):
        call(faig)
    assert fake.app_calls() == []


# -- traffic logs ---------------------------------------------------------------------
def page(uuids: list[str], cursor: str | None, has_next: bool, total: int | None = None) -> Any:
    body: dict[str, Any] = {"items": [{"uuid": u} for u in uuids], "hasNext": has_next}
    if cursor:
        body["nextCursor"] = cursor
    if total is not None:
        body["total"] = total
    return (200, body)


def test_traffic_logs_follow_the_cursor(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer(
        "GET",
        "/api/v1/admin/traffic-logs",
        page(["a", "b"], "c1", True, total=3),
        page(["c"], None, False),
    )
    assert [r["uuid"] for r in faig.traffic_logs(page_size=2)] == ["a", "b", "c"]
    first, second = fake.app_calls()
    assert q(first) == {
        "range": ["24h"],
        "limit": ["2"],
        "direction": ["next"],
        "includeTotal": ["true"],
    }
    assert q(second)["cursor"] == ["c1"]
    assert "includeTotal" not in q(second)


def test_traffic_logs_stop_at_max_items(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/traffic-logs", page(["a", "b"], "c1", True))
    assert len(list(faig.traffic_logs(max_items=1))) == 1
    assert len(fake.app_calls()) == 1


def test_traffic_logs_stop_without_a_cursor(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/traffic-logs", page(["a"], None, True))
    assert len(list(faig.traffic_logs())) == 1


def test_traffic_log_filters_and_custom_window(faig: FortiAIGate, fake: FakeFaig) -> None:
    start = dt.datetime(2026, 10, 1, 0, 0)
    faig.traffic_logs_page(
        start=start,
        end=1791851042418,
        filters={
            "model": "gpt",
            "verdict": ["Block", "Log"],
            "virtual_key": {"operator": "contains", "value": "student"},
            "user": None,
        },
        workspace_id="w1",
    )
    s = one(fake)
    assert s.path == "/api/v1/workspaces/w1/traffic-logs"
    got = q(s)
    assert got["range"] == ["custom"]
    assert got["startTime"] == [str(int(start.replace(tzinfo=dt.timezone.utc).timestamp() * 1000))]
    assert got["endTime"] == ["1791851042418"]
    assert json.loads(got["modelFilters"][0]) == {"operator": "is", "value": ["gpt"]}
    assert json.loads(got["verdictFilters"][0]) == {"operator": "is", "value": ["Block", "Log"]}
    assert json.loads(got["virtualKeyFilters"][0]) == {
        "operator": "contains",
        "value": ["student"],
    }
    assert "userFilters" not in got  # an empty filter is dropped, not sent


@pytest.mark.parametrize(
    ("kwargs", "msg"),
    [
        ({"filters": {"modle": "gpt"}}, "unknown filter"),
        ({"filters": {"model": {"operator": "equals", "value": "gpt"}}}, "operator"),
        ({"range": "30d"}, "range"),
        ({"start": 1}, "both start and end"),
    ],
)
def test_bad_log_queries_raise_instead_of_returning_everything(
    faig: FortiAIGate, fake: FakeFaig, kwargs: dict[str, Any], msg: str
) -> None:
    with pytest.raises(ValueError, match=msg):
        faig.traffic_logs_page(**kwargs)
    assert fake.app_calls() == []


def test_traffic_log_detail_and_filter_options(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/workspaces/w1/traffic-logs/u1", (200, {"uuid": "u1", "cost": "1"}))
    assert faig.traffic_log("u1", "w1") == {"uuid": "u1", "cost": "1"}
    fake.answer("GET", "/api/v1/admin/traffic-logs/u2", (200, []))
    assert faig.traffic_log("u2") == {}
    faig.traffic_log_filter_options(range="7d")
    assert q(fake.calls("GET", "/api/v1/admin/traffic-logs/filter-options")[0]) == {"range": ["7d"]}


def test_icap_logs_page_by_offset(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer(
        "GET",
        "/api/v1/admin/icap-logs",
        (200, {"items": [{"uuid": "a"}, {"uuid": "b"}], "hasNext": True}),
        (200, {"items": [{"uuid": "c"}], "hasNext": False}),
    )
    rows = list(faig.icap_logs(page_size=2, filters={"direction": "outbound"}))
    assert [r["uuid"] for r in rows] == ["a", "b", "c"]
    first, second = fake.app_calls()
    assert q(first)["offset"] == ["0"]
    assert q(second)["offset"] == ["2"]
    assert json.loads(q(first)["directionFilters"][0])["value"] == ["outbound"]


def test_icap_logs_stop_on_an_empty_page_and_max_items(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/icap-logs", (200, {"items": []}))
    assert list(faig.icap_logs()) == []
    fake.answer("GET", "/api/v1/workspaces/w1/icap-logs", (200, {"items": [{"uuid": "a"}] * 3}))
    assert len(list(faig.icap_logs(max_items=2, workspace_id="w1"))) == 2


def test_icap_log_filters_use_the_icap_fields(faig: FortiAIGate) -> None:
    with pytest.raises(ValueError, match="unknown filter"):
        faig.icap_logs_page(filters={"model": "gpt"})


def test_icap_detail_and_filter_options(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/icap-logs/u1", (200, {"uuid": "u1"}))
    assert faig.icap_log("u1") == {"uuid": "u1"}
    fake.answer("GET", "/api/v1/admin/icap-logs/u2", (200, None))
    assert faig.icap_log("u2") == {}
    faig.icap_log_filter_options(workspace_id="w1", range="all")
    assert fake.calls("GET", "/api/v1/workspaces/w1/icap-logs/filter-options")


# -- workspace writes, playground, NL detectors ----------------------------------------
WRITES: list[tuple[Callable[[FortiAIGate], Any], str, str, Any]] = [
    (lambda c: c.delete_detector("d1", "w1"), "DELETE", "/api/v1/workspaces/w1/detectors/d1", None),
    (
        lambda c: c.withdraw("w1", "policies", "p1"),
        "DELETE",
        "/api/v1/workspaces/w1/policies/p1/pending",
        None,
    ),
    (
        lambda c: c.update_policy("w1", "p1", "p", ["g"], [], provider_ids=["openai"]),
        "PUT",
        "/api/v1/workspaces/w1/policies/p1",
        {
            "name": "p",
            "description": "p",
            "inputGuardrailIds": ["g"],
            "outputGuardrailIds": [],
            "responseScanMode": "post_stream",
            "providerAccess": [{"providerId": "openai", "allModels": True}],
        },
    ),
    (
        lambda c: c.rotate_virtual_key("k1", ws_id="w1"),
        "POST",
        "/api/v1/workspaces/w1/virtual-keys/k1/rotate",
        {},
    ),
    (
        lambda c: c.revoke_virtual_key("k1", "done", ws_id="w1"),
        "POST",
        "/api/v1/workspaces/w1/virtual-keys/k1/revoke",
        {"reason": "done"},
    ),
    (
        lambda c: c.delete_virtual_key("k1", ws_id="w1"),
        "DELETE",
        "/api/v1/workspaces/w1/virtual-keys/k1",
        None,
    ),
    (lambda c: c.workspace("w1"), "GET", "/api/v1/workspaces/w1", None),
    (lambda c: c.models(), "GET", "/api/v1/admin/models", None),
    (lambda c: c.model_groups("w1"), "GET", "/api/v1/workspaces/w1/model-groups", None),
    (lambda c: c.grantable_providers(), "GET", "/api/v1/admin/grantable-providers", None),
    (
        lambda c: c.attachable_policies("w1"),
        "GET",
        "/api/v1/workspaces/w1/attachable-policies",
        None,
    ),
]


@pytest.mark.parametrize(("call", "method", "path", "body"), WRITES, ids=[w[2] for w in WRITES])
def test_workspace_calls(
    faig: FortiAIGate, fake: FakeFaig, call: Any, method: str, path: str, body: Any
) -> None:
    call(faig)
    s = one(fake)
    assert s.key == (method, path)
    assert s.body == body


def test_workspace_scoped_key_update_reads_and_writes_the_workspace_path(
    faig: FortiAIGate, fake: FakeFaig
) -> None:
    fake.answer(
        "GET",
        "/api/v1/workspaces/w1/virtual-keys/k1",
        (200, {"id": "k1", "keyName": "k", "status": "active"}),
    )
    faig.update_virtual_key("k1", rpm=3, ws_id="w1")
    assert [c.key for c in fake.app_calls()] == [
        ("GET", "/api/v1/workspaces/w1/virtual-keys/k1"),
        ("PUT", "/api/v1/workspaces/w1/virtual-keys/k1"),
    ]
    assert fake.app_calls()[1].body == {"keyName": "k", "rpm": 3}


def test_workspace_models_and_grantable_providers(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/workspaces/w1", (200, {"allowedModels": ["m1", "m2"]}))
    fake.answer(
        "GET",
        "/api/v1/workspaces/w1/grantable-providers",
        (200, {"providers": [{"providerId": "openai"}], "updatedAt": "t"}),
    )
    assert faig.workspace_models("w1") == ["m1", "m2"]
    assert faig.grantable_providers("w1") == [{"providerId": "openai"}]
    fake.answer("GET", "/api/v1/workspaces/w2", (200, []))
    fake.answer("GET", "/api/v1/workspaces/w2/grantable-providers", (200, []))
    assert faig.workspace_models("w2") == []
    assert faig.grantable_providers("w2") == []


@pytest.mark.parametrize(
    ("ws", "path"),
    [("w1", "/api/v1/workspaces/w1/detectors/test"), (None, "/api/v1/admin/detectors/test")],
)
def test_playground_sends_the_body_without_name(
    faig: FortiAIGate, fake: FakeFaig, ws: str | None, path: str
) -> None:
    body = ai_detector_body("dark-side", [("sith", "talk of joining the dark side")])
    faig.playground("join me", body, ws)
    s = one(fake)
    assert s.key == ("POST", path)
    assert s.body["input"] == "join me"
    assert "name" not in s.body["detector"]
    assert "description" not in s.body["detector"]
    assert s.body["detector"]["detectorType"] == "ai"


def test_ai_detector_body_fills_ai_rules_and_flat_rules() -> None:
    body = ai_detector_body(
        "dark-side",
        [
            ("sith", ["recruiting to the dark side", "praising the Emperor"], "film trivia"),
            ("force-choke", "threats of force-choking"),
        ],
        action="log",
    )
    assert body["detectorType"] == "ai"
    assert body["action"] == "log"
    assert body["inputGuards"] == body["outputGuards"] == ["AI descriptions"]
    sith, choke = body["aiRules"]
    assert sith["violateIf"] == ["recruiting to the dark side", "praising the Emperor"]
    assert sith["exemptIf"] == ["film trivia"]
    assert choke["exemptIf"] == []
    assert [r["description"] for r in body["rules"]] == [
        "recruiting to the dark side",
        "praising the Emperor",
        "threats of force-choking",
    ]
    assert len({r["id"] for r in body["rules"]}) == 3


@pytest.mark.parametrize(
    ("rules", "msg"),
    [([], "no rules"), ([("empty", [])], "violate_if")],
)
def test_ai_detector_body_refuses_rules_that_match_nothing(rules: Any, msg: str) -> None:
    with pytest.raises(ValueError, match=msg):
        ai_detector_body("x", rules)


# -- models a key can use -----------------------------------------------------------
def test_available_models(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer(
        "GET", "/ai/openai/v1/models", (200, {"data": [{"id": "gpt-a"}, {"id": "gpt-b"}, {}]})
    )
    assert faig.available_models("faig_x") == ["gpt-a", "gpt-b"]
    assert faig.can_use_model("faig_x", "gpt-b")
    assert not faig.can_use_model("faig_x", "claude")
    assert fake.calls("GET", "/ai/openai/v1/models")[0].headers["authorization"] == "Bearer faig_x"


def test_available_models_with_a_bad_key_raises(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/ai/openai/v1/models", (401, {"error": "invalid key"}))
    with pytest.raises(FaigError, match="invalid key"):
        faig.available_models("faig_bad")


def test_workspace_guardrail_test_by_guardrail_id(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer(
        "GET",
        "/api/v1/workspaces/w1/guardrails/g1",
        (200, {"id": "g1", "detectorIds": ["d1"], "denySuspiciousCharacters": True}),
    )
    faig.test_guardrail("hi", guardrail_id="g1", ws_id="w1")
    assert [c.key for c in fake.app_calls()] == [
        ("GET", "/api/v1/workspaces/w1/guardrails/g1"),
        ("POST", "/api/v1/workspaces/w1/guardrails/test"),
    ]
    assert fake.app_calls()[1].body == {
        "input": "hi",
        "detectorIds": ["d1"],
        "denySuspiciousCharacters": True,
    }
